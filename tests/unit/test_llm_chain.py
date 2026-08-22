"""Tests for the provider chain.

The chain exists so that a rate-limited or unreachable free-tier service costs
a less fluent sentence rather than a failed report. These tests hold that
property.
"""

from __future__ import annotations

import pytest

from cyber_risk.config.settings import LLMProviderName, Settings
from cyber_risk.core.exceptions import LLMProviderUnavailableError, LLMResponseError
from cyber_risk.services.llm import (
    GeminiProvider,
    OpenAICompatibleProvider,
    ProviderChain,
    build_providers,
)


class StubProvider:
    """A provider that either answers or fails, on demand."""

    def __init__(self, label: str, answer: str | None = None) -> None:
        self._label = label
        self._answer = answer
        self.calls = 0

    @property
    def name(self) -> str:
        return self._label

    async def generate(self, system: str, prompt: str) -> str:
        self.calls += 1
        if self._answer is None:
            raise LLMProviderUnavailableError("unavailable", detail=f"{self._label} down")
        return self._answer


def build(**overrides: object) -> Settings:
    """Construct settings without reading a developer env file."""
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


@pytest.mark.unit
class TestProviderSelection:
    def test_only_providers_with_keys_are_built(self) -> None:
        providers = build_providers(build(groq_api_key="key"))
        assert len(providers) == 1
        assert providers[0].name.startswith("groq:")

    def test_no_keys_yields_no_providers(self) -> None:
        assert build_providers(build()) == ()

    def test_preference_order_is_preserved(self) -> None:
        providers = build_providers(
            build(gemini_api_key="a", groq_api_key="b", openrouter_api_key="c")
        )
        assert [p.name.split(":")[0] for p in providers] == [
            "gemini",
            "groq",
            "openrouter",
        ]

    def test_configured_model_is_used(self) -> None:
        providers = build_providers(build(gemini_api_key="a", gemini_model="some-model"))
        assert providers[0].name == "gemini:some-model"

    def test_reordered_preference_is_respected(self) -> None:
        providers = build_providers(
            build(
                llm_provider_order="openrouter,gemini",
                gemini_api_key="a",
                openrouter_api_key="c",
            )
        )
        assert [p.name.split(":")[0] for p in providers] == ["openrouter", "gemini"]


@pytest.mark.unit
class TestFallbackBehaviour:
    async def test_first_healthy_provider_is_used(self) -> None:
        first = StubProvider("first", "generated text")
        second = StubProvider("second", "unused")

        result = await ProviderChain((first, second)).generate("system", "prompt")

        assert result == "generated text"
        assert second.calls == 0

    async def test_failure_falls_through_to_the_next(self) -> None:
        broken = StubProvider("broken")
        working = StubProvider("working", "generated text")

        result = await ProviderChain((broken, working)).generate("system", "prompt")

        assert result == "generated text"
        assert broken.calls == 1

    async def test_exhausted_chain_returns_nothing_rather_than_raising(self) -> None:
        """A dead provider must cost prose, never the report."""
        chain = ProviderChain((StubProvider("a"), StubProvider("b")))
        assert await chain.generate("system", "prompt") is None

    async def test_empty_chain_returns_nothing(self) -> None:
        assert await ProviderChain(()).generate("system", "prompt") is None

    async def test_the_serving_provider_is_recorded(self) -> None:
        """The report states how its prose was produced."""
        chain = ProviderChain((StubProvider("broken"), StubProvider("working", "text")))
        await chain.generate("system", "prompt")
        assert chain.last_used == "working"

    async def test_exhaustion_clears_the_recorded_provider(self) -> None:
        chain = ProviderChain((StubProvider("working", "text"),))
        await chain.generate("system", "prompt")

        exhausted = ProviderChain((StubProvider("broken"),))
        await exhausted.generate("system", "prompt")
        assert exhausted.last_used is None

    def test_availability_reflects_configuration(self) -> None:
        assert ProviderChain(()).is_available is False
        assert ProviderChain((StubProvider("a"),)).is_available is True

    def test_provider_names_are_reported(self) -> None:
        chain = ProviderChain((StubProvider("a"), StubProvider("b")))
        assert chain.names == ("a", "b")


@pytest.mark.unit
class TestResponseHandling:
    """Provider responses, exercised without touching the network."""

    def _patch(self, monkeypatch: pytest.MonkeyPatch, payload: object) -> None:
        import cyber_risk.core.http as http_module

        class Response:
            def raise_for_status(self) -> None:
                return None

            def json(self) -> object:
                return payload

        class Client:
            async def __aenter__(self) -> Client:
                return self

            async def __aexit__(self, *_: object) -> None:
                return None

            async def post(self, *_: object, **__: object) -> Response:
                return Response()

        monkeypatch.setattr(http_module, "create_async_client", Client)

    async def test_gemini_text_is_extracted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(
            monkeypatch,
            {"candidates": [{"content": {"parts": [{"text": "generated"}]}}]},
        )
        provider = GeminiProvider("key", "model", 0.1)
        assert await provider.generate("system", "prompt") == "generated"

    async def test_gemini_multi_part_text_is_joined(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(
            monkeypatch,
            {"candidates": [{"content": {"parts": [{"text": "one "}, {"text": "two"}]}}]},
        )
        provider = GeminiProvider("key", "model", 0.1)
        assert await provider.generate("system", "prompt") == "one two"

    async def test_gemini_without_candidates_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(monkeypatch, {"candidates": []})
        with pytest.raises(LLMResponseError):
            await GeminiProvider("key", "model", 0.1).generate("system", "prompt")

    async def test_gemini_empty_text_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A truncated response is a failure, not an answer."""
        self._patch(
            monkeypatch,
            {"candidates": [{"content": {"parts": []}, "finishReason": "MAX_TOKENS"}]},
        )
        with pytest.raises(LLMResponseError):
            await GeminiProvider("key", "model", 0.1).generate("system", "prompt")

    async def test_chat_completion_text_is_extracted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(monkeypatch, {"choices": [{"message": {"content": "generated"}}]})
        provider = OpenAICompatibleProvider("key", "model", 0.1, "https://x.test/v1", "groq")
        assert await provider.generate("system", "prompt") == "generated"

    async def test_chat_completion_without_choices_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(monkeypatch, {"choices": []})
        provider = OpenAICompatibleProvider("key", "model", 0.1, "https://x.test/v1", "groq")
        with pytest.raises(LLMResponseError):
            await provider.generate("system", "prompt")

    async def test_chat_completion_empty_content_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._patch(monkeypatch, {"choices": [{"message": {"content": "   "}}]})
        provider = OpenAICompatibleProvider("key", "model", 0.1, "https://x.test/v1", "groq")
        with pytest.raises(LLMResponseError):
            await provider.generate("system", "prompt")

    async def test_transport_failure_becomes_a_provider_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import cyber_risk.core.http as http_module

        class Client:
            async def __aenter__(self) -> Client:
                return self

            async def __aexit__(self, *_: object) -> None:
                return None

            async def post(self, *_: object, **__: object) -> object:
                raise OSError("network unreachable")

        monkeypatch.setattr(http_module, "create_async_client", Client)

        with pytest.raises(LLMProviderUnavailableError):
            await GeminiProvider("key", "model", 0.1).generate("system", "prompt")

    async def test_failure_detail_never_contains_the_credential(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The detail reaches the logs, so it must not carry the key."""
        import cyber_risk.core.http as http_module

        class Client:
            async def __aenter__(self) -> Client:
                return self

            async def __aexit__(self, *_: object) -> None:
                return None

            async def post(self, *_: object, **__: object) -> object:
                raise OSError("failure mentioning super-secret-key")

        monkeypatch.setattr(http_module, "create_async_client", Client)

        with pytest.raises(LLMProviderUnavailableError) as caught:
            await GeminiProvider("super-secret-key", "model", 0.1).generate("s", "p")

        assert "super-secret-key" not in str(caught.value.detail)


@pytest.mark.unit
class TestProviderNaming:
    @pytest.mark.parametrize(
        ("provider", "expected"),
        [
            (GeminiProvider("k", "m", 0.1), "gemini:m"),
            (
                OpenAICompatibleProvider("k", "m", 0.1, "https://x.test/v1", "groq"),
                "groq:m",
            ),
        ],
    )
    def test_name_identifies_service_and_model(self, provider: object, expected: str) -> None:
        assert provider.name == expected  # type: ignore[attr-defined]

    def test_every_provider_name_is_supported(self) -> None:
        """A new provider must be reachable from configuration alone."""
        settings = build(gemini_api_key="a", groq_api_key="b", openrouter_api_key="c")
        assert len(build_providers(settings)) == len(LLMProviderName)
