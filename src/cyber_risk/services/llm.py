"""Language model providers and the fallback chain.

The model writes prose. It does not decide what is risky, what ranks where, or
which control applies: those are settled before it is called, and the evidence
is handed to it already assembled. Its failure mode is therefore a less
fluent sentence rather than a wrong ranking.

Providers are tried in the configured order and the first that answers wins.
When every provider is exhausted -- no key, rate limited, unreachable -- the
caller falls back to deterministic narration, so the report is always
produced. A free-tier key is exactly the kind of dependency that disappears
during a demonstration, so it cannot be load-bearing.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import httpx

from cyber_risk.config.settings import LLMProviderName, Settings
from cyber_risk.core.exceptions import LLMProviderUnavailableError, LLMResponseError
from cyber_risk.core.logging import get_logger

logger = get_logger(__name__)

#: Ceiling on generated output. Narration is a few sentences per risk; a
#: larger allowance only buys the chance to ramble.
MAX_OUTPUT_TOKENS = 2048


@runtime_checkable
class LLMProvider(Protocol):
    """Generates text from a prompt."""

    @property
    def name(self) -> str:
        """Identifier used in logs and in the report's provenance line."""
        ...

    async def generate(self, system: str, prompt: str) -> str:
        """Return generated text, or raise if this provider cannot serve."""
        ...


class GeminiProvider:
    """Google Generative Language provider."""

    ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(
        self,
        api_key: str,
        model: str,
        temperature: float,
        label: str = "gemini",
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._label = label

    @property
    def name(self) -> str:
        """Identifier used in logs and in the report's provenance line."""
        return f"{self._label}:{self._model}"

    async def generate(self, system: str, prompt: str) -> str:
        """Return generated text, or raise if this provider cannot serve."""
        payload: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self._temperature,
                "maxOutputTokens": MAX_OUTPUT_TOKENS,
            },
        }

        data = await _post(
            url=f"{self.ENDPOINT}/{self._model}:generateContent",
            headers={"x-goog-api-key": self._api_key},
            payload=payload,
            provider=self.name,
        )

        candidates = data.get("candidates") or []
        if not candidates:
            raise LLMResponseError(
                "The language service returned no content.",
                detail=f"{self.name} returned no candidates",
            )

        parts = candidates[0].get("content", {}).get("parts") or []
        text = "".join(part.get("text", "") for part in parts).strip()
        if not text:
            reason = candidates[0].get("finishReason", "unknown")
            raise LLMResponseError(
                "The language service returned no content.",
                detail=f"{self.name} produced empty text, finish reason {reason}",
            )
        return text


class OpenAICompatibleProvider:
    """Provider for services exposing an OpenAI-compatible chat endpoint.

    Both remaining providers speak this dialect, so one implementation covers
    them and a third would need only configuration.
    """

    def __init__(
        self, api_key: str, model: str, temperature: float, base_url: str, label: str
    ) -> None:
        self._api_key = api_key
        self._model = model
        self._temperature = temperature
        self._base_url = base_url.rstrip("/")
        self._label = label

    @property
    def name(self) -> str:
        """Identifier used in logs and in the report's provenance line."""
        return f"{self._label}:{self._model}"

    async def generate(self, system: str, prompt: str) -> str:
        """Return generated text, or raise if this provider cannot serve."""
        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": self._temperature,
            "max_tokens": MAX_OUTPUT_TOKENS,
        }

        data = await _post(
            url=f"{self._base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self._api_key}"},
            payload=payload,
            provider=self.name,
        )

        choices = data.get("choices") or []
        if not choices:
            raise LLMResponseError(
                "The language service returned no content.",
                detail=f"{self.name} returned no choices",
            )

        text = (choices[0].get("message", {}).get("content") or "").strip()
        if not text:
            raise LLMResponseError(
                "The language service returned no content.",
                detail=f"{self.name} produced empty text",
            )
        return text


async def _post(
    *,
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    provider: str,
) -> dict[str, Any]:
    """Send one request, translating transport failures into domain errors.

    The credential is never included in the raised detail, which is what
    reaches the logs.
    """
    from cyber_risk.core.http import create_async_client

    try:
        async with create_async_client() as client:
            response = await client.post(url, headers=headers, json=payload)
            response.raise_for_status()
            body: dict[str, Any] = response.json()
            return body
    except httpx.HTTPStatusError as exc:
        raise LLMProviderUnavailableError(
            "The language service is unavailable.",
            detail=f"{provider} responded {exc.response.status_code}",
        ) from exc
    except Exception as exc:
        raise LLMProviderUnavailableError(
            "The language service is unavailable.",
            detail=f"{provider} request failed: {type(exc).__name__}",
        ) from exc


def build_providers(settings: Settings) -> tuple[LLMProvider, ...]:
    """Construct the configured providers, in preference order.

    Providers without a key are omitted rather than constructed and left to
    fail, so the chain reflects what is actually usable.
    """
    providers: list[LLMProvider] = []

    for choice in settings.configured_providers:
        key = settings.api_key_for(choice)
        if key is None:
            continue

        secret = key.get_secret_value()
        model = settings.model_name_for(choice)

        if choice is LLMProviderName.GEMINI:
            # One provider per credential. Free-tier quota is counted per key,
            # so exhausting the first is worth retrying on the second before
            # falling to a different provider and a different model's wording.
            providers.extend(
                GeminiProvider(
                    credential.get_secret_value(),
                    model,
                    settings.llm_temperature,
                    label="gemini" if position == 0 else f"gemini-{position + 1}",
                )
                for position, credential in enumerate(settings.gemini_keys)
            )
        elif choice is LLMProviderName.GROQ:
            providers.append(
                OpenAICompatibleProvider(
                    secret,
                    model,
                    settings.llm_temperature,
                    "https://api.groq.com/openai/v1",
                    "groq",
                )
            )
        elif choice is LLMProviderName.OPENROUTER:
            providers.append(
                OpenAICompatibleProvider(
                    secret,
                    model,
                    settings.llm_temperature,
                    "https://openrouter.ai/api/v1",
                    "openrouter",
                )
            )

    return tuple(providers)


class ProviderChain:
    """Tries each provider in turn and returns the first successful result."""

    def __init__(self, providers: tuple[LLMProvider, ...]) -> None:
        self._providers = providers
        self._last_used: str | None = None

    @property
    def is_available(self) -> bool:
        """Whether any provider is configured."""
        return bool(self._providers)

    @property
    def last_used(self) -> str | None:
        """The provider that served the most recent request, if any."""
        return self._last_used

    @property
    def names(self) -> tuple[str, ...]:
        """Names of the configured providers, in order."""
        return tuple(provider.name for provider in self._providers)

    async def generate(self, system: str, prompt: str) -> str | None:
        """Generate text, or return ``None`` when no provider can serve.

        Returning ``None`` rather than raising is deliberate: narration is an
        enhancement, and the caller has a deterministic alternative. Turning a
        rate-limited free tier into a failed report would be the wrong trade.
        """
        for provider in self._providers:
            try:
                text = await provider.generate(system, prompt)
            except (LLMProviderUnavailableError, LLMResponseError) as error:
                logger.warning(
                    "provider unavailable, trying next",
                    provider=provider.name,
                    reason=error.detail,
                )
                continue

            self._last_used = provider.name
            logger.info("narration generated", provider=provider.name)
            return text

        logger.warning("no provider could serve; using deterministic narration")
        self._last_used = None
        return None
