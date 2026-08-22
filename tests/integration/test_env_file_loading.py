"""Tests that settings load from a real ``.env`` file.

Regression coverage: the unit tests construct ``Settings`` directly, which
bypasses the dotenv source entirely. A parsing failure that only occurs when
reading a file therefore reaches production undetected -- which is exactly
what happened with comma-separated sequence values, where the settings source
attempted to JSON-decode them before the field validator ran.

These tests read the committed ``.env.example`` and files written in the
format that file documents.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cyber_risk.config.settings import PROJECT_ROOT, LLMProviderName, Settings

ENV_EXAMPLE = PROJECT_ROOT / ".env.example"


def load(env_file: Path) -> Settings:
    """Load settings from a specific env file."""
    return Settings(_env_file=env_file)  # type: ignore[arg-type]


@pytest.mark.integration
class TestCommittedTemplate:
    def test_env_example_exists(self) -> None:
        assert ENV_EXAMPLE.is_file(), "the committed environment template is missing"

    def test_env_example_loads_without_error(self) -> None:
        """The documented template must not crash the application at startup."""
        settings = load(ENV_EXAMPLE)
        assert settings.risk_top_n >= 1

    def test_env_example_contains_no_real_credentials(self) -> None:
        """The template is committed, so every key entry must be empty."""
        for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or "=" not in stripped:
                continue
            name, _, value = stripped.partition("=")
            if name.strip().endswith(("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")):
                assert value.strip() == "", f"{name} must be blank in the template"

    def test_template_leaves_the_system_key_free(self) -> None:
        """A reviewer running from the template gets deterministic mode."""
        assert load(ENV_EXAMPLE).configured_providers == ()


@pytest.mark.integration
class TestSequenceParsing:
    def test_comma_separated_provider_order_parses(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("LLM_PROVIDER_ORDER=groq,gemini,openrouter\n", encoding="utf-8")

        assert load(env).llm_provider_order == (
            LLMProviderName.GROQ,
            LLMProviderName.GEMINI,
            LLMProviderName.OPENROUTER,
        )

    def test_single_value_sequence_parses(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("LLM_PROVIDER_ORDER=groq\n", encoding="utf-8")
        assert load(env).llm_provider_order == (LLMProviderName.GROQ,)

    def test_whitespace_around_values_is_tolerated(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("LLM_PROVIDER_ORDER=groq , gemini\n", encoding="utf-8")
        assert load(env).llm_provider_order == (
            LLMProviderName.GROQ,
            LLMProviderName.GEMINI,
        )

    def test_comma_separated_cors_origins_parse(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text(
            "CORS_ALLOWED_ORIGINS=https://a.example,https://b.example\n",
            encoding="utf-8",
        )
        assert load(env).cors_allowed_origins == (
            "https://a.example",
            "https://b.example",
        )

    def test_invalid_provider_in_file_is_rejected_loudly(self, tmp_path: Path) -> None:
        """Misconfiguration must fail fast rather than silently drop a provider."""
        env = tmp_path / ".env"
        env.write_text("LLM_PROVIDER_ORDER=groq,notaprovider\n", encoding="utf-8")
        with pytest.raises(Exception, match=r"llm_provider_order|validation"):
            load(env)


@pytest.mark.integration
class TestValuesFromFile:
    def test_scalar_overrides_apply(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text(
            "APP_ENV=production\nLOG_LEVEL=warning\nRISK_TOP_N=10\n",
            encoding="utf-8",
        )
        settings = load(env)

        assert settings.is_production is True
        assert settings.log_level == "WARNING"
        assert settings.risk_top_n == 10

    def test_weight_overrides_apply_through_the_env_prefix(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WEIGHT_INTERNET_EXPOSURE", "40")
        assert Settings(_env_file=None).weights.internet_exposure == pytest.approx(40.0)

    def test_api_key_from_file_is_wrapped_as_a_secret(self, tmp_path: Path) -> None:
        env = tmp_path / ".env"
        env.write_text("GEMINI_API_KEY=file-sourced-secret\n", encoding="utf-8")
        settings = load(env)

        assert "file-sourced-secret" not in repr(settings)
        assert settings.configured_providers == (LLMProviderName.GEMINI,)
