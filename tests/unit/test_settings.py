"""Tests for the configuration layer."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cyber_risk.config.settings import (
    EmbeddingBackendName,
    Environment,
    LLMProviderName,
    RiskWeights,
    Settings,
    VectorBackendName,
    get_settings,
)


def build(**overrides: object) -> Settings:
    """Construct settings without reading a developer ``.env`` file."""
    return Settings(_env_file=None, **overrides)  # type: ignore[arg-type]


@pytest.mark.unit
class TestDefaults:
    def test_system_is_usable_with_no_configuration(self) -> None:
        """The report must be producible with zero API keys configured."""
        s = build()
        assert s.configured_providers == ()
        assert s.risk_top_n == 5
        assert s.embedding_backend is EmbeddingBackendName.LOCAL
        assert s.vector_backend is VectorBackendName.FAISS

    def test_defaults_are_development(self) -> None:
        s = build()
        assert s.app_env is Environment.DEVELOPMENT
        assert s.is_production is False

    def test_settings_are_immutable(self) -> None:
        s = build()
        with pytest.raises(ValidationError):
            s.risk_top_n = 10  # type: ignore[misc]

    def test_relative_paths_resolve_against_project_root(self) -> None:
        s = build()
        assert s.resolve_path(s.data_raw_dir).is_absolute()


@pytest.mark.unit
class TestSingleton:
    def test_settings_are_parsed_once_and_cached(self) -> None:
        """Validation is expensive and must not repeat on every access."""
        get_settings.cache_clear()
        try:
            assert get_settings() is get_settings()
        finally:
            get_settings.cache_clear()


@pytest.mark.unit
class TestSecretHandling:
    def test_api_key_is_not_exposed_in_repr(self) -> None:
        s = build(gemini_api_key="secret-key-value")
        assert "secret-key-value" not in repr(s)

    def test_api_key_is_not_exposed_in_model_dump(self) -> None:
        s = build(gemini_api_key="secret-key-value")
        assert "secret-key-value" not in str(s.model_dump())

    def test_api_key_requires_explicit_unwrapping(self) -> None:
        s = build(gemini_api_key="secret-key-value")
        key = s.api_key_for(LLMProviderName.GEMINI)
        assert key is not None
        assert key.get_secret_value() == "secret-key-value"


@pytest.mark.unit
class TestProviderChain:
    def test_only_providers_with_keys_are_considered(self) -> None:
        s = build(groq_api_key="k")
        assert s.configured_providers == (LLMProviderName.GROQ,)

    def test_preference_order_is_respected(self) -> None:
        s = build(gemini_api_key="a", groq_api_key="b", openrouter_api_key="c")
        assert s.configured_providers == (
            LLMProviderName.GEMINI,
            LLMProviderName.GROQ,
            LLMProviderName.OPENROUTER,
        )

    def test_order_can_be_overridden_from_a_csv_string(self) -> None:
        s = build(llm_provider_order="groq,gemini", gemini_api_key="a", groq_api_key="b")
        assert s.configured_providers == (LLMProviderName.GROQ, LLMProviderName.GEMINI)

    def test_duplicate_providers_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            build(llm_provider_order="gemini,gemini")

    def test_unknown_provider_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            build(llm_provider_order="gemini,notaprovider")

    def test_every_provider_resolves_a_model_name(self) -> None:
        s = build()
        for provider in LLMProviderName:
            assert s.model_name_for(provider)


@pytest.mark.unit
class TestValidation:
    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("log_level", "CHATTY"),
            ("api_port", 0),
            ("api_port", 70_000),
            ("risk_top_n", 0),
            ("retrieval_top_k", 0),
            ("retrieval_min_score", 1.5),
            ("llm_temperature", -1.0),
            ("llm_timeout_seconds", 0),
            ("embedding_backend", "pinecone"),
            ("vector_backend", "elasticsearch"),
            ("app_env", "staging"),
        ],
    )
    def test_invalid_values_are_rejected(self, field: str, value: object) -> None:
        """Bad configuration must fail at startup, not be silently coerced."""
        with pytest.raises(ValidationError):
            build(**{field: value})

    @pytest.mark.parametrize("level", ["debug", "Info", "WARNING"])
    def test_log_level_is_case_insensitive(self, level: str) -> None:
        assert build(log_level=level).log_level == level.upper()


@pytest.mark.unit
class TestRiskWeights:
    def test_default_weights_normalise_cleanly(self) -> None:
        assert RiskWeights(_env_file=None).total == pytest.approx(100.0)

    def test_weight_ordering_matches_advisory_guidance(self) -> None:
        """Exposure outranks exploitation, which outranks the remaining factors."""
        w = RiskWeights(_env_file=None)
        assert w.internet_exposure > w.active_exploitation
        assert w.active_exploitation > w.business_criticality
        assert w.business_criticality > w.ransomware_association
        assert w.ransomware_association > w.missing_controls

    def test_all_zero_weights_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RiskWeights(
                _env_file=None,
                internet_exposure=0,
                active_exploitation=0,
                business_criticality=0,
                ransomware_association=0,
                missing_controls=0,
            )

    def test_negative_weights_are_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RiskWeights(_env_file=None, internet_exposure=-1)


@pytest.mark.unit
class TestBlankCredentials:
    """A blank key must mean 'unset', never 'configured with an empty value'."""

    @pytest.mark.parametrize("blank", ["", "   ", "\t"])
    def test_blank_key_leaves_provider_unconfigured(self, blank: str) -> None:
        s = build(gemini_api_key=blank)
        assert s.api_key_for(LLMProviderName.GEMINI) is None
        assert s.configured_providers == ()

    def test_blank_key_falls_through_to_the_next_provider(self) -> None:
        s = build(gemini_api_key="", groq_api_key="real-key")
        assert s.configured_providers == (LLMProviderName.GROQ,)

    def test_blank_demo_token_disables_the_gate(self) -> None:
        assert build(demo_access_token="  ").demo_access_token is None

    def test_a_real_key_is_still_accepted(self) -> None:
        s = build(gemini_api_key="real-key")
        assert s.configured_providers == (LLMProviderName.GEMINI,)
