"""Typed application configuration.

Configuration is read once from the environment, validated by Pydantic and
exposed as a frozen object. No other module reads ``os.environ`` directly:
that keeps configuration auditable and makes every component trivially
testable by constructing a ``Settings`` instance explicitly.

Every setting has a working default. The system produces a complete ranked
risk report with no API keys configured at all; keys enable the optional
natural-language narration layer only.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from typing_extensions import Self

PROJECT_ROOT: Path = Path(__file__).resolve().parents[3]


class Environment(str, Enum):
    """Deployment environment."""

    DEVELOPMENT = "development"
    PRODUCTION = "production"


class LLMProviderName(str, Enum):
    """Supported large language model providers."""

    GEMINI = "gemini"
    GROQ = "groq"
    OPENROUTER = "openrouter"


class EmbeddingBackendName(str, Enum):
    """Supported embedding backends."""

    LOCAL = "local"
    GEMINI = "gemini"


class VectorBackendName(str, Enum):
    """Supported vector index backends."""

    FAISS = "faiss"
    NUMPY = "numpy"


class RiskWeights(BaseSettings):
    """Relative weights for the deterministic risk model.

    The five factors and their ordering are taken from the analyst
    prioritisation guidance in the MDR advisory. Weights are configuration
    rather than code so the model can be re-tuned and re-evaluated without
    a release.
    """

    model_config = SettingsConfigDict(env_prefix="WEIGHT_", frozen=True, extra="ignore")

    internet_exposure: float = Field(default=25.0, ge=0.0, le=100.0)
    active_exploitation: float = Field(default=22.0, ge=0.0, le=100.0)
    business_criticality: float = Field(default=20.0, ge=0.0, le=100.0)
    ransomware_association: float = Field(default=18.0, ge=0.0, le=100.0)
    missing_controls: float = Field(default=15.0, ge=0.0, le=100.0)

    @property
    def total(self) -> float:
        """Sum of all factor weights, used to normalise scores onto 0-100."""
        return (
            self.internet_exposure
            + self.active_exploitation
            + self.business_criticality
            + self.ransomware_association
            + self.missing_controls
        )

    @model_validator(mode="after")
    def _require_positive_total(self) -> Self:
        if self.total <= 0.0:
            raise ValueError("At least one risk factor weight must be greater than zero.")
        return self


class Settings(BaseSettings):
    """Root application settings, loaded from the environment and ``.env``."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        frozen=True,
        extra="ignore",
        case_sensitive=False,
    )

    # -- Application --------------------------------------------------------
    app_env: Environment = Environment.DEVELOPMENT
    log_level: str = "INFO"
    # Binding all interfaces is required inside a container, where the platform
    # -- not the process -- controls what is reachable from outside. Suppressed
    # for both scanners: ruff reports S104, bandit reports B104.
    api_host: str = "0.0.0.0"  # noqa: S104  # nosec B104
    api_port: int = Field(default=8000, ge=1, le=65535)

    # -- LLM provider chain -------------------------------------------------
    # NoDecode keeps the settings source from JSON-decoding these values, so
    # the comma-separated form documented in .env.example reaches the
    # validator below instead of failing to parse at startup.
    llm_provider_order: Annotated[tuple[LLMProviderName, ...], NoDecode] = (
        LLMProviderName.GEMINI,
        LLMProviderName.GROQ,
        LLMProviderName.OPENROUTER,
    )
    gemini_api_key: SecretStr | None = None
    gemini_model: str = "gemini-3.5-flash-lite"
    groq_api_key: SecretStr | None = None
    groq_model: str = "openai/gpt-oss-120b"
    openrouter_api_key: SecretStr | None = None
    openrouter_model: str = "google/gemma-4-31b-it:free"

    llm_timeout_seconds: float = Field(default=30.0, gt=0.0, le=300.0)
    llm_max_retries: int = Field(default=2, ge=0, le=10)
    llm_temperature: float = Field(default=0.1, ge=0.0, le=2.0)

    # -- Embeddings ---------------------------------------------------------
    embedding_backend: EmbeddingBackendName = EmbeddingBackendName.LOCAL
    embedding_model: str = "BAAI/bge-small-en-v1.5"
    embedding_batch_size: int = Field(default=32, ge=1, le=512)

    # -- Retrieval ----------------------------------------------------------
    vector_backend: VectorBackendName = VectorBackendName.NUMPY
    vector_index_path: Path = Path("data/processed/nist_index")
    retrieval_top_k: int = Field(default=4, ge=1, le=25)
    retrieval_min_score: float = Field(default=0.30, ge=0.0, le=1.0)

    # -- Data locations -----------------------------------------------------
    data_raw_dir: Path = Path("data/raw")
    data_reference_dir: Path = Path("data/reference")
    data_output_dir: Path = Path("data/outputs")

    # -- Reference corpora --------------------------------------------------
    kev_source_url: str = (
        "https://raw.githubusercontent.com/cisagov/kev-data/main/"
        "known_exploited_vulnerabilities.csv"
    )
    nist_source_url: str = (
        "https://raw.githubusercontent.com/usnistgov/oscal-content/main/"
        "nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
    )

    # -- Risk model ---------------------------------------------------------
    risk_top_n: int = Field(default=5, ge=1, le=50)
    weights: RiskWeights = Field(default_factory=RiskWeights)

    # -- Security -----------------------------------------------------------
    rate_limit_per_minute: int = Field(default=30, ge=1, le=10_000)
    cors_allowed_origins: Annotated[tuple[str, ...], NoDecode] = ("*",)
    demo_access_token: SecretStr | None = None

    @field_validator("log_level", mode="before")
    @classmethod
    def _normalise_log_level(cls, value: str) -> str:
        level = str(value).strip().upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if level not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return level

    @field_validator(
        "gemini_api_key",
        "groq_api_key",
        "openrouter_api_key",
        "demo_access_token",
        mode="before",
    )
    @classmethod
    def _blank_secret_is_unset(cls, value: object) -> object:
        """Treat a blank value as unset rather than as an empty credential.

        ``.env.example`` ships every key blank. Without this, a blank entry
        would parse as an empty secret, the provider would count as
        configured, and the chain would call it with no credential instead of
        falling through to the next provider.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("llm_provider_order", "cors_allowed_origins", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        """Accept comma-separated environment values for sequence settings."""
        if isinstance(value, str):
            return tuple(item.strip() for item in value.split(",") if item.strip())
        return value

    @field_validator("llm_provider_order")
    @classmethod
    def _reject_duplicate_providers(
        cls, value: tuple[LLMProviderName, ...]
    ) -> tuple[LLMProviderName, ...]:
        if len(set(value)) != len(value):
            raise ValueError("llm_provider_order must not contain duplicate providers.")
        return value

    @property
    def is_production(self) -> bool:
        """Whether the application is running with production hardening."""
        return self.app_env is Environment.PRODUCTION

    def api_key_for(self, provider: LLMProviderName) -> SecretStr | None:
        """Return the configured API key for ``provider``, if any."""
        keys: dict[LLMProviderName, SecretStr | None] = {
            LLMProviderName.GEMINI: self.gemini_api_key,
            LLMProviderName.GROQ: self.groq_api_key,
            LLMProviderName.OPENROUTER: self.openrouter_api_key,
        }
        return keys[provider]

    def model_name_for(self, provider: LLMProviderName) -> str:
        """Return the configured model identifier for ``provider``."""
        models: dict[LLMProviderName, str] = {
            LLMProviderName.GEMINI: self.gemini_model,
            LLMProviderName.GROQ: self.groq_model,
            LLMProviderName.OPENROUTER: self.openrouter_model,
        }
        return models[provider]

    @property
    def configured_providers(self) -> tuple[LLMProviderName, ...]:
        """Providers holding an API key, in the configured preference order."""
        return tuple(p for p in self.llm_provider_order if self.api_key_for(p) is not None)

    def resolve_path(self, path: Path) -> Path:
        """Resolve ``path`` against the project root when it is relative."""
        return path if path.is_absolute() else (PROJECT_ROOT / path)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    Cached so environment parsing and validation happen exactly once. Tests
    needing different configuration should construct ``Settings`` directly
    rather than mutating this cache.
    """
    return Settings()
