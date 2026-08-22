"""Application exception hierarchy.

Every failure raised by this system derives from :class:`CyberRiskError`, so
callers can distinguish expected domain failures from genuine defects.

Each error carries two distinct messages:

``message``
    Safe for external consumption. Must never contain asset names, hostnames,
    vulnerability records or credentials.
``detail``
    Operator-facing context, emitted to structured logs only and never
    returned in an API response.

That split is deliberate: this system handles a confidential asset and
vulnerability inventory, and an unhandled traceback echoed to a caller is a
realistic disclosure path.
"""

from __future__ import annotations

from typing import Any


class CyberRiskError(Exception):
    """Base class for all application errors.

    Args:
        message: Safe, non-sensitive summary suitable for an API response.
        detail: Operator-facing context for logs. Never returned to callers.
        context: Structured, non-sensitive key/value pairs for log enrichment.
    """

    status_code: int = 500
    error_code: str = "internal_error"

    def __init__(
        self,
        message: str,
        *,
        detail: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail
        self.context: dict[str, Any] = context or {}

    def __str__(self) -> str:
        """Return the safe message; never the operator detail."""
        return self.message

    def to_public_dict(self) -> dict[str, str]:
        """Render the error for an API response, excluding operator detail."""
        return {"error": self.error_code, "message": self.message}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
class ConfigurationError(CyberRiskError):
    """Raised when the application is misconfigured and cannot start."""

    status_code = 500
    error_code = "configuration_error"


# ---------------------------------------------------------------------------
# Data ingestion
# ---------------------------------------------------------------------------
class DataError(CyberRiskError):
    """Base class for failures loading or validating input data."""

    status_code = 500
    error_code = "data_error"


class DataSourceNotFoundError(DataError):
    """Raised when a required input file is absent."""

    error_code = "data_source_not_found"


class SchemaValidationError(DataError):
    """Raised when an input file does not match its expected schema.

    Raised eagerly at load time rather than tolerated: silently coercing a
    malformed risk input would produce a confidently wrong ranking, which is
    worse than a refusal to start.
    """

    error_code = "schema_validation_error"


class ReferenceDataError(DataError):
    """Raised when a reference corpus is missing, stale or unreadable."""

    error_code = "reference_data_error"


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------
class RetrievalError(CyberRiskError):
    """Base class for vector index and retrieval failures."""

    status_code = 503
    error_code = "retrieval_error"


class IndexNotBuiltError(RetrievalError):
    """Raised when the control catalogue index has not been built yet."""

    error_code = "index_not_built"


class EmbeddingError(RetrievalError):
    """Raised when an embedding backend fails to produce vectors."""

    error_code = "embedding_error"


# ---------------------------------------------------------------------------
# Language model providers
# ---------------------------------------------------------------------------
class LLMError(CyberRiskError):
    """Base class for language model provider failures."""

    status_code = 503
    error_code = "llm_error"


class LLMProviderUnavailableError(LLMError):
    """Raised when a single provider cannot serve a request.

    Recoverable by design: the provider chain moves to the next candidate and,
    if every provider is exhausted, narration falls back to deterministic
    templates so the ranked report is still produced.
    """

    error_code = "llm_provider_unavailable"


class LLMResponseError(LLMError):
    """Raised when a provider returns a malformed or unusable response."""

    error_code = "llm_response_error"


# ---------------------------------------------------------------------------
# Risk model
# ---------------------------------------------------------------------------
class RiskModelError(CyberRiskError):
    """Raised when the risk model cannot produce a ranking."""

    status_code = 500
    error_code = "risk_model_error"


# ---------------------------------------------------------------------------
# API surface
# ---------------------------------------------------------------------------
class AuthorizationError(CyberRiskError):
    """Raised when a caller is not permitted to access a resource."""

    status_code = 401
    error_code = "unauthorized"
