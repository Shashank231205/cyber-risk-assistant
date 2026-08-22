"""Tests for the exception hierarchy.

The public/operator message split exists to stop confidential inventory data
reaching an API caller. These tests hold that boundary.
"""

from __future__ import annotations

import pytest

from cyber_risk.core.exceptions import (
    AuthorizationError,
    ConfigurationError,
    CyberRiskError,
    DataError,
    DataSourceNotFoundError,
    EmbeddingError,
    IndexNotBuiltError,
    LLMError,
    LLMProviderUnavailableError,
    LLMResponseError,
    ReferenceDataError,
    RetrievalError,
    RiskModelError,
    SchemaValidationError,
)

ALL_ERRORS = [
    ConfigurationError,
    DataError,
    DataSourceNotFoundError,
    SchemaValidationError,
    ReferenceDataError,
    RetrievalError,
    IndexNotBuiltError,
    EmbeddingError,
    LLMError,
    LLMProviderUnavailableError,
    LLMResponseError,
    RiskModelError,
    AuthorizationError,
]


@pytest.mark.unit
class TestHierarchy:
    @pytest.mark.parametrize("error_cls", ALL_ERRORS)
    def test_every_error_derives_from_the_base(
        self, error_cls: type[CyberRiskError]
    ) -> None:
        assert issubclass(error_cls, CyberRiskError)

    @pytest.mark.parametrize("error_cls", ALL_ERRORS)
    def test_every_error_declares_a_unique_public_code(
        self, error_cls: type[CyberRiskError]
    ) -> None:
        assert error_cls.error_code
        assert error_cls.error_code != CyberRiskError.error_code

    def test_error_codes_are_distinct(self) -> None:
        codes = [cls.error_code for cls in ALL_ERRORS]
        assert len(codes) == len(set(codes))

    @pytest.mark.parametrize(
        ("error_cls", "expected"),
        [
            (SchemaValidationError, DataError),
            (DataSourceNotFoundError, DataError),
            (ReferenceDataError, DataError),
            (IndexNotBuiltError, RetrievalError),
            (EmbeddingError, RetrievalError),
            (LLMProviderUnavailableError, LLMError),
            (LLMResponseError, LLMError),
        ],
    )
    def test_subclasses_group_under_the_right_category(
        self, error_cls: type[CyberRiskError], expected: type[CyberRiskError]
    ) -> None:
        """Callers rely on category to decide whether a failure is recoverable."""
        assert issubclass(error_cls, expected)


@pytest.mark.unit
class TestDisclosureBoundary:
    def test_operator_detail_is_never_public(self) -> None:
        error = DataSourceNotFoundError(
            "Required input data is unavailable.",
            detail="missing file /srv/data/raw/assets.csv for host payment-api-prod-01",
        )
        public = error.to_public_dict()

        assert "payment-api-prod-01" not in str(public)
        assert "/srv/data/raw" not in str(public)
        assert public == {
            "error": "data_source_not_found",
            "message": "Required input data is unavailable.",
        }

    def test_str_returns_only_the_safe_message(self) -> None:
        error = CyberRiskError("Safe summary.", detail="internal host-01 context")
        assert str(error) == "Safe summary."
        assert "host-01" not in str(error)

    def test_detail_remains_available_for_logging(self) -> None:
        error = CyberRiskError("Safe summary.", detail="operator context")
        assert error.detail == "operator context"

    def test_public_dict_has_no_extra_keys(self) -> None:
        """Response shape is fixed so new fields cannot leak by accident."""
        error = CyberRiskError("Safe summary.", detail="x", context={"internal": "y"})
        assert set(error.to_public_dict()) == {"error", "message"}


@pytest.mark.unit
class TestConstruction:
    def test_detail_and_context_are_optional(self) -> None:
        error = CyberRiskError("Something failed.")
        assert error.detail is None
        assert error.context == {}

    def test_context_is_retained(self) -> None:
        error = CyberRiskError("Something failed.", context={"stage": "ingestion"})
        assert error.context == {"stage": "ingestion"}

    def test_context_defaults_are_not_shared_between_instances(self) -> None:
        """A mutable default would leak context across unrelated errors."""
        first = CyberRiskError("a")
        first.context["leaked"] = True
        assert CyberRiskError("b").context == {}

    def test_errors_are_raisable_and_catchable_by_base(self) -> None:
        with pytest.raises(CyberRiskError):
            raise IndexNotBuiltError("The control index is unavailable.")

    @pytest.mark.parametrize(
        ("error_cls", "status"),
        [
            (ConfigurationError, 500),
            (RiskModelError, 500),
            (RetrievalError, 503),
            (LLMError, 503),
            (AuthorizationError, 401),
        ],
    )
    def test_status_codes_map_to_http_semantics(
        self, error_cls: type[CyberRiskError], status: int
    ) -> None:
        assert error_cls("message").status_code == status
