"""Tests for log redaction.

Redaction is a security control, not a convenience. These tests assert that
credentials and inventory identifiers cannot reach a log record, including
when they are nested inside structures or embedded in free text.
"""

from __future__ import annotations

import pytest

from cyber_risk.core.logging import (
    REDACTED,
    mask_identifier,
    redact_processor,
)


def redact(event: dict[str, object]) -> dict[str, object]:
    """Run the processor the way structlog would."""
    return dict(redact_processor(None, "info", event))


@pytest.mark.unit
class TestCredentialRedaction:
    @pytest.mark.parametrize(
        "key",
        [
            "api_key",
            "API_KEY",
            "password",
            "token",
            "authorization",
            "gemini_api_key",
            "groq_api_key",
            "openrouter_api_key",
            "secret",
            "cookie",
        ],
    )
    def test_sensitive_keys_are_replaced(self, key: str) -> None:
        result = redact({key: "highly-sensitive-value"})
        assert result[key] == REDACTED
        assert "highly-sensitive-value" not in str(result)

    def test_nested_credentials_are_redacted(self) -> None:
        event = {
            "request": {
                "headers": {"authorization": "Bearer abcdef1234567890"},
                "provider": "gemini",
            }
        }
        assert "abcdef1234567890" not in str(redact(event))

    def test_credentials_inside_lists_are_redacted(self) -> None:
        event = {"attempts": [{"token": "aaaaaaaaaaaa"}, {"token": "bbbbbbbbbbbb"}]}
        rendered = str(redact(event))
        assert "aaaaaaaaaaaa" not in rendered
        assert "bbbbbbbbbbbb" not in rendered

    @pytest.mark.parametrize(
        "text",
        [
            "call failed for AIzaSyD-1234567890abcdefghij",
            "auth header was Bearer eyJhbGciOiJIUzI1NiJ9xxxx",
            "using gsk_abcdefghijklmnop for this request",
            "openai style sk-abcdefghijklmnopqrst leaked",
        ],
    )
    def test_credential_shaped_text_is_scrubbed(self, text: str) -> None:
        """A key pasted into a free-text message must not survive."""
        result = redact({"event": text})
        assert REDACTED in str(result["event"])

    def test_non_sensitive_fields_are_preserved(self) -> None:
        event = {"event": "ranking complete", "risk_count": 5, "duration_ms": 12.5}
        assert redact(event) == event


@pytest.mark.unit
class TestIdentifierMasking:
    @pytest.mark.parametrize(
        "key",
        ["asset_name", "hostname", "host", "fqdn", "owner_team", "business_owner"],
    )
    def test_inventory_identifiers_are_masked(self, key: str) -> None:
        result = redact({key: "payment-api-prod-01"})
        assert result[key] != "payment-api-prod-01"
        assert "payment-api-prod-01" not in str(result)

    def test_mask_retains_a_correlatable_prefix(self) -> None:
        """Operators must still be able to follow one asset across log lines."""
        masked = mask_identifier("payment-api-prod-01")
        assert masked.startswith("pay")
        assert "payment-api-prod-01" not in masked

    def test_masking_is_deterministic(self) -> None:
        assert mask_identifier("vpn-edge-01") == mask_identifier("vpn-edge-01")

    def test_distinct_assets_mask_distinctly(self) -> None:
        assert mask_identifier("payment-api-prod-01") != mask_identifier("vpn-edge-01")

    @pytest.mark.parametrize("value", ["", "a", "ab", "abc"])
    def test_short_identifiers_reveal_nothing(self, value: str) -> None:
        assert value not in mask_identifier(value) or value == ""


@pytest.mark.unit
class TestProcessorRobustness:
    def test_non_string_values_pass_through(self) -> None:
        event = {"count": 3, "ratio": 0.5, "ok": True, "missing": None}
        assert redact(event) == event

    def test_empty_event_is_handled(self) -> None:
        assert redact({}) == {}

    def test_list_type_is_preserved(self) -> None:
        result = redact({"items": ["a", "b"]})
        assert isinstance(result["items"], list)

    def test_tuple_type_is_preserved(self) -> None:
        result = redact({"items": ("a", "b")})
        assert isinstance(result["items"], tuple)
