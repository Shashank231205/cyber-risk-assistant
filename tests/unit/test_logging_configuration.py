"""Tests for logging configuration and end-to-end redaction.

The redaction unit tests exercise the processor directly. These tests drive
a real configured logger so that a regression in the processor chain -- for
example dropping the redaction step -- is caught rather than assumed absent.
"""

from __future__ import annotations

import json

import pytest

from cyber_risk.core.logging import configure_logging, get_logger


@pytest.mark.unit
class TestConfiguration:
    @pytest.mark.parametrize("level", ["DEBUG", "INFO", "WARNING", "ERROR"])
    def test_configuration_accepts_each_level(self, level: str) -> None:
        configure_logging(level=level)
        assert get_logger("test") is not None

    def test_configuration_is_idempotent(self) -> None:
        configure_logging(level="INFO")
        configure_logging(level="INFO")
        assert get_logger("test") is not None

    def test_unknown_level_falls_back_rather_than_crashing(self) -> None:
        """Logging must never be the reason the application fails to start."""
        configure_logging(level="NOT_A_LEVEL")
        assert get_logger("test") is not None

    def test_json_output_is_machine_parseable(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        configure_logging(level="INFO", json_output=True)
        get_logger("test").info("ranking complete", risk_count=5)

        payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert payload["event"] == "ranking complete"
        assert payload["risk_count"] == 5
        assert payload["level"] == "info"
        assert "timestamp" in payload


@pytest.mark.unit
class TestRedactionThroughRealLogger:
    def test_credentials_do_not_reach_the_output_stream(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        configure_logging(level="INFO", json_output=True)
        get_logger("test").info(
            "provider call failed",
            api_key="AIzaSyD-super-secret-key-value",
            provider="gemini",
        )

        out = capsys.readouterr().out
        assert "AIzaSyD-super-secret-key-value" not in out
        assert "[REDACTED]" in out
        assert "gemini" in out

    def test_asset_identifiers_do_not_reach_the_output_stream(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        configure_logging(level="INFO", json_output=True)
        get_logger("test").info("scored asset", asset_name="payment-api-prod-01")

        out = capsys.readouterr().out
        assert "payment-api-prod-01" not in out

    def test_below_threshold_records_are_suppressed(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        configure_logging(level="ERROR", json_output=True)
        get_logger("test").debug("verbose diagnostic detail")
        assert capsys.readouterr().out.strip() == ""
