"""Structured logging with mandatory redaction.

This system processes a confidential asset and vulnerability inventory.
Logs are the most common accidental disclosure path for that kind of data,
so redaction is enforced by a processor in the logging pipeline rather than
left to the discipline of each call site.

Two categories are scrubbed before a record is emitted:

Credentials
    Any field whose name suggests a secret is replaced with a placeholder,
    regardless of its value.
Inventory identifiers
    Hostnames and asset names are masked so that operational logs remain
    useful for correlation without reproducing the inventory itself.

Development emits colourised console output; production emits JSON for
ingestion by any log aggregator without a vendor dependency.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import MutableMapping
from typing import Any, Final

import structlog
from structlog.types import EventDict, Processor

REDACTED: Final[str] = "[REDACTED]"

#: Field names treated as credentials wherever they appear.
SENSITIVE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "cookie",
        "credential",
        "credentials",
        "gemini_api_key",
        "groq_api_key",
        "openrouter_api_key",
        "password",
        "secret",
        "session",
        "token",
        "x-api-key",
    }
)

#: Field names carrying inventory identifiers that are masked rather than dropped.
IDENTIFIER_KEYS: Final[frozenset[str]] = frozenset(
    {
        "asset_name",
        "hostname",
        "host",
        "fqdn",
        "owner_team",
        "business_owner",
    }
)

_BEARER_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"(bearer\s+)[A-Za-z0-9._\-]{8,}", re.IGNORECASE
)
_API_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"\b(AIza[A-Za-z0-9._\-]{10,}|gsk_[A-Za-z0-9]{10,}|sk-[A-Za-z0-9._\-]{10,})\b"
)


def mask_identifier(value: str) -> str:
    """Mask an inventory identifier, preserving just enough to correlate.

    Keeps a short prefix so operators can follow a record across log lines
    without the log reproducing the asset inventory.

    Args:
        value: The identifier to mask.

    Returns:
        The masked identifier, for example ``payment-api-prod-01`` becomes
        ``pay***(19)``.
    """
    text = str(value)
    if len(text) <= 3:
        return f"***({len(text)})"
    return f"{text[:3]}***({len(text)})"


def _scrub_text(value: str) -> str:
    """Remove credential-shaped substrings from a free-text value."""
    scrubbed = _BEARER_PATTERN.sub(rf"\1{REDACTED}", value)
    return _API_KEY_PATTERN.sub(REDACTED, scrubbed)


def _scrub_value(key: str, value: Any) -> Any:
    """Recursively redact a single key/value pair."""
    normalised = key.lower()

    if normalised in SENSITIVE_KEYS:
        return REDACTED
    if normalised in IDENTIFIER_KEYS and isinstance(value, str):
        return mask_identifier(value)
    if isinstance(value, str):
        return _scrub_text(value)
    if isinstance(value, MutableMapping):
        return {k: _scrub_value(str(k), v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_scrub_value(key, item) for item in value)
    return value


def redact_processor(
    _logger: object,
    _method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Redact credentials and inventory identifiers from a log event."""
    return {key: _scrub_value(str(key), value) for key, value in event_dict.items()}


def configure_logging(*, level: str = "INFO", json_output: bool = False) -> None:
    """Configure structlog and the standard library logging bridge.

    Idempotent: safe to call from both the application entry point and test
    fixtures.

    Args:
        level: Minimum level to emit, for example ``"INFO"``.
        json_output: Emit JSON lines instead of colourised console output.
            Enabled in production.
    """
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
        force=True,
    )

    shared: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        redact_processor,
    ]

    renderer: Processor = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=False)
    )

    structlog.configure(
        processors=[*shared, structlog.processors.format_exc_info, renderer],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper(), logging.INFO)
        ),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound structured logger for ``name``."""
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
