"""Shared pytest fixtures."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from cyber_risk.config.settings import Settings


@pytest.fixture
def settings() -> Settings:
    """Return default settings that ignore any developer ``.env`` file.

    Tests must not depend on whatever happens to be configured locally, so
    the env file is disabled and secrets are left unset.
    """
    return Settings(_env_file=None)


@pytest.fixture
def isolated_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
    """Remove application environment variables for the duration of a test."""
    for name in (
        "APP_ENV",
        "LOG_LEVEL",
        "GEMINI_API_KEY",
        "GROQ_API_KEY",
        "OPENROUTER_API_KEY",
        "LLM_PROVIDER_ORDER",
        "EMBEDDING_BACKEND",
        "VECTOR_BACKEND",
        "RISK_TOP_N",
    ):
        monkeypatch.delenv(name, raising=False)
    yield monkeypatch
