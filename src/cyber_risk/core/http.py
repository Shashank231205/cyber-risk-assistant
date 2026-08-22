"""Outbound HTTP with correct certificate verification everywhere.

Certificate verification is never disabled. Some corporate networks terminate
TLS at an inspecting proxy whose certificate authority is trusted by the
operating system but absent from the bundle Python ships with, which makes
otherwise valid requests fail locally while succeeding in production.

``truststore`` resolves this by having Python consult the operating system
trust store, so the same code verifies correctly on a developer workstation,
in CI and in a container, with no per-environment exception and no weakened
verification anywhere.
"""

from __future__ import annotations

from typing import Final

import httpx
import truststore

from cyber_risk.core.logging import get_logger

logger = get_logger(__name__)

DEFAULT_TIMEOUT: Final[float] = 60.0
_TRUST_STORE_READY = False


def _ensure_trust_store() -> None:
    """Point Python's TLS verification at the operating system trust store."""
    global _TRUST_STORE_READY
    if not _TRUST_STORE_READY:
        truststore.inject_into_ssl()
        _TRUST_STORE_READY = True


def create_client(timeout: float = DEFAULT_TIMEOUT) -> httpx.Client:
    """Return a synchronous client with verification enabled."""
    _ensure_trust_store()
    return httpx.Client(timeout=timeout, follow_redirects=True)


def create_async_client(timeout: float = DEFAULT_TIMEOUT) -> httpx.AsyncClient:
    """Return an asynchronous client with verification enabled.

    Reused across requests by callers so that connection pooling avoids a
    fresh TLS handshake per call.
    """
    _ensure_trust_store()
    return httpx.AsyncClient(timeout=timeout, follow_redirects=True)
