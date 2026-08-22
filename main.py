"""Application entry point.

Kept at the repository root so the service can be started with a single,
obvious command, both locally and by a platform that looks for it there.
"""

from __future__ import annotations

import uvicorn

from cyber_risk.api.app import create_app
from cyber_risk.config.settings import get_settings

app = create_app()


def main() -> None:
    """Run the development server."""
    settings = get_settings()
    uvicorn.run(
        "main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=not settings.is_production,
        log_config=None,
    )


if __name__ == "__main__":
    main()
