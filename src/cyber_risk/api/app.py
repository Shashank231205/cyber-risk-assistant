"""The HTTP application.

Everything expensive happens once during startup: the data pack is loaded, the
retrieval index is read and the embedding model is warmed. A reader therefore
waits for a cached report rather than for a pipeline.

Errors are translated at the boundary. Domain errors carry a safe message and
an operator detail; only the safe message crosses the boundary, and an
unhandled exception becomes a generic response with a correlation identifier
rather than a traceback. This system holds a confidential inventory, and a
stack trace echoed to a caller is a realistic disclosure path.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Query, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.cors import CORSMiddleware

from cyber_risk import __version__
from cyber_risk.api.schemas import ErrorResponse, HealthResponse, ReportResponse
from cyber_risk.api.templates import render_page
from cyber_risk.config.settings import Settings, get_settings
from cyber_risk.core.exceptions import AuthorizationError, CyberRiskError
from cyber_risk.core.logging import configure_logging, get_logger
from cyber_risk.services.container import Application
from cyber_risk.services.renderer import render_report

logger = get_logger(__name__)

#: Headers applied to every response. Defence in depth for a page that renders
#: text drawn from internal records.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; script-src 'none'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'"
    ),
}

limiter = Limiter(key_func=get_remote_address)


def get_application(request: Request) -> Application:
    """Return the assembled application from application state."""
    application: Application = request.app.state.application
    return application


def require_access(request: Request) -> None:
    """Enforce the optional shared demo token.

    Left unset the service is open, which is the default for a public
    demonstration. Setting it gates every report endpoint.
    """
    settings: Settings = request.app.state.settings
    expected = settings.demo_access_token
    if expected is None:
        return

    supplied = request.headers.get("x-access-token") or request.query_params.get("token")
    if supplied != expected.get_secret_value():
        raise AuthorizationError(
            "A valid access token is required.",
            detail="request rejected: missing or incorrect access token",
        )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Build the application once, before the first request arrives.

    Settings are taken from application state rather than the process-wide
    singleton, so a caller that passed explicit settings gets those, and tests
    need no patching to run against a configuration of their choosing.
    """
    settings: Settings = app.state.settings
    configure_logging(level=settings.log_level, json_output=settings.is_production)

    application = Application(settings)
    application.warm_up()
    await application.reports.generate()

    app.state.application = application
    logger.info("startup complete", version=__version__)

    yield

    logger.info("shutdown complete")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Construct the HTTP application."""
    config = settings or get_settings()

    app = FastAPI(
        title="Cyber Risk Assistant",
        version=__version__,
        description=(
            "Evidence-based cyber risk prioritisation with remediation guidance "
            "retrieved from NIST SP 800-53 Rev. 5."
        ),
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
    )

    app.state.settings = config
    app.state.limiter = limiter
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.cors_allowed_origins),
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["x-access-token"],
    )

    _register_middleware(app)
    _register_error_handlers(app)
    _register_routes(app, config)
    return app


def _register_middleware(app: FastAPI) -> None:
    """Attach request correlation and security headers."""

    @app.middleware("http")
    async def add_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = uuid.uuid4().hex[:12]
        request.state.request_id = request_id

        response = await call_next(request)

        response.headers.update(SECURITY_HEADERS)
        response.headers["X-Request-ID"] = request_id
        return response


def _register_error_handlers(app: FastAPI) -> None:
    """Translate errors into responses that disclose nothing internal."""

    @app.exception_handler(CyberRiskError)
    async def handle_domain_error(request: Request, exc: CyberRiskError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "")
        logger.warning(
            "request failed",
            error=exc.error_code,
            detail=exc.detail,
            request_id=request_id,
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=exc.error_code, message=exc.message, request_id=request_id
            ).model_dump(),
        )

    @app.exception_handler(RateLimitExceeded)
    async def handle_rate_limit(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=ErrorResponse(
                error="rate_limited",
                message="Too many requests. Please retry shortly.",
                request_id=getattr(request.state, "request_id", ""),
            ).model_dump(),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        request_id = getattr(request.state, "request_id", "")
        logger.error(
            "unhandled error",
            error_type=type(exc).__name__,
            request_id=request_id,
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                error="internal_error",
                message="The request could not be completed.",
                request_id=request_id,
            ).model_dump(),
        )


def _register_routes(app: FastAPI, config: Settings) -> None:
    """Attach the public routes."""
    rate_limit = f"{config.rate_limit_per_minute}/minute"

    @app.get("/health", response_model=HealthResponse, tags=["operations"])
    async def health() -> HealthResponse:
        """Liveness. Answers without touching the report pipeline."""
        return HealthResponse(status="ok", version=__version__)

    @app.get("/ready", response_model=HealthResponse, tags=["operations"])
    async def ready(application: Application = Depends(get_application)) -> HealthResponse:
        """Readiness. Confirms the index and providers are in place."""
        return HealthResponse(
            status="ready",
            version=__version__,
            controls_indexed=application.retriever.catalogue_size,
            narration_providers=application.chain.names,
        )

    @app.get("/", response_class=HTMLResponse, tags=["report"])
    @limiter.limit(rate_limit)
    async def index(
        request: Request,
        application: Application = Depends(get_application),
        _: None = Depends(require_access),
    ) -> HTMLResponse:
        """The report as a readable page."""
        report = await application.reports.generate()
        return HTMLResponse(render_page(report))

    @app.get("/report", response_model=ReportResponse, tags=["report"])
    @limiter.limit(rate_limit)
    async def report_json(
        request: Request,
        application: Application = Depends(get_application),
        _: None = Depends(require_access),
        limit: int = Query(default=0, ge=0, le=50, description="0 uses the configured count"),
    ) -> ReportResponse:
        """The report as structured data, for machine consumption."""
        report = await application.reports.generate(limit or None)
        return ReportResponse.from_report(report)

    @app.get("/report.md", response_class=PlainTextResponse, tags=["report"])
    @limiter.limit(rate_limit)
    async def report_markdown(
        request: Request,
        application: Application = Depends(get_application),
        _: None = Depends(require_access),
    ) -> PlainTextResponse:
        """The report as Markdown, for pasting into a document."""
        report = await application.reports.generate()
        return PlainTextResponse(render_report(report), media_type="text/markdown")

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon() -> Response:
        """Answer the browser's automatic request without logging an error."""
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    if not config.is_production:

        @app.get("/debug/config", tags=["operations"], include_in_schema=False)
        async def debug_config() -> dict[str, object]:
            """Non-secret configuration, for local diagnosis only.

            Registered only outside production, and reports whether a key is
            present rather than any part of its value.
            """
            return {
                "environment": config.app_env.value,
                "embedding_backend": config.embedding_backend.value,
                "vector_backend": config.vector_backend.value,
                "risk_top_n": config.risk_top_n,
                "providers_configured": [p.value for p in config.configured_providers],
            }
