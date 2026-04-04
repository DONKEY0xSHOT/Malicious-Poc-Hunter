"""FastAPI application entry point."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send

from ..config import settings
from ..db.database import Database
from ..scanner.analyzer import Analyzer
from ..scanner.github_client import GitHubClient
from ..scanner.scheduler import setup_scheduler
from ..scanner.yara_engine import YaraEngine
from .middleware import SecurityHeadersMiddleware
from .routes import auth, comments, findings, scan_runs, stats, votes

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

# Resolve frontend directory once at module load
_FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"
_INDEX_HTML = _FRONTEND_DIR / "index.html"
_STATIC_DIR = _FRONTEND_DIR / "static"


# ---------------------------------------------------------------------------
# SPA fallback middleware: intercept 404 responses for non-API GET requests
# and serve index.html instead.  This is more reliable than a catch-all route
# because it runs *after* all routing (including StaticFiles mounts) and is
# unaffected by route registration order.
# ---------------------------------------------------------------------------
class SPAFallbackMiddleware:
    """ASGI middleware that serves index.html for non-API GET 404s."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path: str = scope.get("path", "")
        method: str = scope.get("method", "")

        # Only intercept GET requests for non-API, non-static paths
        if method != "GET" or path.startswith("/api/"):
            return await self.app(scope, receive, send)

        # Capture the response status code from the inner app
        response_started = False
        status_code = 200
        original_headers: list = []
        body_parts: list[bytes] = []

        async def capture_send(message: dict) -> None:
            nonlocal response_started, status_code, original_headers
            if message["type"] == "http.response.start":
                status_code = message["status"]
                original_headers = message.get("headers", [])
                response_started = True
                if status_code != 404:
                    # Not a 404 -- pass through immediately
                    await send(message)
                # If 404, hold the start message so we can replace it
            elif message["type"] == "http.response.body":
                if status_code != 404:
                    await send(message)
                else:
                    # Buffer the 404 body (we will discard it)
                    body_parts.append(message.get("body", b""))

        await self.app(scope, receive, capture_send)

        # If the inner app returned 404, serve index.html instead
        if status_code == 404 and _INDEX_HTML.is_file():
            html_bytes = _INDEX_HTML.read_bytes()
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    [b"content-type", b"text/html; charset=utf-8"],
                    [b"content-length", str(len(html_bytes)).encode()],
                ],
            })
            await send({
                "type": "http.response.body",
                "body": html_bytes,
            })
        elif status_code == 404:
            # No index.html available -- send the original 404 through
            await send({
                "type": "http.response.start",
                "status": 404,
                "headers": original_headers,
            })
            await send({
                "type": "http.response.body",
                "body": b"".join(body_parts),
            })


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ---------- Startup ----------
    db = Database(settings.database_path)
    await db.connect()
    await db.init_schema()
    app.state.db = db

    try:
        yara_engine = YaraEngine(settings.rules_dir)
    except ValueError as exc:
        logger.error("YARA engine init failed: %s", exc)
        raise

    app.state.yara_engine = yara_engine

    gh_client = GitHubClient(
        token=settings.github_token,
        max_retries=5,
    )
    analyzer = Analyzer(
        github_client=gh_client,
        yara_engine=yara_engine,
        db=db,
        max_concurrent=settings.max_concurrent_downloads,
        max_repo_size_kb=settings.max_repo_size_kb,
    )
    app.state.analyzer = analyzer

    scheduler = setup_scheduler(
        analyzer=analyzer,
        interval_minutes=settings.scan_interval_minutes,
        max_repos=settings.max_repos_per_scan,
    )
    scheduler.start()
    app.state.scheduler = scheduler

    logger.info(
        "Application started. Frontend: %s (exists=%s). Scan interval: %d min",
        _FRONTEND_DIR, _INDEX_HTML.exists(), settings.scan_interval_minutes,
    )

    yield

    # ---------- Shutdown ----------
    scheduler.shutdown(wait=False)
    await gh_client.close()
    await db.close()
    logger.info("Application shutdown complete.")


limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Malicious PoC Hunter",
    description="Hunts malicious fake CVE exploitation PoCs targeting security researchers.",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# ---------- Middleware (order matters: outermost first) ----------
# SPA fallback is outermost so it can intercept 404s from any inner handler
app.add_middleware(SPAFallbackMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url, "*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    session_cookie="poc_session",
    max_age=86400 * 7,  # 7 days
    https_only=os.getenv("ENV", "development") == "production",
    same_site="lax",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------- API routers ----------
API_PREFIX = "/api/v1"
app.include_router(findings.router,  prefix=API_PREFIX)
app.include_router(scan_runs.router, prefix=API_PREFIX)
app.include_router(stats.router,     prefix=API_PREFIX)
app.include_router(votes.router,     prefix=API_PREFIX)
app.include_router(comments.router,  prefix=API_PREFIX)
app.include_router(auth.router,      prefix=API_PREFIX)

# ---------- Static assets ----------
if _STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")
