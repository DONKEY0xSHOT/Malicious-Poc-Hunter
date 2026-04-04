"""FastAPI application entry point."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware

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
    logger.info("Application started. Scan interval: %d min", settings.scan_interval_minutes)

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

# ---------- Middleware (order matters) ----------
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url],
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

# ---------- Routers ----------
API_PREFIX = "/api/v1"
app.include_router(findings.router,  prefix=API_PREFIX)
app.include_router(scan_runs.router, prefix=API_PREFIX)
app.include_router(stats.router,     prefix=API_PREFIX)
app.include_router(votes.router,     prefix=API_PREFIX)
app.include_router(comments.router,  prefix=API_PREFIX)
app.include_router(auth.router,      prefix=API_PREFIX)

# ---------- Static frontend (SPA with catch-all) ----------
_FRONTEND_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))

if os.path.isdir(_FRONTEND_DIR):
    # Serve /static/* files directly
    _STATIC_DIR = os.path.join(_FRONTEND_DIR, "static")
    if os.path.isdir(_STATIC_DIR):
        app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    # SPA catch-all: any path not matched by /api/* or /static/* serves index.html
    from fastapi.responses import FileResponse

    @app.get("/{full_path:path}")
    async def spa_fallback(full_path: str):
        # If the exact file exists in frontend/, serve it (e.g. favicon.ico)
        file_path = os.path.join(_FRONTEND_DIR, full_path)
        if full_path and os.path.isfile(file_path):
            return FileResponse(file_path)
        # Otherwise, serve index.html and let the SPA router handle it
        return FileResponse(os.path.join(_FRONTEND_DIR, "index.html"))
