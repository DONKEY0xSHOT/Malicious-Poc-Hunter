from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...db.database import Database
from ..schemas import RuleInfoOut, StatsOut

logger = logging.getLogger(__name__)

router = APIRouter(tags=["stats"])
limiter = Limiter(key_func=get_remote_address)


def _get_db(request: Request) -> Database:
    return request.app.state.db


@router.get("/stats", response_model=StatsOut)
@limiter.limit("60/minute")
async def get_stats(request: Request, db: Database = Depends(_get_db)):
    stats = await db.get_stats()
    stats["rules_count"] = len(request.app.state.yara_engine.get_rule_info())
    return stats


@router.get("/rules", response_model=list[RuleInfoOut])
@limiter.limit("60/minute")
async def get_rules(request: Request):
    return request.app.state.yara_engine.get_rule_info()


@router.get("/debug/connectivity")
@limiter.limit("5/minute")
async def debug_connectivity(request: Request):
    """Diagnostic endpoint: tests GitHub API and download connectivity.

    Visit /api/v1/debug/connectivity in your browser to see what's failing.
    """
    from ...scanner.github_client import GitHubClient

    gh: GitHubClient = request.app.state.analyzer._gh
    try:
        result = await gh.check_connectivity()
    except Exception as exc:
        logger.exception("Connectivity check failed")
        result = {"error": str(exc)}
    return JSONResponse(content=result)
