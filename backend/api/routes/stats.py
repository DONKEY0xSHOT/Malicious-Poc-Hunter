from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...db.database import Database
from ..schemas import RuleInfoOut, StatsOut

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
