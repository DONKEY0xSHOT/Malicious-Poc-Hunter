from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...db.database import Database
from ..schemas import ScanRunOut, ScanRunsResponse

router = APIRouter(prefix="/scan-runs", tags=["scan-runs"])
limiter = Limiter(key_func=get_remote_address)


def _get_db(request: Request) -> Database:
    return request.app.state.db


@router.get("", response_model=ScanRunsResponse)
@limiter.limit("60/minute")
async def list_scan_runs(
    request: Request,
    page:     int = Query(default=1,  ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    db: Database = Depends(_get_db),
):
    return await db.get_scan_runs(page=page, per_page=per_page)


@router.get("/latest", response_model=ScanRunOut | None)
@limiter.limit("60/minute")
async def latest_scan_run(request: Request, db: Database = Depends(_get_db)):
    return await db.get_latest_scan_run()
