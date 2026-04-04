from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...db.database import Database
from ..auth import require_auth
from ..schemas import VoteRequest, VoteResponse

router = APIRouter(prefix="/findings", tags=["votes"])
limiter = Limiter(key_func=get_remote_address)


def _get_db(request: Request) -> Database:
    return request.app.state.db


@router.post("/{finding_id}/vote", response_model=VoteResponse)
@limiter.limit("20/minute")
async def vote_finding(
    request: Request,
    finding_id: int,
    body: VoteRequest,
    user: dict = Depends(require_auth),
    db: Database = Depends(_get_db),
):
    finding = await db.get_finding_detail(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    new_score = await db.upsert_vote(finding_id, user["github_user"], body.vote)

    # Fetch the user's current vote after the toggle logic
    detail = await db.get_finding_detail(finding_id, github_user=user["github_user"])
    user_vote = detail["votes"]["user_vote"] if detail else None

    return VoteResponse(score=new_score, user_vote=user_vote)
