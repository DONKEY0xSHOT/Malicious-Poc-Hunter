from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...db.database import Database
from ..auth import require_auth
from ..schemas import CommentCreate, CommentOut

router = APIRouter(prefix="/findings", tags=["comments"])
limiter = Limiter(key_func=get_remote_address)


def _get_db(request: Request) -> Database:
    return request.app.state.db


@router.post("/{finding_id}/comments", response_model=CommentOut, status_code=201)
@limiter.limit("20/minute")
async def add_comment(
    request: Request,
    finding_id: int,
    body: CommentCreate,
    user: dict = Depends(require_auth),
    db: Database = Depends(_get_db),
):
    finding = await db.get_finding_detail(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    comment = await db.insert_comment(
        finding_id=finding_id,
        github_user=user["github_user"],
        github_avatar_url=user.get("github_avatar_url", ""),
        body=body.body,
    )
    return comment


@router.delete(
    "/{finding_id}/comments/{comment_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
@limiter.limit("20/minute")
async def delete_comment(
    request: Request,
    finding_id: int,
    comment_id: int,
    user: dict = Depends(require_auth),
    db: Database = Depends(_get_db),
):
    deleted = await db.delete_comment(comment_id, user["github_user"])
    if not deleted:
        raise HTTPException(
            status_code=403, detail="Comment not found or you are not the author"
        )
