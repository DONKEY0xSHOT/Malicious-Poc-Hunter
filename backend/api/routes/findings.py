from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

from ...db.database import Database
from ..schemas import FindingDetail, FindingsResponse, MatchedStringOut, MatchOut, VoteInfo

router = APIRouter(prefix="/findings", tags=["findings"])
limiter = Limiter(key_func=get_remote_address)


def _get_db(request: Request) -> Database:
    return request.app.state.db


@router.get("", response_model=FindingsResponse)
@limiter.limit("60/minute")
async def list_findings(
    request: Request,
    page:      int   = Query(default=1,  ge=1),
    per_page:  int   = Query(default=20, ge=1, le=100),
    status:    str   = Query(default="suspicious"),
    rule_name: str | None = Query(default=None),
    repo_name: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to:   str | None = Query(default=None),
    sort:      str   = Query(default="newest"),
    db: Database = Depends(_get_db),
):
    result = await db.get_findings({
        "page":      page,
        "per_page":  per_page,
        "status":    status,
        "rule_name": rule_name,
        "repo_name": repo_name,
        "date_from": date_from,
        "date_to":   date_to,
        "sort":      sort,
    })
    return result


@router.get("/{finding_id}", response_model=FindingDetail)
@limiter.limit("60/minute")
async def get_finding(
    request: Request,
    finding_id: int,
    db: Database = Depends(_get_db),
):
    from ..auth import get_current_user
    user = get_current_user(request)
    github_user = user["github_user"] if user else None

    detail = await db.get_finding_detail(finding_id, github_user=github_user)
    if not detail:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Parse matched_strings JSON for each match
    matches = []
    for m in detail.get("matches", []):
        ms_list = [MatchedStringOut(**s) for s in (m.get("matched_strings") or [])]
        matches.append(MatchOut(
            id=m["id"],
            rule_name=m["rule_name"],
            rule_category=m.get("rule_category"),
            rule_severity=m.get("rule_severity"),
            file_path=m["file_path"],
            file_size=m.get("file_size"),
            matched_strings=ms_list,
            code_snippet=m.get("code_snippet"),
            snippet_start_line=m.get("snippet_start_line", 1),
        ))

    votes_raw = detail.get("votes", {})
    return FindingDetail(
        id=detail["id"],
        repo_full_name=detail["repo_full_name"],
        repo_url=detail["repo_url"],
        repo_size_kb=detail["repo_size_kb"],
        repo_stars=detail.get("repo_stars", 0),
        repo_description=detail.get("repo_description"),
        repo_created_at=detail.get("repo_created_at"),
        repo_updated_at=detail.get("repo_updated_at"),
        default_branch=detail.get("default_branch", "main"),
        scan_status=detail["scan_status"],
        scanned_at=detail["scanned_at"],
        matches=matches,
        votes=VoteInfo(score=votes_raw.get("score", 0), user_vote=votes_raw.get("user_vote")),
        comments=detail.get("comments", []),
    )
