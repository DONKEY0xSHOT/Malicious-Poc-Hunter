"""Pydantic models for API request/response bodies."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


# ------------------------------------------------------------------ #
# Shared sub-models                                                    #
# ------------------------------------------------------------------ #

class MatchedStringOut(BaseModel):
    identifier: str
    offset: int
    length: int
    data_preview: str


class MatchOut(BaseModel):
    id: int
    rule_name: str
    rule_category: str | None
    rule_severity: str | None
    file_path: str
    file_size: int | None
    matched_strings: list[MatchedStringOut]
    code_snippet: str | None
    snippet_start_line: int


class VoteInfo(BaseModel):
    score: int
    user_vote: int | None  # -1, 0, 1, or None if not voted


class CommentOut(BaseModel):
    id: int
    finding_id: int
    github_user: str
    github_avatar_url: str | None
    body: str
    created_at: str


# ------------------------------------------------------------------ #
# Findings                                                             #
# ------------------------------------------------------------------ #

class FindingSummary(BaseModel):
    id: int
    repo_full_name: str
    repo_url: str
    repo_size_kb: int
    repo_stars: int
    repo_description: str | None
    scan_status: str
    scanned_at: str
    rules_triggered: list[str]
    vote_score: int
    comment_count: int


class FindingDetail(BaseModel):
    id: int
    repo_full_name: str
    repo_url: str
    repo_size_kb: int
    repo_stars: int
    repo_description: str | None
    repo_created_at: str | None
    repo_updated_at: str | None
    default_branch: str
    scan_status: str
    scanned_at: str
    matches: list[MatchOut]
    votes: VoteInfo
    comments: list[CommentOut]


class FindingsResponse(BaseModel):
    findings: list[FindingSummary]
    total: int
    page: int
    per_page: int


# ------------------------------------------------------------------ #
# Scan runs                                                            #
# ------------------------------------------------------------------ #

class ScanRunOut(BaseModel):
    id: int
    started_at: str
    finished_at: str | None
    repos_scanned: int
    repos_flagged: int
    status: str


class ScanRunsResponse(BaseModel):
    items: list[ScanRunOut]
    total: int
    page: int
    per_page: int


# ------------------------------------------------------------------ #
# Stats / rules                                                        #
# ------------------------------------------------------------------ #

class StatsOut(BaseModel):
    total_scanned: int
    total_flagged: int
    last_scan: str | None
    last_scan_status: str | None
    rules_count: int


class RuleInfoOut(BaseModel):
    name: str
    category: str | None
    severity: str | None
    description: str | None


# ------------------------------------------------------------------ #
# Votes / comments                                                     #
# ------------------------------------------------------------------ #

class VoteRequest(BaseModel):
    vote: int = Field(..., description="1 for upvote, -1 for downvote")

    @field_validator("vote")
    @classmethod
    def validate_vote(cls, v: int) -> int:
        if v not in (-1, 1):
            raise ValueError("vote must be 1 or -1")
        return v


class VoteResponse(BaseModel):
    score: int
    user_vote: int | None


class CommentCreate(BaseModel):
    body: str = Field(..., min_length=1, max_length=2000)

    @field_validator("body")
    @classmethod
    def sanitize_body(cls, v: str) -> str:
        import re
        # Strip HTML tags
        v = re.sub(r"<[^>]+>", "", v)
        return v.strip()


# ------------------------------------------------------------------ #
# Auth                                                                 #
# ------------------------------------------------------------------ #

class UserOut(BaseModel):
    github_user: str
    github_avatar_url: str | None
