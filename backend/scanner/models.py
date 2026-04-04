"""Pydantic models shared across the scanner layer."""
from __future__ import annotations

from pydantic import BaseModel, Field


class RepoInfo(BaseModel):
    full_name: str
    html_url: str
    default_branch: str
    size: int  # KB
    description: str | None = None
    stargazers_count: int = 0
    created_at: str | None = None
    updated_at: str | None = None


class MatchedString(BaseModel):
    identifier: str
    offset: int
    length: int
    data_preview: str  # first 80 bytes as escaped string


class YaraMatch(BaseModel):
    rule_name: str
    rule_category: str | None = None
    rule_severity: str | None = None
    file_path: str
    file_size: int = 0
    matched_strings: list[MatchedString] = Field(default_factory=list)
    code_snippet: str = ""
    snippet_start_line: int = 1


class ScanRunResult(BaseModel):
    run_id: int
    repos_scanned: int = 0
    repos_flagged: int = 0
    status: str = "completed"
