"""Async GitHub API client with rate-limit-aware pagination and ZIP downloads."""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncGenerator
from typing import Any

import httpx

from .models import RepoInfo

logger = logging.getLogger(__name__)

_SEARCH_URL = "https://api.github.com/search/repositories"
_API_BASE = "https://api.github.com"
_ACCEPT_HEADER = "application/vnd.github.v3+json"
_PAGE_SIZE = 100
_SEARCH_QUERY = "CVE-20 in:name"


class GitHubClient:
    def __init__(self, token: str = "", max_retries: int = 5) -> None:
        headers: dict[str, str] = {"Accept": _ACCEPT_HEADER}
        self._has_token = bool(token)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=10.0),
            follow_redirects=True,
        )
        self._max_retries = max_retries
        if not token:
            logger.warning(
                "No GITHUB_TOKEN configured. API rate limit is 60 req/hr "
                "(vs 5000/hr with a token). Set GITHUB_TOKEN for reliable scanning."
            )

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ #
    # Search                                                               #
    # ------------------------------------------------------------------ #

    async def search_cve_repos(
        self, max_repos: int = 100
    ) -> AsyncGenerator[RepoInfo, None]:
        """Yield RepoInfo for CVE-named repos, newest first."""
        page = 1
        yielded = 0

        while yielded < max_repos:
            params: dict[str, Any] = {
                "q": _SEARCH_QUERY,
                "sort": "updated",
                "order": "desc",
                "per_page": _PAGE_SIZE,
                "page": page,
            }
            data = await self._search_page(params)
            if data is None:
                break

            items = data.get("items", [])
            if not items:
                break

            for item in items:
                if yielded >= max_repos:
                    return
                yield RepoInfo(
                    full_name=item["full_name"],
                    html_url=item["html_url"],
                    default_branch=item.get("default_branch", "main"),
                    size=item.get("size", 0),
                    description=item.get("description"),
                    stargazers_count=item.get("stargazers_count", 0),
                    created_at=item.get("created_at"),
                    updated_at=item.get("updated_at"),
                )
                yielded += 1

            page += 1
            await asyncio.sleep(2)  # be polite to search API

    async def _search_page(self, params: dict) -> dict | None:
        """Fetch one search results page with retry/backoff on rate limits."""
        for attempt in range(self._max_retries):
            try:
                resp = await self._client.get(_SEARCH_URL, params=params)
            except httpx.RequestError as exc:
                logger.warning("Search request error (attempt %d): %s", attempt + 1, exc)
                await asyncio.sleep(2 ** attempt)
                continue

            if resp.status_code == 200:
                return resp.json()

            if resp.status_code in (403, 429):
                wait = self._rate_limit_wait(resp)
                logger.warning("Search API rate limit hit, sleeping %ds", wait)
                await asyncio.sleep(wait)
                continue

            logger.error("Search API error %d: %s", resp.status_code, resp.text[:200])
            return None

        logger.error("Search API: exhausted retries")
        return None

    # ------------------------------------------------------------------ #
    # Download                                                             #
    # ------------------------------------------------------------------ #

    async def download_repo_zip(self, repo: RepoInfo) -> bytes | None:
        """Download repository as ZIP archive via the GitHub API. Returns bytes or None."""
        url = f"{_API_BASE}/repos/{repo.full_name}/zipball/{repo.default_branch}"

        for attempt in range(self._max_retries):
            try:
                # 1. Disable automatic redirects to intercept the Location header
                resp = await self._client.get(url, follow_redirects=False)
                
                # 2. If redirected, fetch the target manually to preserve the Authorization header
                if resp.status_code in (301, 302, 307):
                    redirect_url = resp.headers.get("Location")
                    if redirect_url:
                        # Because this is a fresh get() call, self._client explicitly attaches 
                        # the default headers (including Authorization) to the new domain.
                        resp = await self._client.get(redirect_url, follow_redirects=True)
                        
            except httpx.RequestError as exc:
                logger.warning(
                    "Download error for %s (attempt %d/%d): %s",
                    repo.full_name, attempt + 1, self._max_retries, exc,
                )
                await asyncio.sleep(2 ** attempt)
                continue

            if resp.status_code == 200:
                logger.debug("Downloaded %s (%d bytes)", repo.full_name, len(resp.content))
                return resp.content

            if resp.status_code in (403, 429):
                wait = self._rate_limit_wait(resp)
                remaining = resp.headers.get("X-RateLimit-Remaining", "?")
                logger.warning(
                    "Rate limit for %s (remaining=%s), sleeping %ds (attempt %d/%d)",
                    repo.full_name, remaining, wait, attempt + 1, self._max_retries,
                )
                await asyncio.sleep(wait)
                continue

            if resp.status_code == 404:
                logger.warning(
                    "Repo/branch not found (404): %s (branch=%s)",
                    repo.full_name, repo.default_branch,
                )
                return None

            logger.warning(
                "Download HTTP %d for %s: %s",
                resp.status_code, repo.full_name, resp.text[:200],
            )
            await asyncio.sleep(2 ** attempt)
            continue

        logger.error("Download exhausted %d retries for %s", self._max_retries, repo.full_name)
        return None


    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _rate_limit_wait(resp: httpx.Response) -> int:
        """Return seconds to wait based on rate-limit headers (max 60s)."""
        reset_ts = resp.headers.get("X-RateLimit-Reset")
        if reset_ts:
            wait = int(reset_ts) - int(time.time())
            return max(1, min(wait, 60))
        return 30
