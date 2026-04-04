"""Orchestrates concurrent repository scanning."""
from __future__ import annotations

import asyncio
import io
import logging
import tempfile
import zipfile
from pathlib import Path

from ..db.database import Database
from .github_client import GitHubClient
from .models import RepoInfo, ScanRunResult, YaraMatch
from .snippet import extract_snippet
from .yara_engine import YaraEngine

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(
        self,
        github_client: GitHubClient,
        yara_engine: YaraEngine,
        db: Database,
        max_concurrent: int = 5,
        max_repo_size_kb: int = 100,
    ) -> None:
        self._gh = github_client
        self._yara = yara_engine
        self._db = db
        self._sem = asyncio.Semaphore(max_concurrent)
        self._max_repo_size_kb = max_repo_size_kb

    async def run_scan(self, max_repos: int = 100) -> ScanRunResult:
        """Discover and scan up to *max_repos* repositories. Returns run summary."""
        run_id = await self._db.insert_scan_run()
        logger.info("Scan run #%d started (max_repos=%d)", run_id, max_repos)

        repos_scanned = 0
        repos_flagged = 0
        status = "completed"

        try:
            tasks: list[asyncio.Task] = []
            async with asyncio.TaskGroup() as tg:
                async for repo in self._gh.search_cve_repos(max_repos=max_repos):
                    if repo.size > self._max_repo_size_kb:
                        logger.debug("Skipping large repo %s (%dKB)", repo.full_name, repo.size)
                        continue
                    if await self._db.is_recently_scanned(repo.full_name):
                        logger.debug("Skipping recently scanned %s", repo.full_name)
                        continue
                    task = tg.create_task(self._analyze_one(repo, run_id))
                    tasks.append(task)

            for task in tasks:
                result = task.result() if not task.cancelled() and not task.exception() else None
                if result:
                    repos_scanned += 1
                    if result == "suspicious":
                        repos_flagged += 1

        except* Exception as eg:
            for exc in eg.exceptions:
                logger.error("Scan task error: %s", exc, exc_info=True)
            status = "failed"

        await self._db.update_scan_run(run_id, status, repos_scanned, repos_flagged)
        logger.info(
            "Scan run #%d %s: %d scanned, %d flagged",
            run_id, status, repos_scanned, repos_flagged,
        )
        return ScanRunResult(
            run_id=run_id,
            repos_scanned=repos_scanned,
            repos_flagged=repos_flagged,
            status=status,
        )

    async def _analyze_one(self, repo: RepoInfo, run_id: int) -> str:
        """Download, extract, and scan one repository. Returns scan_status string."""
        async with self._sem:
            return await self._do_analyze(repo, run_id)

    async def _do_analyze(self, repo: RepoInfo, run_id: int) -> str:
        logger.info("Analyzing %s", repo.full_name)
        zip_bytes = await self._gh.download_repo_zip(repo)

        if zip_bytes is None:
            await self._db.insert_finding(
                run_id,
                {**repo.model_dump(), "repo_full_name": repo.full_name, "repo_url": repo.html_url,
                 "repo_size_kb": repo.size, "default_branch": repo.default_branch,
                 "scan_status": "error"},
            )
            return "error"

        # Extract + scan in a thread so we don't block the event loop
        try:
            matches = await asyncio.to_thread(
                self._extract_and_scan, zip_bytes, repo.full_name
            )
        except Exception as exc:
            logger.warning("Extract/scan failed for %s: %s", repo.full_name, exc)
            await self._db.insert_finding(
                run_id,
                {**repo.model_dump(), "repo_full_name": repo.full_name, "repo_url": repo.html_url,
                 "repo_size_kb": repo.size, "default_branch": repo.default_branch,
                 "scan_status": "error"},
            )
            return "error"

        scan_status = "suspicious" if matches else "clean"
        finding_id = await self._db.insert_finding(
            run_id,
            {
                "repo_full_name": repo.full_name,
                "repo_url": repo.html_url,
                "repo_size_kb": repo.size,
                "default_branch": repo.default_branch,
                "repo_description": repo.description,
                "repo_stars": repo.stargazers_count,
                "repo_created_at": repo.created_at,
                "repo_updated_at": repo.updated_at,
                "scan_status": scan_status,
            },
        )

        for rel_path, match in matches:
            await self._db.insert_match(
                finding_id,
                {
                    "rule_name": match.rule_name,
                    "rule_category": match.rule_category,
                    "rule_severity": match.rule_severity,
                    "file_path": rel_path,
                    "file_size": match.file_size,
                    "matched_strings": [ms.model_dump() for ms in match.matched_strings],
                    "code_snippet": match.code_snippet,
                    "snippet_start_line": match.snippet_start_line,
                },
            )

        logger.info(
            "%s → %s (%d match(es))", repo.full_name, scan_status, len(matches)
        )
        return scan_status

    def _extract_and_scan(
        self, zip_bytes: bytes, repo_full_name: str
    ) -> list[tuple[str, YaraMatch]]:
        """Synchronous: extract ZIP to tempdir and YARA-scan all files."""
        with tempfile.TemporaryDirectory(prefix="poc-hunter-") as tmp:
            try:
                with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                    # Guard against zip-slip
                    for member in zf.infolist():
                        member_path = Path(tmp) / member.filename
                        if not str(member_path.resolve()).startswith(str(Path(tmp).resolve())):
                            logger.warning(
                                "Zip-slip attempt in %s: %s", repo_full_name, member.filename
                            )
                            continue
                    zf.extractall(tmp)
            except (zipfile.BadZipFile, Exception) as exc:
                raise RuntimeError(f"ZIP extraction failed: {exc}") from exc

            raw_matches = self._yara.scan_directory(tmp)

            enriched: list[tuple[str, YaraMatch]] = []
            seen: set[tuple[str, str]] = set()  # deduplicate rule+file pairs

            for rel_path, match in raw_matches:
                key = (match.rule_name, rel_path)
                if key in seen:
                    continue
                seen.add(key)

                abs_path = str(Path(tmp) / rel_path)
                snippet = extract_snippet(
                    abs_path,
                    byte_offset=(
                        match.matched_strings[0].offset
                        if match.matched_strings
                        else 0
                    ),
                    match_length=(
                        match.matched_strings[0].length
                        if match.matched_strings
                        else 0
                    ),
                )
                enriched.append(
                    (
                        rel_path,
                        match.model_copy(
                            update={
                                "code_snippet": snippet.code,
                                "snippet_start_line": snippet.start_line,
                            }
                        ),
                    )
                )

        return enriched
