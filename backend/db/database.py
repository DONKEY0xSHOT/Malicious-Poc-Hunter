"""Async SQLite database layer using aiosqlite."""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

_SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, db_path: str) -> None:
        self._path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        os.makedirs(os.path.dirname(self._path), exist_ok=True) if os.path.dirname(self._path) else None
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.commit()

    async def init_schema(self) -> None:
        schema = _SCHEMA_PATH.read_text()
        await self._conn.executescript(schema)
        await self._conn.commit()
        logger.info("Database schema initialised at %s", self._path)

    async def close(self) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------ #
    # Scan runs                                                            #
    # ------------------------------------------------------------------ #

    async def insert_scan_run(self) -> int:
        async with self._conn.execute(
            "INSERT INTO scan_runs (started_at, status) VALUES (?, 'running')",
            (_now(),),
        ) as cur:
            run_id = cur.lastrowid
        await self._conn.commit()
        return run_id

    async def update_scan_run(
        self,
        run_id: int,
        status: str,
        repos_scanned: int,
        repos_flagged: int,
    ) -> None:
        await self._conn.execute(
            """UPDATE scan_runs
               SET finished_at=?, status=?, repos_scanned=?, repos_flagged=?
               WHERE id=?""",
            (_now(), status, repos_scanned, repos_flagged, run_id),
        )
        await self._conn.commit()

    async def get_latest_scan_run(self) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT 1"
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_scan_runs(self, page: int = 1, per_page: int = 20) -> dict:
        offset = (page - 1) * per_page
        async with self._conn.execute("SELECT COUNT(*) FROM scan_runs") as cur:
            total = (await cur.fetchone())[0]
        async with self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ? OFFSET ?",
            (per_page, offset),
        ) as cur:
            rows = await cur.fetchall()
        return {"items": [dict(r) for r in rows], "total": total, "page": page, "per_page": per_page}

    # ------------------------------------------------------------------ #
    # Findings                                                             #
    # ------------------------------------------------------------------ #

    async def is_recently_scanned(self, repo_full_name: str, hours: int = 24) -> bool:
        async with self._conn.execute(
            """SELECT 1 FROM findings
               WHERE repo_full_name=?
                 AND datetime(scanned_at) > datetime('now', ? || ' hours')
               LIMIT 1""",
            (repo_full_name, f"-{hours}"),
        ) as cur:
            return await cur.fetchone() is not None

    async def insert_finding(self, scan_run_id: int, data: dict[str, Any]) -> int:
        async with self._conn.execute(
            """INSERT INTO findings
               (scan_run_id, repo_full_name, repo_url, repo_size_kb,
                default_branch, repo_description, repo_stars,
                repo_created_at, repo_updated_at, scan_status, scanned_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                scan_run_id,
                data["repo_full_name"],
                data["repo_url"],
                data["repo_size_kb"],
                data["default_branch"],
                data.get("repo_description"),
                data.get("repo_stars", 0),
                data.get("repo_created_at"),
                data.get("repo_updated_at"),
                data["scan_status"],
                _now(),
            ),
        ) as cur:
            finding_id = cur.lastrowid
        await self._conn.commit()
        return finding_id

    async def insert_match(self, finding_id: int, data: dict[str, Any]) -> None:
        await self._conn.execute(
            """INSERT INTO matches
               (finding_id, rule_name, rule_category, rule_severity,
                file_path, file_size, matched_strings, code_snippet, snippet_start_line)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                finding_id,
                data["rule_name"],
                data.get("rule_category"),
                data.get("rule_severity"),
                data["file_path"],
                data.get("file_size"),
                json.dumps(data.get("matched_strings", [])),
                data.get("code_snippet"),
                data.get("snippet_start_line", 1),
            ),
        )
        await self._conn.commit()

    async def get_findings(self, filters: dict) -> dict:
        conditions: list[str] = []
        params: list[Any] = []

        status = filters.get("status", "suspicious")
        if status and status != "all":
            conditions.append("f.scan_status = ?")
            params.append(status)

        if filters.get("rule_name"):
            conditions.append(
                "EXISTS (SELECT 1 FROM matches m2 WHERE m2.finding_id=f.id AND m2.rule_name=?)"
            )
            params.append(filters["rule_name"])

        if filters.get("repo_name"):
            conditions.append("f.repo_full_name LIKE ?")
            params.append(f"%{filters['repo_name']}%")

        if filters.get("date_from"):
            conditions.append("f.scanned_at >= ?")
            params.append(filters["date_from"])

        if filters.get("date_to"):
            conditions.append("f.scanned_at <= ?")
            params.append(filters["date_to"])

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sort = filters.get("sort", "newest")
        order = {
            "newest": "f.scanned_at DESC",
            "oldest": "f.scanned_at ASC",
            "most_voted": "vote_score DESC",
        }.get(sort, "f.scanned_at DESC")

        page = max(1, int(filters.get("page", 1)))
        per_page = min(100, max(1, int(filters.get("per_page", 20))))
        offset = (page - 1) * per_page

        count_sql = f"SELECT COUNT(*) FROM findings f {where}"
        async with self._conn.execute(count_sql, params) as cur:
            total = (await cur.fetchone())[0]

        data_sql = f"""
            SELECT
                f.*,
                COALESCE(SUM(v.vote), 0) AS vote_score,
                COUNT(DISTINCT c.id)      AS comment_count,
                GROUP_CONCAT(DISTINCT m.rule_name) AS rules_triggered
            FROM findings f
            LEFT JOIN votes v   ON v.finding_id = f.id
            LEFT JOIN comments c ON c.finding_id = f.id
            LEFT JOIN matches m  ON m.finding_id = f.id
            {where}
            GROUP BY f.id
            ORDER BY {order}
            LIMIT ? OFFSET ?
        """
        async with self._conn.execute(data_sql, params + [per_page, offset]) as cur:
            rows = await cur.fetchall()

        items = []
        for r in rows:
            item = dict(r)
            item["rules_triggered"] = (
                sorted(set(item["rules_triggered"].split(",")))
                if item.get("rules_triggered")
                else []
            )
            items.append(item)

        return {"findings": items, "total": total, "page": page, "per_page": per_page}

    async def get_finding_detail(self, finding_id: int, github_user: str | None = None) -> dict | None:
        async with self._conn.execute(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None

        finding = dict(row)

        async with self._conn.execute(
            "SELECT * FROM matches WHERE finding_id=? ORDER BY id",
            (finding_id,),
        ) as cur:
            match_rows = await cur.fetchall()

        matches = []
        for m in match_rows:
            md = dict(m)
            try:
                md["matched_strings"] = json.loads(md["matched_strings"] or "[]")
            except (json.JSONDecodeError, TypeError):
                md["matched_strings"] = []
            matches.append(md)

        async with self._conn.execute(
            "SELECT COALESCE(SUM(vote),0) FROM votes WHERE finding_id=?",
            (finding_id,),
        ) as cur:
            score = (await cur.fetchone())[0]

        user_vote = None
        if github_user:
            async with self._conn.execute(
                "SELECT vote FROM votes WHERE finding_id=? AND github_user=?",
                (finding_id, github_user),
            ) as cur:
                vr = await cur.fetchone()
            user_vote = vr[0] if vr else None

        async with self._conn.execute(
            "SELECT * FROM comments WHERE finding_id=? ORDER BY created_at ASC",
            (finding_id,),
        ) as cur:
            comment_rows = await cur.fetchall()

        finding["matches"] = matches
        finding["votes"] = {"score": score, "user_vote": user_vote}
        finding["comments"] = [dict(c) for c in comment_rows]
        return finding

    # ------------------------------------------------------------------ #
    # Votes                                                                #
    # ------------------------------------------------------------------ #

    async def upsert_vote(self, finding_id: int, github_user: str, vote: int) -> int:
        """Insert or toggle vote. Returns new aggregate score."""
        async with self._conn.execute(
            "SELECT vote FROM votes WHERE finding_id=? AND github_user=?",
            (finding_id, github_user),
        ) as cur:
            existing = await cur.fetchone()

        if existing and existing[0] == vote:
            # Same vote → remove (toggle off)
            await self._conn.execute(
                "DELETE FROM votes WHERE finding_id=? AND github_user=?",
                (finding_id, github_user),
            )
        else:
            await self._conn.execute(
                "INSERT OR REPLACE INTO votes (finding_id, github_user, vote, created_at) VALUES (?,?,?,?)",
                (finding_id, github_user, vote, _now()),
            )
        await self._conn.commit()

        async with self._conn.execute(
            "SELECT COALESCE(SUM(vote),0) FROM votes WHERE finding_id=?",
            (finding_id,),
        ) as cur:
            return (await cur.fetchone())[0]

    # ------------------------------------------------------------------ #
    # Comments                                                             #
    # ------------------------------------------------------------------ #

    async def insert_comment(
        self,
        finding_id: int,
        github_user: str,
        github_avatar_url: str,
        body: str,
    ) -> dict:
        async with self._conn.execute(
            """INSERT INTO comments
               (finding_id, github_user, github_avatar_url, body, created_at)
               VALUES (?,?,?,?,?)""",
            (finding_id, github_user, github_avatar_url, body, _now()),
        ) as cur:
            comment_id = cur.lastrowid
        await self._conn.commit()
        async with self._conn.execute(
            "SELECT * FROM comments WHERE id=?", (comment_id,)
        ) as cur:
            return dict(await cur.fetchone())

    async def delete_comment(self, comment_id: int, github_user: str) -> bool:
        async with self._conn.execute(
            "SELECT github_user FROM comments WHERE id=?", (comment_id,)
        ) as cur:
            row = await cur.fetchone()
        if not row or row[0] != github_user:
            return False
        await self._conn.execute("DELETE FROM comments WHERE id=?", (comment_id,))
        await self._conn.commit()
        return True

    # ------------------------------------------------------------------ #
    # Stats / misc                                                         #
    # ------------------------------------------------------------------ #

    async def get_stats(self) -> dict:
        async with self._conn.execute(
            "SELECT COUNT(*) FROM findings"
        ) as cur:
            total_scanned = (await cur.fetchone())[0]
        async with self._conn.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_status='suspicious'"
        ) as cur:
            total_flagged = (await cur.fetchone())[0]
        latest = await self.get_latest_scan_run()
        return {
            "total_scanned": total_scanned,
            "total_flagged": total_flagged,
            "last_scan": latest["started_at"] if latest else None,
            "last_scan_status": latest["status"] if latest else None,
        }
