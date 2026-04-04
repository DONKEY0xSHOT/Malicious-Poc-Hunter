"""APScheduler setup for periodic scanning."""
from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .analyzer import Analyzer

logger = logging.getLogger(__name__)


def setup_scheduler(analyzer: Analyzer, interval_minutes: int, max_repos: int) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()

    # Run the first scan immediately on startup
    scheduler.add_job(
        _safe_scan,
        args=[analyzer, max_repos],
        id="poc_scan_initial",
        name="PoC Hunter initial scan",
        misfire_grace_time=60,
        max_instances=1,
    )

    # Then repeat on the configured interval
    scheduler.add_job(
        _safe_scan,
        trigger=IntervalTrigger(minutes=interval_minutes),
        args=[analyzer, max_repos],
        id="poc_scan",
        name="PoC Hunter scan",
        replace_existing=True,
        misfire_grace_time=60,
        max_instances=1,
    )
    logger.info("Scheduler configured: immediate first scan, then every %d minutes", interval_minutes)
    return scheduler


async def _safe_scan(analyzer: Analyzer, max_repos: int) -> None:
    """Wrapper so scheduler never crashes on scan errors."""
    try:
        result = await analyzer.run_scan(max_repos=max_repos)
        logger.info(
            "Scheduled scan complete: %d scanned, %d flagged",
            result.repos_scanned,
            result.repos_flagged,
        )
    except Exception as exc:
        logger.error("Scheduled scan raised an exception: %s", exc, exc_info=True)
