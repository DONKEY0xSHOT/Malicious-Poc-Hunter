"""APScheduler setup for periodic scanning."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.date import DateTrigger
from apscheduler.triggers.interval import IntervalTrigger

from .analyzer import Analyzer

logger = logging.getLogger(__name__)


def setup_scheduler(
    analyzer: Analyzer, interval_minutes: int, max_repos: int
) -> AsyncIOScheduler:
    scheduler = AsyncIOScheduler()

    # Fire the very first scan 5 seconds after startup so the app is fully
    # initialised and can serve health-checks while the scan runs.
    first_run = datetime.now(timezone.utc) + timedelta(seconds=5)
    scheduler.add_job(
        _safe_scan,
        trigger=DateTrigger(run_date=first_run),
        args=[analyzer, max_repos],
        id="poc_scan_initial",
        name="PoC Hunter initial scan",
        misfire_grace_time=300,
        max_instances=1,
    )

    # Recurring scan on the configured interval
    scheduler.add_job(
        _safe_scan,
        trigger=IntervalTrigger(minutes=interval_minutes),
        args=[analyzer, max_repos],
        id="poc_scan_recurring",
        name="PoC Hunter recurring scan",
        replace_existing=True,
        misfire_grace_time=300,
        max_instances=1,
    )

    logger.info(
        "Scheduler configured: initial scan at %s, then every %d minutes",
        first_run.isoformat(),
        interval_minutes,
    )
    return scheduler


async def _safe_scan(analyzer: Analyzer, max_repos: int) -> None:
    """Wrapper that catches all exceptions so the scheduler never crashes."""
    try:
        result = await analyzer.run_scan(max_repos=max_repos)
        logger.info(
            "Scheduled scan complete: run #%d, %d scanned, %d flagged",
            result.run_id,
            result.repos_scanned,
            result.repos_flagged,
        )
    except Exception:
        logger.exception("Scheduled scan raised an exception")
