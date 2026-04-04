"""Shared pytest fixtures."""
import asyncio
import os
from pathlib import Path

import pytest
import pytest_asyncio

FIXTURES_DIR = Path(__file__).parent / "fixtures"
RULES_DIR    = Path(__file__).parent.parent / "Rules"


@pytest.fixture(scope="session")
def rules_dir() -> str:
    return str(RULES_DIR)


@pytest.fixture(scope="session")
def fixtures_dir() -> str:
    return str(FIXTURES_DIR)


@pytest.fixture(scope="session")
def event_loop_policy():
    return asyncio.DefaultEventLoopPolicy()


@pytest_asyncio.fixture
async def db(tmp_path):
    """In-memory SQLite database for tests."""
    import aiosqlite
    from backend.db.database import Database

    db_path = str(tmp_path / "test.db")
    d = Database(db_path)
    await d.connect()
    await d.init_schema()
    yield d
    await d.close()
