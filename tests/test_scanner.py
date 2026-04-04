"""Unit tests for scanner modules."""
import asyncio
import io
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

from backend.scanner.models import RepoInfo
from backend.scanner.snippet import extract_snippet, _byte_offset_to_line


# ---- snippet.py ---- #

def test_byte_offset_to_line_first_line():
    raw = b"hello\nworld\n"
    assert _byte_offset_to_line(raw, 0) == 1
    assert _byte_offset_to_line(raw, 4) == 1


def test_byte_offset_to_line_second_line():
    raw = b"hello\nworld\n"
    assert _byte_offset_to_line(raw, 6) == 2


def test_extract_snippet_returns_code(tmp_path):
    f = tmp_path / "sample.py"
    code = "\n".join(f"line_{i}" for i in range(30))
    f.write_text(code)
    result = extract_snippet(str(f), byte_offset=0, match_length=6)
    assert result.code != ""
    assert result.start_line >= 1


def test_extract_snippet_binary_file(tmp_path):
    f = tmp_path / "binary.bin"
    f.write_bytes(b"\x00\x01\x02\x03" * 100)
    result = extract_snippet(str(f), byte_offset=0, match_length=4)
    assert "binary file" in result.code.lower()


def test_extract_snippet_missing_file():
    result = extract_snippet("/nonexistent/file.py", byte_offset=0, match_length=10)
    assert result.code == ""


# ---- yara_engine.py ---- #

def test_yara_engine_invalid_dir():
    from backend.scanner.yara_engine import YaraEngine
    with pytest.raises(ValueError, match="not found"):
        YaraEngine("/does/not/exist")


def test_yara_engine_compiles(rules_dir):
    from backend.scanner.yara_engine import YaraEngine
    engine = YaraEngine(rules_dir)
    assert engine.rule_count > 0


def test_yara_engine_scan_empty_file(rules_dir, tmp_path):
    from backend.scanner.yara_engine import YaraEngine
    engine = YaraEngine(rules_dir)
    f = tmp_path / "empty.py"
    f.write_text("")
    results = engine.scan_file(str(f))
    assert results == []


# ---- RepoInfo model ---- #

def test_repo_info_defaults():
    r = RepoInfo(full_name="user/repo", html_url="https://github.com/user/repo",
                 default_branch="main", size=50)
    assert r.stargazers_count == 0
    assert r.description is None


# ---- github_client.py (mocked) ---- #

@pytest.mark.asyncio
async def test_search_returns_repos():
    from backend.scanner.github_client import GitHubClient

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "items": [
            {
                "full_name": "attacker/CVE-2025-1234",
                "html_url": "https://github.com/attacker/CVE-2025-1234",
                "default_branch": "main",
                "size": 10,
                "description": None,
                "stargazers_count": 0,
                "created_at": None,
                "updated_at": None,
            }
        ]
    }

    with patch("backend.scanner.github_client.GitHubClient._search_page", new_callable=AsyncMock) as mock_search:
        mock_search.return_value = mock_resp.json.return_value
        client = GitHubClient()
        repos = []
        async for repo in client.search_cve_repos(max_repos=1):
            repos.append(repo)
        await client.close()

    assert len(repos) == 1
    assert repos[0].full_name == "attacker/CVE-2025-1234"


@pytest.mark.asyncio
async def test_download_returns_none_on_404():
    from backend.scanner.github_client import GitHubClient
    import httpx

    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with patch.object(GitHubClient, "_client") as mc:
        mc.get = AsyncMock(return_value=mock_resp)
        client = GitHubClient()
        repo = RepoInfo(full_name="x/y", html_url="https://github.com/x/y", default_branch="main", size=10)
        result = await client.download_repo_zip(repo)
    assert result is None
