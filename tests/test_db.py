"""Tests for the database layer."""
import pytest
import pytest_asyncio


@pytest.mark.asyncio
async def test_scan_run_lifecycle(db):
    run_id = await db.insert_scan_run()
    assert run_id is not None

    await db.update_scan_run(run_id, status="completed", repos_scanned=10, repos_flagged=2)
    latest = await db.get_latest_scan_run()
    assert latest["id"] == run_id
    assert latest["status"] == "completed"
    assert latest["repos_scanned"] == 10


@pytest.mark.asyncio
async def test_insert_and_get_finding(db):
    run_id = await db.insert_scan_run()
    fid = await db.insert_finding(run_id, {
        "repo_full_name": "attacker/CVE-2025-1234",
        "repo_url": "https://github.com/attacker/CVE-2025-1234",
        "repo_size_kb": 42,
        "default_branch": "main",
        "scan_status": "suspicious",
    })
    assert fid is not None

    detail = await db.get_finding_detail(fid)
    assert detail is not None
    assert detail["repo_full_name"] == "attacker/CVE-2025-1234"
    assert detail["scan_status"] == "suspicious"


@pytest.mark.asyncio
async def test_insert_match(db):
    run_id = await db.insert_scan_run()
    fid = await db.insert_finding(run_id, {
        "repo_full_name": "x/repo",
        "repo_url": "https://github.com/x/repo",
        "repo_size_kb": 5,
        "default_branch": "main",
        "scan_status": "suspicious",
    })
    await db.insert_match(fid, {
        "rule_name": "Python_Reverse_Shell",
        "rule_category": "Reverse Shell",
        "rule_severity": "Critical",
        "file_path": "exploit.py",
        "matched_strings": [{"identifier": "$sock", "offset": 10, "length": 5, "data_preview": "sock."}],
        "code_snippet": "import socket",
        "snippet_start_line": 1,
    })
    detail = await db.get_finding_detail(fid)
    assert len(detail["matches"]) == 1
    assert detail["matches"][0]["rule_name"] == "Python_Reverse_Shell"


@pytest.mark.asyncio
async def test_vote_upsert_and_toggle(db):
    run_id = await db.insert_scan_run()
    fid = await db.insert_finding(run_id, {
        "repo_full_name": "x/y", "repo_url": "https://github.com/x/y",
        "repo_size_kb": 1, "default_branch": "main", "scan_status": "clean",
    })

    score = await db.upsert_vote(fid, "user1", 1)
    assert score == 1

    score = await db.upsert_vote(fid, "user2", 1)
    assert score == 2

    # Toggle: same vote removes it
    score = await db.upsert_vote(fid, "user1", 1)
    assert score == 1


@pytest.mark.asyncio
async def test_comment_crud(db):
    run_id = await db.insert_scan_run()
    fid = await db.insert_finding(run_id, {
        "repo_full_name": "x/y", "repo_url": "https://github.com/x/y",
        "repo_size_kb": 1, "default_branch": "main", "scan_status": "clean",
    })

    comment = await db.insert_comment(fid, "researcher1", "https://avatar.url", "Confirmed malicious!")
    assert comment["github_user"] == "researcher1"
    assert comment["body"] == "Confirmed malicious!"

    # Delete by owner
    deleted = await db.delete_comment(comment["id"], "researcher1")
    assert deleted is True

    # Delete by wrong user
    comment2 = await db.insert_comment(fid, "user2", "", "Another comment")
    deleted = await db.delete_comment(comment2["id"], "wrong_user")
    assert deleted is False


@pytest.mark.asyncio
async def test_get_findings_filter(db):
    run_id = await db.insert_scan_run()
    for status in ["suspicious", "suspicious", "clean"]:
        await db.insert_finding(run_id, {
            "repo_full_name": f"x/{status}_{id(status)}",
            "repo_url": "https://github.com/x/r",
            "repo_size_kb": 1, "default_branch": "main", "scan_status": status,
        })

    result = await db.get_findings({"status": "suspicious"})
    assert result["total"] >= 2

    result_all = await db.get_findings({"status": "all"})
    assert result_all["total"] >= result["total"]


@pytest.mark.asyncio
async def test_is_recently_scanned(db):
    run_id = await db.insert_scan_run()
    await db.insert_finding(run_id, {
        "repo_full_name": "fresh/repo",
        "repo_url": "https://github.com/fresh/repo",
        "repo_size_kb": 1, "default_branch": "main", "scan_status": "clean",
    })
    assert await db.is_recently_scanned("fresh/repo", hours=24) is True
    assert await db.is_recently_scanned("never/scanned", hours=24) is False


@pytest.mark.asyncio
async def test_get_stats(db):
    stats = await db.get_stats()
    assert "total_scanned" in stats
    assert "total_flagged" in stats
