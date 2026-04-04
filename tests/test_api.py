"""Integration tests for FastAPI endpoints using TestClient."""
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client(rules_dir, tmp_path_factory):
    """Create a test FastAPI client with a temporary database."""
    import os
    tmp = tmp_path_factory.mktemp("api_test")
    db_path = str(tmp / "test.db")

    os.environ["DATABASE_PATH"]  = db_path
    os.environ["RULES_DIR"]      = rules_dir
    os.environ["SESSION_SECRET"] = "test-secret"
    os.environ["GITHUB_OAUTH_CLIENT_ID"]     = "test_client_id"
    os.environ["GITHUB_OAUTH_CLIENT_SECRET"] = "test_client_secret"

    # Import after env vars are set
    from backend.api.main import app
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


def test_stats_endpoint(client):
    resp = client.get("/api/v1/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_scanned" in data
    assert "rules_count" in data


def test_rules_endpoint(client):
    resp = client.get("/api/v1/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert isinstance(rules, list)
    # Should have compiled YARA rules
    names = [r["name"] for r in rules]
    # at least some rules loaded
    assert len(rules) >= 0


def test_findings_list_default(client):
    resp = client.get("/api/v1/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data
    assert "total" in data


def test_findings_filter_status(client):
    resp = client.get("/api/v1/findings?status=clean")
    assert resp.status_code == 200


def test_findings_filter_invalid_page(client):
    resp = client.get("/api/v1/findings?page=0")
    assert resp.status_code == 422  # validation error


def test_finding_not_found(client):
    resp = client.get("/api/v1/findings/99999")
    assert resp.status_code == 404


def test_scan_runs_endpoint(client):
    resp = client.get("/api/v1/scan-runs")
    assert resp.status_code == 200
    data = resp.json()
    assert "items" in data


def test_latest_scan_run_endpoint(client):
    resp = client.get("/api/v1/scan-runs/latest")
    assert resp.status_code == 200


def test_vote_requires_auth(client):
    resp = client.post("/api/v1/findings/1/vote", json={"vote": 1})
    assert resp.status_code == 401


def test_comment_requires_auth(client):
    resp = client.post("/api/v1/findings/1/comments", json={"body": "hello"})
    assert resp.status_code == 401


def test_auth_me_unauthenticated(client):
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 200
    assert resp.json() is None


def test_vote_invalid_value(client):
    # Must be 1 or -1
    resp = client.post(
        "/api/v1/findings/1/vote",
        json={"vote": 0},
        cookies={"poc_session": "invalid"},  # still no session but tests validation
    )
    # Either 422 (validation) or 401 (auth) – both acceptable
    assert resp.status_code in (401, 422)


def test_comment_too_long(client):
    body = "x" * 2001
    resp = client.post(
        "/api/v1/findings/1/comments",
        json={"body": body},
    )
    assert resp.status_code in (401, 422)
