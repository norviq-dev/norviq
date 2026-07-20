# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Per-agent tool-usage + trust-history aggregate real audit_log rows (no fabricated widgets).

Covers happy (counts/buckets), empty (no rows -> []), and auth. The greedy /agents/{spiffe_id:path}
GET must NOT swallow the /tool-usage and /trust-history suffixes."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings

AGENT = "spiffe://norviq/ns/default/sa/customer-support"


class _FakeSession:
    def __init__(self, rows: list[tuple]) -> None:
        self._rows = rows

    async def execute(self, _stmt):
        rows = list(self._rows)
        return SimpleNamespace(all=lambda: rows)

    async def close(self) -> None:
        return None


def _client(rows: list[tuple]) -> TestClient:
    app = create_app()

    async def _override():
        yield _FakeSession(rows)

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _token() -> str:
    return jwt.encode(
        {"sub": "u", "role": "admin", "exp": int(time.time()) + 3600},
        settings.api_secret_key,
        algorithm="HS256",
    )


def test_tool_usage_aggregates_counts() -> None:
    rows = [("execute_sql", "block"), ("execute_sql", "allow"), ("search_kb", "allow")]
    client = _client(rows)
    resp = client.get(f"/api/v1/agents/{AGENT}/tool-usage", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    body = resp.json()
    by_tool = {r["tool"]: r for r in body}
    # Each tool is tagged with its TOOL_RISK_MAP risk tier — "execute_sql" classifies as critical
    # (destruction/exec default, see classify_tool) — see norviq/api/routers/agents.py agent_tool_usage.
    assert by_tool["execute_sql"] == {"tool": "execute_sql", "count": 2, "blocked": 1, "risk": "critical"}
    assert by_tool["search_kb"]["count"] == 1
    assert body[0]["tool"] == "execute_sql"  # sorted by count desc


def test_tool_usage_empty() -> None:
    client = _client([])
    resp = client.get(f"/api/v1/agents/{AGENT}/tool-usage", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    assert resp.json() == []


def test_trust_history_buckets_by_day() -> None:
    d1 = datetime(2026, 6, 27, 10, tzinfo=timezone.utc)
    d2 = datetime(2026, 6, 28, 11, tzinfo=timezone.utc)
    rows = [(d1, "allow", 0.9), (d1, "block", 0.5), (d2, "allow", 0.8)]
    client = _client(rows)
    resp = client.get(f"/api/v1/agents/{AGENT}/trust-history", headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 200
    body = resp.json()
    assert [b["time"] for b in body] == ["2026-06-27", "2026-06-28"]
    assert body[0]["allow"] == 1 and body[0]["block"] == 1
    assert body[0]["trust_score"] == 0.7  # avg(0.9, 0.5)
    assert body[1]["allow"] == 1 and body[1]["block"] == 0


def test_agent_insights_require_auth() -> None:
    client = _client([])
    assert client.get(f"/api/v1/agents/{AGENT}/tool-usage").status_code in (401, 403)
    assert client.get(f"/api/v1/agents/{AGENT}/trust-history").status_code in (401, 403)
