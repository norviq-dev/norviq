# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""C4: GET /api/v1/audit/export streams audit rows as NDJSON/CSV, authenticated + namespace-scoped."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings


def _row(namespace: str = "default", tool: str = "search_kb", decision: str = "allow") -> SimpleNamespace:
    """Build a fake AuditLogEntry row covering every field the serializer reads."""
    return SimpleNamespace(
        id=uuid.uuid4(),
        event_id=uuid.uuid4(),
        tool_name=tool,
        decision=decision,
        agent_id="spiffe://norviq/ns/default/sa/customer-support",
        agent_class="customer-support",
        namespace=namespace,
        rule_id="default_allow",
        reason="ok",
        session_id="sess-1",
        trust_score=0.8,
        latency_ms=4.2,
        timestamp_utc=datetime.now(timezone.utc),
        # F-19: masked_params provenance the export serializer reads directly (no getattr fallback) —
        # see norviq/api/routers/audit.py _export_dict.
        payload={"masked_params": {}},
    )


class _FakeSession:
    def __init__(self, rows: list[SimpleNamespace]) -> None:
        self.rows = rows

    async def execute(self, stmt):
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: self.rows))

    async def close(self) -> None:
        return None


def _client(rows: list[SimpleNamespace]) -> TestClient:
    app = create_app()

    async def _override():
        yield _FakeSession(rows)

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _token(role: str = "admin", namespace: str = "default") -> dict[str, str]:
    tok = jwt.encode({"sub": "t", "role": role, "namespace": namespace}, settings.api_secret_key, algorithm="HS256")
    return {"Authorization": f"Bearer {tok}"}


def test_export_ndjson_streams_rows() -> None:
    """NDJSON export returns one JSON object per audit row with the right content type."""
    client = _client([_row(decision="allow"), _row(decision="block")])
    try:
        resp = client.get("/api/v1/audit/export?format=ndjson", headers=_token())
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/x-ndjson")
        lines = [line for line in resp.text.splitlines() if line]
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["tool_name"] == "search_kb" and "decision" in first and "agent_class" in first
    finally:
        client.close()


def test_export_csv_has_header_and_rows() -> None:
    """CSV export emits a header row plus one line per record."""
    client = _client([_row(), _row()])
    try:
        resp = client.get("/api/v1/audit/export?format=csv", headers=_token())
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        rows = [line for line in resp.text.splitlines() if line]
        assert rows[0].startswith("id,event_id,tool_name")
        assert len(rows) == 3  # header + 2 records
    finally:
        client.close()


def test_export_requires_auth() -> None:
    """Without a token the export endpoint is rejected (401)."""
    client = _client([_row()])
    try:
        assert client.get("/api/v1/audit/export").status_code == 401
    finally:
        client.close()


def test_export_viewer_cannot_cross_namespace() -> None:
    """A viewer scoped to 'default' requesting another namespace is forbidden (403)."""
    client = _client([_row()])
    try:
        resp = client.get("/api/v1/audit/export?namespace=payments", headers=_token(role="viewer"))
        assert resp.status_code == 403
    finally:
        client.close()
