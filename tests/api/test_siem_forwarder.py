# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""C4: SIEM AuditForwarder pushes audit rows to a webhook when enabled; no-op when disabled."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from types import SimpleNamespace

import httpx
import pytest

from norviq.api.siem import AuditForwarder
from norviq.config import settings


def _row() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        event_id=uuid.uuid4(),
        tool_name="execute_sql",
        decision="block",
        agent_id="spiffe://norviq/ns/default/sa/customer-support",
        agent_class="customer-support",
        namespace="default",
        rule_id="deny_sql_injection",
        reason="blocked",
        session_id="s1",
        trust_score=0.4,
        latency_ms=3.0,
        timestamp_utc=datetime.now(timezone.utc),
    )


class _FakeSession:
    def __init__(self, rows: list[SimpleNamespace]) -> None:
        self.rows = rows

    async def execute(self, stmt):
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: self.rows))

    async def aclose(self) -> None:
        return None


def _session_factory(rows: list[SimpleNamespace]):
    async def _gen():
        yield _FakeSession(rows)

    return _gen


@pytest.mark.asyncio
async def test_forward_once_posts_rows_when_enabled(monkeypatch) -> None:
    """forward_once() POSTs the queued audit rows as NDJSON to the configured webhook."""
    monkeypatch.setattr(settings, "siem_enabled", True)
    monkeypatch.setattr(settings, "siem_webhook_url", "http://siem.local/ingest")
    captured: dict[str, str] = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["body"] = request.content.decode("utf-8")
        return httpx.Response(200)

    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    forwarder = AuditForwarder(session_factory=_session_factory([_row(), _row()]), client=client)
    try:
        count = await forwarder.forward_once()
        assert count == 2
        assert captured["url"] == "http://siem.local/ingest"
        assert len([ln for ln in captured["body"].splitlines() if ln]) == 2
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_start_is_noop_when_disabled(monkeypatch) -> None:
    """With siem disabled, start() must not launch a task or require a webhook URL."""
    monkeypatch.setattr(settings, "siem_enabled", False)
    forwarder = AuditForwarder(session_factory=_session_factory([_row()]))
    await forwarder.start()
    assert forwarder._task is None
    await forwarder.stop()


@pytest.mark.asyncio
async def test_forward_once_noop_when_no_rows(monkeypatch) -> None:
    """No new rows -> no POST, returns 0."""
    monkeypatch.setattr(settings, "siem_enabled", True)
    monkeypatch.setattr(settings, "siem_webhook_url", "http://siem.local/ingest")

    def _handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - must not be called
        raise AssertionError("should not POST when there are no rows")

    client = httpx.AsyncClient(transport=httpx.MockTransport(_handler))
    forwarder = AuditForwarder(session_factory=_session_factory([]), client=client)
    try:
        assert await forwarder.forward_once() == 0
    finally:
        await client.aclose()
