# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The console's "is something wrong right now?" surface.

A governance product failing is not self-announcing: when the engine is unreachable the sidecars
quietly fail closed, every agent's tool calls stop working, and the operator's first signal is a user
complaining the bot "got dumber". With a fail-open posture it is quieter still — calls are forwarded
UNGOVERNED and nothing visibly changes.

The route reports only what it can prove from decisions the data plane actually recorded, and is
scoped like every other read so one tenant is never shown another tenant's incident.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app

_ADMIN = {"role": "admin", "namespace": "", "sub": "admin"}
_TENANT = {"role": "viewer", "namespace": "chatbot-prod", "sub": "tenant"}
_NOW = datetime(2026, 7, 26, 10, 0, tzinfo=timezone.utc)


class _Session:
    """Yields canned grouped rows, and records the compiled SQL so scoping can be asserted."""

    def __init__(self, rows: list) -> None:
        self.rows = rows
        self.statements: list[str] = []

    async def execute(self, stmt):
        self.statements.append(str(stmt))
        return SimpleNamespace(all=lambda: self.rows)

    async def close(self) -> None:
        return None


def _row(rule_id: str, n: int = 3, namespaces: list[str] | None = None):
    return SimpleNamespace(rule_id=rule_id, n=n, last_seen=_NOW, namespaces=namespaces or ["chatbot-prod"])


def _client(rows: list, user: dict | None = None) -> tuple[TestClient, _Session]:
    app = create_app()
    session = _Session(rows)
    app.dependency_overrides[get_current_user] = lambda: user or _ADMIN

    async def _get_session():
        yield session

    app.dependency_overrides[get_session] = _get_session
    return TestClient(app), session


def test_healthy_when_nothing_was_recorded() -> None:
    """No infra-attributed decisions in the window means no incident to report."""
    client, _ = _client([])
    body = client.get("/api/v1/system-health").json()
    assert body["status"] == "ok"
    assert body["issues"] == []


def test_engine_outage_is_reported_with_evidence() -> None:
    """The fail-closed case: agents are alive but every tool call is being refused."""
    client, _ = _client([_row("thin_proxy_fail_closed", n=42)])
    body = client.get("/api/v1/system-health").json()
    assert body["status"] == "degraded"
    issue = body["issues"][0]
    assert issue["id"] == "thin_proxy_fail_closed"
    assert issue["severity"] == "critical"
    assert issue["affected_calls"] == 42
    assert issue["namespaces"] == ["chatbot-prod"]
    assert issue["remediation"]  # actionable, not just an alarm


def test_fail_open_is_reported_as_ungoverned() -> None:
    """The quietest failure of all: nothing breaks and nothing is enforced. It must be named plainly."""
    client, _ = _client([_row("thin_proxy_fail_open")])
    issue = client.get("/api/v1/system-health").json()["issues"][0]
    assert "UNGOVERNED" in issue["title"]
    assert issue["severity"] == "critical"


def test_rejected_sidecars_are_not_described_as_an_outage() -> None:
    """A 401/403 is a credential fault. Calling it an outage sends operators to healthy engine pods."""
    client, _ = _client([_row("engine_rejected_request")])
    issue = client.get("/api/v1/system-health").json()["issues"][0]
    assert "token" in issue["remediation"].lower()
    assert "unreachable" not in issue["detail"].lower()


def test_a_tenant_only_sees_their_own_namespace() -> None:
    """Scoped like every other read — one tenant must never see another tenant's incident."""
    client, session = _client([_row("thin_proxy_fail_closed")], user=_TENANT)
    assert client.get("/api/v1/system-health").status_code == 200
    assert "namespace" in session.statements[0]


def test_admin_without_a_namespace_claim_sees_the_whole_deployment() -> None:
    """The operator running the cluster needs the unscoped view."""
    client, session = _client([_row("thin_proxy_fail_closed")], user=_ADMIN)
    assert client.get("/api/v1/system-health").status_code == 200
    # No equality filter on namespace was added for the unscoped admin.
    assert "audit_log.namespace =" not in session.statements[0]


def test_only_infrastructure_rule_ids_qualify_as_incidents() -> None:
    """A policy doing its job is not an outage. If a normal block could raise the banner, operators
    would learn to ignore it — and then miss the real enforcement outage it exists for.

    Asserted against the constant rather than the compiled SQL: SQLAlchemy renders an IN clause as a
    post-compile placeholder, so string-matching the statement would pass no matter what it filtered."""
    from norviq.api.routers.system_health import _INFRA_RULE_IDS

    assert set(_INFRA_RULE_IDS) == {
        "thin_proxy_fail_closed",
        "thin_proxy_fail_open",
        "engine_rejected_request",
    }
    # Every entry must carry a severity, a title, a detail and a remediation — an alarm with no
    # next step is just noise on a dashboard.
    for rule_id, spec in _INFRA_RULE_IDS.items():
        assert len(spec) == 4, rule_id
        assert all(str(part).strip() for part in spec), rule_id


def test_the_infra_rule_ids_are_the_ones_the_data_plane_actually_writes() -> None:
    """The banner is only as honest as this coupling: if the sidecar/SDK renames a fallback rule_id,
    this route silently stops reporting outages and the console goes quiet during an incident."""
    from norviq.api.routers.system_health import _INFRA_RULE_IDS
    from norviq.sidecar import remote_evaluator

    source = (
        remote_evaluator.__file__ and open(remote_evaluator.__file__, encoding="utf-8").read()
    ) or ""
    for rule_id in ("thin_proxy_fail_closed", "thin_proxy_fail_open"):
        assert rule_id in _INFRA_RULE_IDS
        assert f'rule_id="{rule_id}"' in source, f"{rule_id} is no longer written by the sidecar"
