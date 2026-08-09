# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""GET /policy-compliance — what is non-compliant, and with which control.

The endpoint answers one question: if I promote this control to Enforce, what breaks? So the
assertions are about the ways that number could be WRONG — counting red-team probes as customer
traffic, counting calls a control already blocks, splitting one control across its two would-block
prefixes, or rendering "nothing is non-compliant" when in fact nothing has happened at all.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings

NOW = datetime.now(timezone.utc)


def _row(rule_id: str, *, tool="get_order", cls="cmp-support", ns="chatbot-prod",
         framework="langgraph", decision="audit", minutes_ago=1):
    return SimpleNamespace(
        rule_id=rule_id, tool_name=tool, agent_class=cls, namespace=ns, framework=framework,
        decision=decision, timestamp_utc=NOW - timedelta(minutes=minutes_ago),
    )


class _FakeSession:
    def __init__(self, rows):
        self.rows = rows

    async def execute(self, _stmt):
        return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: self.rows))

    async def close(self):
        return None


def _client(rows):
    app = create_app()
    session = _FakeSession(rows)

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _h(role="admin", namespace="chatbot-prod"):
    token = jwt.encode(
        {"sub": "u", "role": role, "namespace": namespace, "exp": int(time.time()) + 3600},
        settings.api_secret_key, algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def _get(rows, query="?namespace=chatbot-prod&range=24h"):
    return _client(rows).get(f"/api/v1/policy-compliance{query}", headers=_h()).json()


def test_groups_would_block_rows_by_control() -> None:
    body = _get([
        _row("policy_audit_would_block:deny_shell_execution"),
        _row("policy_audit_would_block:deny_shell_execution", tool="get_customer"),
        _row("policy_audit_would_block:deny_sql_injection", tool="run_report"),
    ])
    by_id = {c["control_id"]: c for c in body["controls"]}
    assert by_id["deny_shell_execution"]["count"] == 2
    assert by_id["deny_sql_injection"]["count"] == 1
    # worst blast radius first — the control most in need of a decision
    assert body["controls"][0]["control_id"] == "deny_shell_execution"


def test_both_would_block_prefixes_fold_to_one_control() -> None:
    """They record WHY the block was softened — posture vs the policy's own mode — which is a
    debugging distinction, not a different control. Splitting them would show one control twice with
    a divided count, which is precisely the number this endpoint must get right."""
    body = _get([
        _row("policy_audit_would_block:pii_detection"),
        _row("monitor_would_block:pii_detection"),
    ])
    assert len(body["controls"]) == 1
    assert body["controls"][0]["control_id"] == "pii_detection"
    assert body["controls"][0]["count"] == 2


def test_a_doubly_prefixed_rule_id_still_resolves() -> None:
    """Reachable when a policy-audit softening is cached and posture is applied on the cache hit."""
    body = _get([_row("monitor_would_block:policy_audit_would_block:deny_shell_execution")])
    assert body["controls"][0]["control_id"] == "deny_shell_execution"


def test_rows_that_actually_blocked_are_not_counted() -> None:
    """A control that is already enforcing is not evidence about a PROSPECTIVE promotion — counting
    it would inflate the projected impact with calls it is already turning away."""
    body = _get([
        _row("deny_sql_injection", decision="block"),
        _row("policy_audit_would_block:deny_sql_injection"),
    ])
    assert body["controls"][0]["count"] == 1


def test_plain_allows_are_not_counted() -> None:
    body = _get([_row("default_allow", decision="allow"), _row("policy_audit_would_block:pii_detection")])
    assert len(body["controls"]) == 1
    assert body["controls"][0]["control_id"] == "pii_detection"


def test_redteam_and_probe_traffic_is_excluded() -> None:
    """A red-team probe tripping a control is not a customer workload about to break."""
    body = _get([
        _row("policy_audit_would_block:deny_shell_execution", framework="redteam"),
        _row("policy_audit_would_block:deny_shell_execution", cls="probe-scanner"),
        _row("policy_audit_would_block:deny_shell_execution", cls="cmp-support"),
    ])
    assert body["controls"][0]["count"] == 1
    assert body["excluded_synthetic"] == 2


def test_breaks_down_by_agent_class_and_tool() -> None:
    """12 hits across nine classes is a different decision from 4,000 across one."""
    body = _get([
        _row("policy_audit_would_block:deny_shell_execution", cls="cmp-support", tool="get_order"),
        _row("policy_audit_would_block:deny_shell_execution", cls="cmp-support", tool="get_order"),
        _row("policy_audit_would_block:deny_shell_execution", cls="cmp-finance", tool="get_invoice"),
    ])
    control = body["controls"][0]
    assert control["agent_classes"][0] == {"name": "cmp-support", "count": 2}
    assert {t["name"] for t in control["tools"]} == {"get_order", "get_invoice"}


def test_carries_samples_and_a_time_window() -> None:
    body = _get([
        _row("policy_audit_would_block:pii_detection", minutes_ago=60),
        _row("policy_audit_would_block:pii_detection", minutes_ago=1),
    ])
    control = body["controls"][0]
    assert control["first_seen"] < control["last_seen"]
    assert len(control["samples"]) == 2
    assert control["samples"][0]["tool_name"] == "get_order"


def test_samples_are_capped() -> None:
    body = _get([_row("policy_audit_would_block:pii_detection") for _ in range(40)])
    assert body["controls"][0]["count"] == 40
    assert len(body["controls"][0]["samples"]) == 5  # a summary, not a log export


def test_scanned_distinguishes_compliant_from_idle() -> None:
    """The number that makes an empty list readable.

    Zero non-compliant out of zero traffic means "nothing has happened here yet". Zero out of 40,000
    means "genuinely compliant". Without `scanned` the console cannot tell those apart, and would
    render an idle namespace as a clean bill of health.
    """
    idle = _get([])
    assert idle["controls"] == [] and idle["scanned"] == 0

    busy = _get([_row("default_allow", decision="allow") for _ in range(25)])
    assert busy["controls"] == [] and busy["scanned"] == 25
