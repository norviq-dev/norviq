# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The in-process AuditHub fans decisions out to /ws/audit subscribers."""

from __future__ import annotations

import pytest

from norviq.api.audit_hub import AuditHub, audit_record
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent


@pytest.mark.asyncio
async def test_hub_fans_out_then_stops_after_unsubscribe() -> None:
    hub = AuditHub()
    q1 = hub.subscribe()
    q2 = hub.subscribe()

    hub.publish({"namespace": "default", "tool_name": "x"})
    assert (await q1.get())["tool_name"] == "x"
    assert (await q2.get())["tool_name"] == "x"

    hub.unsubscribe(q1)
    hub.publish({"namespace": "default", "tool_name": "y"})
    assert q1.empty()  # unsubscribed → no further events
    assert (await q2.get())["tool_name"] == "y"


def test_audit_record_carries_decision_provenance() -> None:
    """The broadcast record must include the real decision + rule_id (not just a decision)."""
    event = ToolCallEvent(
        tool_name="execute_sql",
        tool_params={"query": "DROP TABLE users"},
        agent_identity=AgentIdentity(
            spiffe_id="spiffe://norviq/ns/default/sa/customer-support",
            namespace="default",
            agent_class="customer-support",
        ),
        session_id="s1",
    )
    decision = PolicyDecision(
        decision="block", rule_id="deny_sql_injection", reason="sql injection", trust_score=0.5, latency_ms=3.0
    )
    rec = audit_record(event, decision)
    assert rec["namespace"] == "default"
    assert rec["tool_name"] == "execute_sql"
    assert rec["decision"] == "block"
    assert rec["rule_id"] == "deny_sql_injection"
    assert rec["agent_class"] == "customer-support"
    assert rec["trust_score"] == 0.5
    assert rec["id"] == event.event_id
