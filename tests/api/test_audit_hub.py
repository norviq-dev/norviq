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


def _event(agent_class: str, framework: str) -> ToolCallEvent:
    return ToolCallEvent(
        tool_name="search_kb",
        tool_params={"query": "hello"},
        agent_identity=AgentIdentity(
            spiffe_id=f"spiffe://norviq/ns/default/sa/{agent_class}",
            namespace="default",
            agent_class=agent_class,
        ),
        framework=framework,
        session_id="s1",
    )


_ALLOW = PolicyDecision(decision="allow", rule_id="default_allow", reason="ok", trust_score=0.9, latency_ms=2.0)


def test_audit_record_carries_the_real_traffic_verdict() -> None:
    """The live-tail payload must let the client apply the SAME real-traffic-only predicate the server
    applies to fetched rows.

    It carried neither `framework` nor any synthetic verdict, so the Audit Log's live filter tested
    `r.framework === "redteam"` against `undefined`: with "Real traffic only" ON, red-team and probe rows
    streamed into the tail regardless while the fetched rows below them were correctly excluded. The
    verdict is computed server-side by the shared classifier so the class-prefix list is never forked
    into TypeScript.
    """
    real = audit_record(_event("customer-support", "langchain"), _ALLOW)
    assert real["framework"] == "langchain"  # also backs the Source column, blank on live rows before
    assert real["non_real"] is False

    # (1) red-team framework — the half the client THOUGHT it was testing
    assert audit_record(_event("customer-support", "redteam"), _ALLOW)["non_real"] is True
    # (2) synthetic/probe agent class — the half it never tested at all
    assert audit_record(_event("probe-alpha", "langchain"), _ALLOW)["non_real"] is True
    assert audit_record(_event("policy-tester", "langchain"), _ALLOW)["non_real"] is True
