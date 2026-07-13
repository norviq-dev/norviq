# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""DRY-RUN correctness: the candidate rego is REPLAYED against recent real traffic and the response
leads with the DECISION FLIPS (currently-allowed calls it would newly block) — not the old 'global
historical block rate' which reported what the LIVE policy already did, independent of the candidate."""

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from norviq.api.routers.policies import PolicyCreate, _opa_input_from_record, _replay_recent


def _rec(tool_name, decision, agent_class="report-gen", ns="analytics", framework="", payload=None):
    return SimpleNamespace(
        tool_name=tool_name, decision=decision, agent_class=agent_class, namespace=ns,
        agent_id=f"spiffe://norviq/ns/{ns}/sa/{agent_class}", trust_score=0.8, session_id="s1",
        framework=framework, payload=payload, timestamp_utc=datetime.now(timezone.utc),
    )


class _FakeScalarResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _FakeSession:
    """Minimal async session stub: returns the seeded rows for the replay query."""

    def __init__(self, rows):
        self._rows = rows

    async def scalars(self, _q):
        return _FakeScalarResult(self._rows)


class _FakeEvaluator:
    """Decides by a tool_name → decision map, mirroring a candidate rego that blocks specific tools."""

    def __init__(self, decide):
        self._decide = decide
        self.calls = 0

    async def _evaluate_opa(self, key, ns, cls, opa_input, rego):
        self.calls += 1
        d = self._decide(opa_input["tool_name"])
        return {"decision": d, "rule_id": f"rule_{d}", "reason": ""}


class TestOpaInputFromRecord:
    def test_reconstructs_input_from_record(self):
        rec = _rec("delete_kb", "allow", payload={"masked_params": {"id": "***"}})
        got = _opa_input_from_record(rec)
        assert got["tool_name"] == "delete_kb"
        assert got["agent"]["agent_class"] == "report-gen"
        assert got["agent"]["namespace"] == "analytics"
        assert got["tool_params"] == {"id": "***"}
        assert got["trust_category"] == "high"

    def test_missing_payload_yields_empty_params(self):
        got = _opa_input_from_record(_rec("search_kb", "allow", payload=None))
        assert got["tool_params"] == {}


@pytest.mark.asyncio
class TestReplay:
    async def test_counts_decision_flips(self):
        # candidate blocks index_kb + delete_kb; historically both were ALLOWED → 2 newly-blocked flips.
        rows = [
            _rec("search_kb", "allow"),  # stays allowed
            _rec("index_kb", "allow"),   # flip → block
            _rec("delete_kb", "allow"),  # flip → block
        ]
        ev = _FakeEvaluator(lambda t: "block" if t in ("index_kb", "delete_kb") else "allow")
        body = PolicyCreate(namespace="analytics", agent_class="report-gen", rego_source="package x")
        out = await _replay_recent(ev, _FakeSession(rows), body, datetime.now(timezone.utc))
        assert out["total_records_checked"] == 3
        assert out["would_block"] == 2
        assert out["would_allow"] == 1
        assert out["newly_blocked"] == 2  # THE signal
        assert {s["tool_name"] for s in out["newly_blocked_samples"]} == {"index_kb", "delete_kb"}
        assert out["block_rate_pct"] == round(2 / 3 * 100, 2)

    async def test_already_blocked_call_is_not_a_new_flip(self):
        # a call that was ALREADY blocked and stays blocked is not a NEW restriction.
        rows = [_rec("delete_kb", "block"), _rec("search_kb", "allow")]
        ev = _FakeEvaluator(lambda t: "block" if t == "delete_kb" else "allow")
        body = PolicyCreate(namespace="analytics", agent_class="report-gen", rego_source="package x")
        out = await _replay_recent(ev, _FakeSession(rows), body, datetime.now(timezone.utc))
        assert out["would_block"] == 1
        assert out["newly_blocked"] == 0  # delete_kb was already blocked — no new impact

    async def test_monitor_audit_call_flipping_to_block_counts_as_newly_blocked(self):
        # a call logged as 'audit' (monitor would-block) that the candidate blocks IS a new restriction.
        rows = [_rec("index_kb", "audit")]
        ev = _FakeEvaluator(lambda t: "block")
        body = PolicyCreate(namespace="analytics", agent_class="report-gen", rego_source="package x")
        out = await _replay_recent(ev, _FakeSession(rows), body, datetime.now(timezone.utc))
        assert out["newly_blocked"] == 1

    async def test_no_traffic_yields_zero_checked(self):
        ev = _FakeEvaluator(lambda t: "allow")
        body = PolicyCreate(namespace="analytics", agent_class="quiet-class", rego_source="package x")
        out = await _replay_recent(ev, _FakeSession([]), body, datetime.now(timezone.utc))
        assert out["total_records_checked"] == 0
        assert out["newly_blocked"] == 0
