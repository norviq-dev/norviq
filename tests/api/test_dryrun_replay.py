# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""DRY-RUN correctness: the candidate rego is REPLAYED against recent real traffic and the response
leads with the DECISION FLIPS (currently-allowed calls it would newly block) — not the old 'global
historical block rate' which reported what the LIVE policy already did, independent of the candidate."""

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from norviq.api.routers.policies import PolicyCreate, _opa_input_from_record, _replay_recent
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.intent.dryrun import opa_subprocess_evaluator


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


# A candidate that passes `validate_policy_create` (declared default + a real block resolver), so the
# route-level tests below exercise the REPLAY path rather than dying in write-time validation.
_VALID_REGO = """package norviq.policy

default decision = "allow"

decision = "block" {
    input.tool_name == "delete_kb"
}

rule_id = "deny_delete_kb" {
    input.tool_name == "delete_kb"
}

reason = "delete_kb is not granted" {
    input.tool_name == "delete_kb"
}
"""


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


@pytest.mark.asyncio
class TestCheckedCountsOnlyWhatWasReplayed:
    """`total_records_checked` is the denominator the console prints ("Replayed N recent real calls"),
    the one its `replayUnmeasured` guard tests against 0, and the one the route's recommendation divides
    by. A row that was FETCHED but never evaluated was not measured, so counting it there manufactures
    an all-clear ("safe to deploy") out of a replay that examined nothing."""

    async def test_synthetic_only_window_reports_zero_checked_not_the_fetched_count(self):
        # A class-less (namespace-tier) policy replays the WHOLE namespace — exactly where another
        # class's Policy-Tester sessions land. Every row is skipped; NOTHING was simulated.
        rows = [_rec("search_kb", "allow", agent_class=f"policy-tester-{i}") for i in range(120)]
        ev = _FakeEvaluator(lambda t: "block")
        body = PolicyCreate(namespace="analytics", agent_class="", rego_source="package x")
        out = await _replay_recent(ev, _FakeSession(rows), body, datetime.now(timezone.utc))
        assert ev.calls == 0, "no record was evaluated"
        assert out["total_records_checked"] == 0  # was 120 — an all-clear over zero evaluations
        assert out["records_fetched"] == 120
        assert out["synthetic_skipped"] == 120
        assert out["block_rate_pct"] == 0

    async def test_block_rate_denominator_excludes_skipped_rows(self):
        # 100 skipped Policy-Tester rows + 20 real rows the candidate blocks. The true impact is
        # 20 of 20 (100%); counting the skipped rows reported 20 of 120 (16.7%) — a 6x understatement.
        rows = [_rec("search_kb", "allow", agent_class=f"policy-tester-{i}") for i in range(100)]
        rows += [_rec("delete_kb", "allow") for _ in range(20)]
        ev = _FakeEvaluator(lambda t: "block" if t == "delete_kb" else "allow")
        body = PolicyCreate(namespace="analytics", agent_class="", rego_source="package x")
        out = await _replay_recent(ev, _FakeSession(rows), body, datetime.now(timezone.utc))
        assert out["total_records_checked"] == 20
        assert out["newly_blocked"] == 20
        assert out["block_rate_pct"] == 100.0

    async def test_evaluator_failures_are_counted_and_never_read_as_clean(self):
        # OPA is down: every record raises. "The evaluator answered for nothing" must not be spelled
        # the same way as "the candidate blocks nothing".
        class _Exploding(_FakeEvaluator):
            async def _evaluate_opa(self, *a, **k):
                self.calls += 1
                raise RuntimeError("opa unreachable")

        rows = [_rec("delete_kb", "allow") for _ in range(10)]
        ev = _Exploding(lambda t: "allow")
        body = PolicyCreate(namespace="analytics", agent_class="report-gen", rego_source="package x")
        out = await _replay_recent(ev, _FakeSession(rows), body, datetime.now(timezone.utc))
        assert ev.calls == 10
        assert out["total_records_checked"] == 0  # was 10 → "safe to deploy"
        assert out["eval_errors"] == 10
        assert out["records_fetched"] == 10

    async def test_partial_evaluator_failure_is_visible_not_averaged_away(self):
        rows = [_rec("delete_kb", "allow"), _rec("boom", "allow"), _rec("search_kb", "allow")]

        class _HalfExploding(_FakeEvaluator):
            async def _evaluate_opa(self, key, ns, cls, opa_input, rego):
                if opa_input["tool_name"] == "boom":
                    raise RuntimeError("opa hiccup")
                return await _FakeEvaluator._evaluate_opa(self, key, ns, cls, opa_input, rego)

        ev = _HalfExploding(lambda t: "block" if t == "delete_kb" else "allow")
        body = PolicyCreate(namespace="analytics", agent_class="report-gen", rego_source="package x")
        out = await _replay_recent(ev, _FakeSession(rows), body, datetime.now(timezone.utc))
        assert out["total_records_checked"] == 2
        assert out["eval_errors"] == 1
        assert out["records_fetched"] == 3
        assert out["newly_blocked"] == 1


@pytest.mark.asyncio
class TestRecommendationCannotClearAnUnmeasuredReplay:
    """The route's headline sentence is what the operator reads before clicking "Save & enforce"
    (canSave opens on `valid === true`). It must never say "safe to deploy" off a replay that
    evaluated nothing."""

    @staticmethod
    async def _run(rows, decide, *, agent_class="", exploding=False):
        from types import SimpleNamespace as NS

        from norviq.api.routers.policies import dry_run_policy

        class _Ev(_FakeEvaluator):
            async def _evaluate_opa(self, key, ns, cls, opa_input, rego):
                # `_validate_rego` probes with a synthetic "search_kb" sample first; it must compile.
                if str(key).startswith("dryrun:") and opa_input.get("session_id") == "dry-run" and not rows:
                    return {"decision": "allow", "rule_id": "ok", "reason": ""}
                if exploding and opa_input.get("session_id") != "dry-run":
                    raise RuntimeError("opa unreachable")
                self.calls += 1
                return {"decision": decide(opa_input["tool_name"]), "rule_id": "r", "reason": ""}

        ev = _Ev(decide)
        request = NS(app=NS(state=NS(evaluator=ev)))
        body = PolicyCreate(namespace="analytics", agent_class=agent_class, rego_source=_VALID_REGO)
        return await dry_run_policy(
            body, request, session=_FakeSession(rows), user={"role": "admin", "sub": "t"}, _target=None
        )

    async def test_all_synthetic_replay_says_cannot_simulate_not_safe_to_deploy(self):
        rows = [_rec("search_kb", "allow", agent_class=f"policy-tester-{i}") for i in range(120)]
        out = await self._run(rows, lambda t: "block")
        assert out["total_records_checked"] == 0
        assert "safe to deploy" not in out["recommendation"]
        assert "cannot simulate impact" in out["recommendation"]

    async def test_total_evaluator_failure_names_the_engine_not_absent_traffic(self):
        rows = [_rec("delete_kb", "allow") for _ in range(10)]
        out = await self._run(rows, lambda t: "allow", agent_class="report-gen", exploding=True)
        assert out["total_records_checked"] == 0
        assert out["eval_errors"] == 10
        assert "safe to deploy" not in out["recommendation"]
        assert "evaluator failed" in out["recommendation"]


_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "builder_composition" / "allowlist_refined_grants_class.json"
needs_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="needs the opa binary")


def _allowlist_rego() -> str:
    """A real Visual Builder allowlist (pinned to builderCompile.ts by builderCompositionFixtures.test.ts):
    read-only refinement on; grants get_order (id ~ ^[0-9]+$), update_order (status in open/closed),
    list_orders (limit <= 100 AND call_depth <= 2), query_run and lookup_widget (id required AND
    verb == read)."""
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))["rego"]


class _OpaReplay:
    """The candidate evaluated by the real opa, over the input document the engine itself builds."""

    def __init__(self):
        self._engine = OPAEvaluator.__new__(OPAEvaluator)  # only the pure input builders are used
        self.keys: list[str] = []

    def _build_input(self, event, trust):
        return self._engine._build_input(event, trust)

    async def _evaluate_opa(self, key, ns, cls, opa_input, rego):
        self.keys.append(key)
        return opa_subprocess_evaluator(rego, opa_input)


def _support(tool, payload):
    return _rec(tool, "allow", agent_class="support-agent", ns="default", payload=payload)


@pytest.mark.asyncio
class TestArgumentRefusalsWithoutValues:
    """A record kept without argument values replays with no arguments, so an argument constraint
    refuses it whatever the real call carried. Such a refusal is `cannot_evaluate`, not newly blocked.

    The rule id the builder gives it, `intent_constraint_violation`, is not enough to say so. The builder
    emits it whether or not a refinement failed too, a grant may carry a fact that reads no argument, and
    hand-written rego can emit the same id for anything. Each of those used to be set aside; each is a
    block whatever the arguments were."""

    @needs_opa
    async def test_only_a_refusal_down_to_argument_values_is_set_aside(self):
        rows = [
            _support("get_order", {"param_keys": ["id"]}),                    # grant reads values only
            _support("get_order", {"masked_params": {"id": "abc"}}),          # value kept: really refused
            _support("get_order", {"masked_params": {"id": "42"}}),           # value kept: allowed
            _support("update_order", {"param_keys": ["status"]}),             # read-only refinement fails too
            _support("list_orders", {"param_keys": ["limit"], "call_depth": 3}),  # call_depth fact fails too
            _support("query_run", {"param_keys": ["id"]}),                    # verb comes from the payload
            _support("lookup_widget", {"param_keys": ["id"]}),                # verb fixed by the name
            _support("delete_kb", {"param_keys": ["id"]}),                    # not allowlisted
        ]
        body = PolicyCreate(namespace="default", agent_class="support-agent", rego_source=_allowlist_rego())
        out = await _replay_recent(_OpaReplay(), _FakeSession(rows), body, datetime.now(timezone.utc))
        assert out["eval_errors"] == 0
        assert out["total_records_checked"] == 8
        assert sorted(s["tool_name"] for s in out["cannot_evaluate_samples"]) == ["get_order", "query_run"]
        assert out["cannot_evaluate"] == 2
        assert (out["would_allow"], out["would_block"], out["newly_blocked"]) == (1, 5, 5)
        flips = {s["tool_name"]: s["rule_id"] for s in out["newly_blocked_samples"]}
        assert flips == {
            "get_order": "intent_constraint_violation",
            "update_order": "intent_constraint_violation",
            "list_orders": "intent_constraint_violation",
            "lookup_widget": "intent_constraint_violation",
            "delete_kb": "intent_default_deny",
        }

    @needs_opa
    async def test_a_refinement_that_also_refuses_keeps_the_call_a_block(self):
        """THE case: update_order is not a read, so the read-only refinement refuses it whatever its
        arguments. Its grant fails as well on an empty replay, and the builder then labels it
        `intent_constraint_violation`."""
        ev = _OpaReplay()
        body = PolicyCreate(namespace="default", agent_class="support-agent", rego_source=_allowlist_rego())
        out = await _replay_recent(ev, _FakeSession([_support("update_order", {"param_keys": ["status"]})]),
                                   body, datetime.now(timezone.utc))
        assert out["newly_blocked_samples"] == [
            {"tool_name": "update_order", "was": "allow", "now": "block", "rule_id": "intent_constraint_violation"}]
        assert out["cannot_evaluate"] == 0
        # The verdict came from the probe with every grant assumed met, not from the rule id.
        assert any(k.endswith(":grants-met") for k in ev.keys)

    @needs_opa
    async def test_a_verb_fact_on_a_tool_whose_name_fixes_the_verb_stays_a_block(self):
        """Pinned on purpose. lookup_widget's grant failed on a value-less replay; it holds `id required`
        (an argument) and `verb == read` (fixed by the name). The replay cannot say which line failed, so
        the call is counted as a block. Here it was the argument, so this over-reports by one; the
        opposite choice would hide every refusal a name-fixed fact makes."""
        body = PolicyCreate(namespace="default", agent_class="support-agent", rego_source=_allowlist_rego())
        out = await _replay_recent(_OpaReplay(), _FakeSession([_support("lookup_widget", {"param_keys": ["id"]})]),
                                   body, datetime.now(timezone.utc))
        assert (out["cannot_evaluate"], out["would_block"]) == (0, 1)

    async def test_the_rule_id_from_rego_that_is_not_a_builder_allowlist_proves_nothing(self):
        """Hand-written rego can emit `intent_constraint_violation` for any reason. No graph describes it,
        so its refusal of a value-less record is counted as a block."""

        class _Ev(_FakeEvaluator):
            async def _evaluate_opa(self, key, ns, cls, opa_input, rego):
                self.calls += 1
                return {"decision": "block", "rule_id": "intent_constraint_violation", "reason": ""}

        body = PolicyCreate(namespace="analytics", agent_class="report-gen", rego_source="package x")
        rows = [_rec("send_email", "allow", payload={"param_keys": ["to"]})]
        out = await _replay_recent(_Ev(lambda _t: "block"), _FakeSession(rows), body, datetime.now(timezone.utc))
        assert (out["cannot_evaluate"], out["would_block"], out["newly_blocked"]) == (0, 1, 1)

    @needs_opa
    async def test_the_recommendation_does_not_call_unjudged_calls_safe(self):
        from types import SimpleNamespace as NS

        from norviq.api.routers.policies import dry_run_policy

        rows = [_support("get_order", {"param_keys": ["id"]}) for _ in range(6)]
        request = NS(app=NS(state=NS(evaluator=_OpaReplay())))
        body = PolicyCreate(namespace="default", agent_class="support-agent", rego_source=_allowlist_rego())
        out = await dry_run_policy(body, request, session=_FakeSession(rows), user={"role": "admin", "sub": "t"},
                                   _target=None)
        assert out["newly_blocked"] == 0
        assert out["cannot_evaluate"] == 6
        assert "safe to deploy" not in out["recommendation"]
        assert "6 further calls could not be evaluated" in out["recommendation"]


def test_the_advisory_names_what_is_set_aside_and_what_is_not(monkeypatch):
    """The advisory used to say any call refused only on an argument constraint was set aside. Only a
    builder allowlist's per-tool grant is; every other value rule is counted as it replays."""
    from norviq.api.routers import policies

    monkeypatch.setattr(policies.settings, "audit_capture_masked_params", False)
    text = policies._dryrun_advisory(5, 0)
    assert "Visual Builder allowlist refused only on its per-tool argument grant" in text
    assert "Any other refusal is counted as it replays" in text
