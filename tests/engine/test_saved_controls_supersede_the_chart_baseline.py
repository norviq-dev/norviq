# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A namespace's saved control effects replace the chart's baseline there; nothing else does.

From 0.2.6 the chart's baseline enforces and is a floor, and the console's per-control switch was a
floor too. Floors combine strictest-wins, so the switch could tighten a control and never relax one.
Measured live on prep/0.2.6 (persona-legal, chart baseline in block): deny_shell_execution set to Off,
then to Monitor, still came back block / deny_shell_execution. The same on this resolver before the
fix, with the shipped strict preset as `<ns>:__baseline__` and the console's compiled module as
`<ns>:__controls__`:

    chart block  + controls deny_shell_execution=off       block / deny_shell_execution
    chart block  + controls deny_shell_execution=monitor   block / deny_shell_execution

These run the real evaluator, the managed OPA server and the shipped preset, and assert the deciding
rule_id, so a trust freeze or a fallback cannot pass for the property under test.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text

from norviq.api import baseline
from norviq.engine import evaluator as evaluator_mod
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.policy_loader import PolicyLoader
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from tests.engine.test_priority_enforcement import FakeCache, _healthy_trust

NS = "persona-legal"
OTHER = "persona-hr"
CLASS = "legal-assistant"
CHART = baseline.preset_source("strict")

SHELL = ("run_shell", {"cmd": "cat /etc/passwd; rm -rf /tmp/x"})
SQLI = ("run_report", {"q": "drop table users"})

# A class policy that allows everything, at the default class priority. It must never loosen a baseline.
ALLOW_ALL = 'package norviq.classpol\ndefault decision = "allow"\nrule_id = "class_allow"\nreason = "class allows"'


def _chart(ns: str = NS, mode: str = "block", rego: str = CHART) -> dict:
    """The chart's baseline exactly as the controller stores it: the preset file, priority 1."""
    return {f"{ns}:__baseline__": {"rego": rego, "priority": 1, "enforcement_mode": mode}}


def _controls(ns: str = NS, rego: str | None = None, **effects: str) -> dict:
    """The console's saved controls exactly as baseline_router._materialize stores them."""
    return {f"{ns}:__controls__": {"rego": rego if rego is not None else baseline.compile("strict", effects),
                                   "priority": 2, "enforcement_mode": "block"}}


def _class_policy(ns: str = NS) -> dict:
    return {f"{ns}:{CLASS}": {"rego": ALLOW_ALL, "priority": 100, "enforcement_mode": "block"}}


class _Loader:
    """The loader surface the collectors read: the in-memory map, the DB fallback and the union lookup."""

    def __init__(self, policies: dict, failing: tuple[str, ...] = ()) -> None:
        self._policies = dict(policies)
        self._warmed = True
        self._failing = set(failing)

    async def load_from_db(self, namespace: str, agent_class: str) -> dict | None:
        if f"{namespace}:{agent_class}" in self._failing:
            raise ConnectionError("postgres unreachable")
        return None

    async def namespaces_for_class(self, agent_class: str) -> list[str]:
        return sorted({k.partition(":")[0] for k in self._policies if k.partition(":")[2] == agent_class})


def _event(tool: str, params: dict, ns: str = NS) -> ToolCallEvent:
    return ToolCallEvent(
        tool_name=tool, tool_params=params, session_id="supersede",
        agent_identity=AgentIdentity(spiffe_id=f"spiffe://norviq/ns/{ns}/sa/legal", namespace=ns,
                                     agent_class=CLASS),
    )


def _evaluator(policies: dict, failing: tuple[str, ...] = ()) -> OPAEvaluator:
    ev = OPAEvaluator(FakeCache())
    _healthy_trust(ev)
    ev.bind_loader(_Loader(policies, failing))
    return ev


async def _decide(policies: dict, call: tuple[str, dict], ns: str = NS, failing: tuple[str, ...] = ()) -> tuple[str, str]:
    ev = _evaluator(policies, failing)
    try:
        decision = await ev.evaluate(_event(*call, ns=ns))
    finally:
        await ev.close()
    return decision.decision, decision.rule_id


@pytest.mark.asyncio
async def test_off_relaxes_a_control_the_chart_baseline_blocks() -> None:
    policies = {**_chart(), **_controls(deny_shell_execution="off"), **_chart(OTHER)}
    assert await _decide(policies, SHELL) == ("allow", "default_allow")
    # A control the operator left at its deny default still blocks...
    assert await _decide(policies, SQLI) == ("block", "deny_sql_injection")
    # ...and a namespace with no saved controls keeps the chart's block.
    assert await _decide(policies, SHELL, ns=OTHER) == ("block", "deny_shell_execution")


@pytest.mark.asyncio
async def test_monitor_records_the_call_under_the_controls_rule_id() -> None:
    policies = {**_chart(), **_controls(deny_shell_execution="monitor")}
    assert await _decide(policies, SHELL) == ("audit", "deny_shell_execution")


@pytest.mark.asyncio
async def test_saved_effects_govern_over_a_chart_baseline_in_audit() -> None:
    """`enforcementMode=audit` on the chart: an explicit Enforce still blocks, and an explicit Off is
    off — before the fix the audit chart floor still recorded it as a would-block."""
    assert await _decide({**_chart(mode="audit"), **_controls(deny_shell_execution="deny")}, SHELL) == \
        ("block", "deny_shell_execution")
    assert await _decide({**_chart(mode="audit"), **_controls(deny_shell_execution="off")}, SHELL) == \
        ("allow", "default_allow")


@pytest.mark.asyncio
async def test_every_control_then_does_what_the_console_showed() -> None:
    """The consequence of "complete specification", pinned so it is a decision and not a surprise.

    The chart's baseline is the preset file, where `strict_default_block` registers as a block. The
    console shows that control at Monitor (its shipped default) and saves every row as shown, so once
    any control is saved this one records instead of blocking — what the console said all along. The
    alternative, keeping the chart's block for rows the operator did not touch, would leave every
    Monitor row that differs from the chart unable to take effect."""
    execute_sql = ("execute_sql", {"query": "select 1"})
    assert await _decide(_chart(), execute_sql) == ("block", "strict_default_block")
    saved = {**_chart(), **_controls(deny_shell_execution="off")}
    assert await _decide(saved, execute_sql) == ("audit", "strict_default_block")


@pytest.mark.asyncio
async def test_without_saved_controls_the_chart_baseline_governs() -> None:
    assert await _decide(_chart(), SHELL) == ("block", "deny_shell_execution")
    assert await _decide(_chart(mode="audit"), SHELL) == \
        ("audit", "policy_audit_would_block:deny_shell_execution")


@pytest.mark.asyncio
async def test_a_class_policy_cannot_loosen_the_effective_baseline() -> None:
    """b9d414b's guarantee, in both states: the chart's baseline, and the saved controls replacing it."""
    assert await _decide({**_chart(), **_class_policy()}, SHELL) == ("block", "deny_shell_execution")
    superseded = {**_chart(), **_controls(deny_shell_execution="monitor"), **_class_policy()}
    assert await _decide(superseded, SQLI) == ("block", "deny_sql_injection")
    assert await _decide(superseded, SHELL) == ("audit", "deny_shell_execution")


@pytest.mark.asyncio
async def test_the_cluster_baseline_is_never_superseded() -> None:
    """`__cluster__:__baseline__` is an admin's cluster-wide floor, not the chart's per-namespace guard."""
    cluster = {"__cluster__:__baseline__": {"rego": CHART, "priority": 900, "enforcement_mode": "block"}}
    policies = {**cluster, **_chart(), **_controls(deny_shell_execution="off")}
    assert await _decide(policies, SHELL) == ("block", "deny_shell_execution")


@pytest.mark.asyncio
async def test_saved_controls_do_not_supersede_a_baseline_built_from_another_preset() -> None:
    """The console compiles `strict` only. A chart on `moderate` has rules the console cannot express,
    so superseding it would drop a rule nobody switched off: both stay floors."""
    moderate = baseline._preset_dir() / "moderate.rego"  # type: ignore[operator]
    everything_off = {cid: "off" for cid in baseline.control_ids("strict")}
    policies = {**_chart(rego=moderate.read_text(encoding="utf-8")), **_controls(**everything_off)}
    assert await _decide(policies, ("run_report", {"query": "drop table users"})) == \
        ("block", "moderate_drop_block")


@pytest.mark.asyncio
async def test_controls_saved_before_the_off_marker_keep_the_chart_floor_for_what_they_switched_off() -> None:
    """A module compiled before CONTROLS_OFF cannot say a missing control was switched off rather than
    unknown, so it supersedes only when nothing is missing. Re-saving the controls writes the marker."""
    def legacy(**effects: str) -> str:
        return "\n".join(line for line in baseline.compile("strict", effects).splitlines()
                         if not line.startswith(baseline.CONTROLS_OFF)) + "\n"

    assert await _decide({**_chart(), **_controls(rego=legacy(deny_shell_execution="off"))}, SHELL) == \
        ("block", "deny_shell_execution")
    assert await _decide({**_chart(), **_controls(rego=legacy(deny_shell_execution="monitor"))}, SHELL) == \
        ("audit", "deny_shell_execution")


@pytest.mark.asyncio
async def test_a_failing_controls_lookup_fails_closed() -> None:
    """Postgres down while looking up `__controls__`: the operator's effects are unknown, so the chart's
    block must not be dropped. Today the raised lookup fails the whole evaluation closed
    (evaluator_fallback); keeping the chart floor (deny_shell_execution) would be acceptable too. An
    allow is not."""
    decision = await _decide({**_chart(), **_chart(OTHER)}, SHELL, failing=(f"{NS}:__controls__",))
    assert decision in (("block", "evaluator_fallback"), ("block", "deny_shell_execution"))


@pytest.mark.asyncio
async def test_an_error_while_comparing_keeps_the_chart_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_a: object) -> bool:
        raise RuntimeError("comparison failed")

    monkeypatch.setattr(evaluator_mod.baseline_lib, "covers", broken)
    policies = {**_chart(), **_controls(deny_shell_execution="off")}
    assert await _decide(policies, SHELL) == ("block", "deny_shell_execution")


@pytest.mark.asyncio
async def test_both_collectors_agree() -> None:
    """The console's "All namespaces" view (namespace="all") must report what an agent actually gets."""
    policies = {**_class_policy(), **_chart(), **_controls(deny_shell_execution="off"),
                **_class_policy(OTHER), **_chart(OTHER)}
    ev = _evaluator(policies)
    try:
        concrete = {c["key"] for c in await ev._collect_candidates(_event(*SHELL))}
        union = {c["key"] for c in await ev._collect_candidates(_event(*SHELL, ns="all"))}
        assert f"{NS}:__controls__" in concrete and f"{NS}:__baseline__" not in concrete
        assert f"{NS}:__controls__" in union and f"{NS}:__baseline__" not in union
        assert f"{OTHER}:__baseline__" in union, "a namespace without saved controls keeps its chart baseline"
        # explain=True (/policies/effective) keeps the superseded baseline, saying what replaced it.
        for ns in (NS, "all"):
            explained = {c["key"]: c for c in await ev._collect_candidates(_event(*SHELL, ns=ns), explain=True)}
            assert explained[f"{NS}:__baseline__"].get("superseded_by") == f"{NS}:__controls__"
    finally:
        await ev.close()
    only_ns = {**_class_policy(), **_chart(), **_controls(deny_shell_execution="off")}
    assert await _decide(only_ns, SHELL, ns="all") == ("allow", "class_allow")
    assert await _decide(only_ns, SQLI, ns="all") == ("block", "deny_sql_injection")


class _CachingCache(FakeCache):
    """FakeCache plus a real eval cache and the invalidation hook, like RedisCache."""

    def __init__(self) -> None:
        self.evals: dict[tuple[str, str, str], object] = {}
        self._hooks: list = []

    def register_eval_invalidation_hook(self, callback) -> None:
        self._hooks.append(callback)

    async def get_eval(self, namespace: str, agent_class: str, key: str):
        return self.evals.get((namespace, agent_class, key))

    async def get_eval_and_agent_flags(self, namespace: str, agent_class: str, key: str, spiffe_id: str):
        return self.evals.get((namespace, agent_class, key)), False, None

    async def set_eval(self, namespace: str, agent_class: str, key: str, decision) -> None:
        self.evals[(namespace, agent_class, key)] = decision

    async def invalidate_eval_scope(self, namespace: str, agent_class: str | None = None) -> int:
        for hook in self._hooks:
            hook(namespace, agent_class)
        doomed = [k for k in self.evals if k[0] == namespace and agent_class in (None, k[1])]
        for k in doomed:
            del self.evals[k]
        return len(doomed)


_CACHE_NS = "ctl-supersede-cache"


async def _drop_rows(loader: PolicyLoader) -> None:
    try:
        async with loader._db_engine().begin() as conn:
            for agent_class in ("__baseline__", "__controls__"):
                await conn.execute(text("DELETE FROM policy_versions WHERE policy_id IN (SELECT id FROM "
                                        "policies WHERE namespace = :ns AND agent_class = :ac)"),
                                   {"ns": _CACHE_NS, "ac": agent_class})
                await conn.execute(text("DELETE FROM policies WHERE namespace = :ns AND agent_class = :ac"),
                                   {"ns": _CACHE_NS, "ac": agent_class})
    except Exception:  # pragma: no cover - teardown must not raise
        pass


@pytest.mark.asyncio
async def test_saving_controls_evicts_decisions_cached_under_the_chart_baseline() -> None:
    """Through the real loader: the chart's block is cached, then the controls are saved the way
    baseline_router._materialize saves them. The next call must be decided afresh, not served the block
    for the eval TTL. loader.create invalidates the whole namespace for any `__`-prefixed scope."""
    cache = _CachingCache()
    ev = OPAEvaluator(cache)
    _healthy_trust(ev)
    loader = PolicyLoader(cache, ev)
    try:
        await _drop_rows(loader)
        await loader.create(_CACHE_NS, "__baseline__", CHART, saved_by="chart", priority=1)
        first = await ev.evaluate(_event(*SHELL, ns=_CACHE_NS))
        assert (first.decision, first.rule_id) == ("block", "deny_shell_execution")
        assert any(k[0] == _CACHE_NS for k in cache.evals), "fixture: the chart's decision was not cached"
        await loader.create(_CACHE_NS, "__controls__", baseline.compile("strict", {"deny_shell_execution": "off"}),
                            saved_by="baseline-controls", priority=2, enforcement_mode="block")
        second = await ev.evaluate(_event(*SHELL, ns=_CACHE_NS))
        assert (second.decision, second.rule_id) == ("allow", "default_allow")
    finally:
        await _drop_rows(loader)
        await ev.close()
