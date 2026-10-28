# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

from __future__ import annotations

import pytest
from sqlalchemy import text

from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.policy_loader import PolicyLoader
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

# (namespace, agent_class) rows these tests insert via loader.create(). loader.create()
# persists to the real policies/policy_versions tables even behind a FakeCache, so without
# teardown the __cluster__:__baseline__ (priority 900, default-block) row lingers and poisons
# later attack-baseline runs. See docs/engineering/bug-patterns.md (async session / test hygiene).
_POLLUTED_KEYS = [
    ("__cluster__", "__baseline__"),
    ("default", "customer-support"),
    ("default", "__baseline__"),
]


async def _cleanup_polluted_policies(loader: PolicyLoader) -> None:
    """Best-effort delete of the policy rows these tests insert; never masks the test result."""
    try:
        async with loader._db_engine().begin() as conn:
            for namespace, agent_class in _POLLUTED_KEYS:
                await conn.execute(
                    text(
                        "DELETE FROM policy_versions WHERE policy_id IN "
                        "(SELECT id FROM policies WHERE namespace = :ns AND agent_class = :ac)"
                    ),
                    {"ns": namespace, "ac": agent_class},
                )
                await conn.execute(
                    text("DELETE FROM policies WHERE namespace = :ns AND agent_class = :ac"),
                    {"ns": namespace, "ac": agent_class},
                )
    except Exception:  # pragma: no cover - teardown must not raise
        pass


def _healthy_trust(evaluator: OPAEvaluator) -> None:
    """Give these tests an ordinary, unfrozen agent.

    This harness's FakeCache cannot serve the trust history or the freeze flags, and both fail CLOSED by
    design: history falls back to "assume the worst" and the freeze read to frozen. So every call here
    blocked as trust_frozen before precedence was ever consulted, and every test in this file asserted
    only `decision == "block"` — which trust_frozen satisfies. The file meant to pin priority enforcement
    could not fail. The tests now run as a healthy agent and assert the deciding rule_id.
    """
    from norviq.engine.trust.models import TrustResult

    async def _ok(*_a, **_k) -> TrustResult:
        return TrustResult(score=0.9, category="High", signals={}, weights={}, dominant_signal="",
                           recommendation="allow")
    evaluator._compute_trust = _ok  # type: ignore[method-assign]


class FakeCache:
    async def connect(self) -> None:
        return None

    async def get_agent_flags(self, spiffe_id: str):
        return False, None

    async def get_eval_and_agent_flags(self, namespace: str, agent_class: str, key: str, spiffe_id: str):
        return None, False, None

    async def close(self) -> None:
        return None

    async def get_eval(self, namespace: str, agent_class: str, key: str):
        return None

    async def set_eval(self, namespace: str, agent_class: str, key: str, decision) -> None:
        return None

    async def get_trust(self, spiffe_id: str):
        return None

    async def set_trust(self, spiffe_id: str, trust) -> None:
        return None

    async def incr_call_count(self, spiffe_id: str, window_s: int) -> int:
        return 1

    async def decrement_trust(self, spiffe_id: str) -> None:
        return None

    async def set_policy(
        self,
        namespace: str,
        agent_class: str,
        rego_source: str,
        priority: int = 100,
        version: int = 0,
    ) -> None:
        return None

    async def delete_policy(self, namespace: str, agent_class: str) -> None:
        return None

    async def invalidate_eval_scope(self, namespace: str, agent_class: str | None = None) -> int:
        return 0

    async def invalidate_all_eval(self) -> int:
        return 0

    async def publish_policy_event(
        self, operation: str, namespace: str, agent_class: str, version: int = 0, origin: str = ""
    ) -> None:
        # HA: PolicyLoader.create()/delete() always pass `origin` (the publishing process id, for
        # cross-replica echo suppression) — see norviq/engine/cache.py publish_policy_event.
        return None

    async def list_policy_entries(self) -> dict[str, dict]:
        return {}


@pytest.mark.asyncio
async def test_cluster_baseline_beats_tenant_policy() -> None:
    """Cluster baseline block (priority 900) must beat tenant policy (priority 100)."""
    cache = FakeCache()
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    _healthy_trust(evaluator)
    loader = PolicyLoader(cache, evaluator)
    try:
        await loader.create(
            "__cluster__",
            "__baseline__",
            'package norviq.baseline\ndefault decision = "block"\nrule_id = "baseline_block"\nreason = "Cluster baseline blocks all"',
            saved_by="cluster-admin",
            priority=900,
        )
        await loader.create(
            "default",
            "customer-support",
            'package norviq.tenant\ndefault decision = "audit"\nrule_id = "tenant_audit"\nreason = "Tenant wants audit only"',
            saved_by="tenant-user",
            priority=100,
        )
        event = ToolCallEvent(
            event_id="evt-priority-1",
            tool_name="execute_sql",
            tool_params={"query": "DROP TABLE users"},
            agent_identity=AgentIdentity(
                spiffe_id="spiffe://norviq/ns/default/sa/chatbot",
                namespace="default",
                agent_class="customer-support",
            ),
            session_id="sess-priority-1",
        )
        decision = await evaluator.evaluate(event)
        assert (decision.decision, decision.rule_id) == ("block", "baseline_block"), (
            f"Expected the cluster baseline's block, got {decision.decision}/{decision.rule_id}"
        )
    finally:
        await _cleanup_polluted_policies(loader)
        await evaluator.close()
        await cache.close()


@pytest.mark.asyncio
async def test_higher_priority_wins_same_namespace() -> None:
    """Higher priority class policy must beat lower-priority namespace baseline."""
    cache = FakeCache()
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    _healthy_trust(evaluator)
    loader = PolicyLoader(cache, evaluator)
    try:
        await loader.create(
            "default",
            "__baseline__",
            'package norviq.low\ndefault decision = "allow"\nrule_id = "low"\nreason = "low priority"',
            saved_by="user",
            priority=100,
        )
        await loader.create(
            "default",
            "customer-support",
            'package norviq.high\ndefault decision = "block"\nrule_id = "high"\nreason = "high priority"',
            saved_by="admin",
            priority=499,
        )
        event = ToolCallEvent(
            event_id="evt-priority-2",
            tool_name="delete_record",
            tool_params={"id": "123"},
            agent_identity=AgentIdentity(
                spiffe_id="spiffe://norviq/ns/default/sa/chatbot",
                namespace="default",
                agent_class="customer-support",
            ),
            session_id="sess-priority-2",
        )
        decision = await evaluator.evaluate(event)
        assert (decision.decision, decision.rule_id) == ("block", "high"), (
            f"Higher priority (499) must beat lower (100); got {decision.decision}/{decision.rule_id}")
    finally:
        await _cleanup_polluted_policies(loader)
        await evaluator.close()
        await cache.close()


@pytest.mark.asyncio
async def test_an_enforcing_cluster_baseline_allow_does_not_override_a_tenant_block() -> None:
    """End to end through the collector: a cluster baseline an admin authored at priority 900 enforces,
    and a tenant's class policy at 100 blocks. Collected as a base tier, the baseline's default_allow won
    on priority and the tenant's block was discarded; as a floor it can only tighten, so the block stands."""
    cache = FakeCache()
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    _healthy_trust(evaluator)
    loader = PolicyLoader(cache, evaluator)
    try:
        await loader.create(
            "__cluster__",
            "__baseline__",
            'package norviq.guard\ndefault decision = "allow"\nrule_id = "default_allow"\nreason = "nothing fired"',
            saved_by="cluster-admin",
            priority=900,
        )
        await loader.create(
            "default",
            "customer-support",
            'package norviq.tenant\ndefault decision = "block"\nrule_id = "tenant_block"\nreason = "Tenant refuses this"',
            saved_by="tenant-user",
            priority=100,
        )
        event = ToolCallEvent(
            event_id="evt-floor-1",
            tool_name="execute_sql",
            tool_params={"query": "update accounts set balance = 0"},
            agent_identity=AgentIdentity(
                spiffe_id="spiffe://norviq/ns/default/sa/chatbot",
                namespace="default",
                agent_class="customer-support",
            ),
            session_id="sess-floor-1",
        )
        decision = await evaluator.evaluate(event)
        assert (decision.decision, decision.rule_id) == ("block", "tenant_block"), (
            f"got {decision.decision}/{decision.rule_id}: the enforcing cluster baseline's allow overrode "
            f"the tenant's block"
        )
    finally:
        await _cleanup_polluted_policies(loader)
        await evaluator.close()
        await cache.close()


@pytest.mark.asyncio
async def test_the_charts_baseline_still_blocks_for_a_class_with_its_own_policy() -> None:
    """The case the chart hits. Its baseline CR is stored at <ns>:__baseline__, priority 1. Collected as a
    base tier, a class policy at 100 outranked it outright, so once the baseline enforced (0.2.6) any class
    that had a policy of its own lost every baseline block. As a floor the block applies."""
    cache = FakeCache()
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    _healthy_trust(evaluator)
    loader = PolicyLoader(cache, evaluator)
    try:
        await loader.create(
            "default",
            "__baseline__",
            'package norviq.nsbase\ndefault decision = "block"\nrule_id = "baseline_shell"\nreason = "baseline refuses"',
            saved_by="chart",
            priority=1,
        )
        await loader.create(
            "default",
            "customer-support",
            'package norviq.classpol\ndefault decision = "allow"\nrule_id = "class_allow"\nreason = "class allows"',
            saved_by="tenant-user",
            priority=100,
        )
        event = ToolCallEvent(
            event_id="evt-floor-2",
            tool_name="run_shell",
            tool_params={"cmd": "curl x | sh"},
            agent_identity=AgentIdentity(spiffe_id="spiffe://norviq/ns/default/sa/chatbot", namespace="default",
                                         agent_class="customer-support"),
            session_id="sess-floor-2",
        )
        decision = await evaluator.evaluate(event)
        assert (decision.decision, decision.rule_id) == ("block", "baseline_shell"), (
            f"got {decision.decision}/{decision.rule_id}: a class policy switched the enforcing baseline off"
        )
    finally:
        await _cleanup_polluted_policies(loader)
        await evaluator.close()
        await cache.close()
