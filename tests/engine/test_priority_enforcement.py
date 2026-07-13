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


class FakeCache:
    async def connect(self) -> None:
        return None

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
        assert decision.decision == "block", (
            f"Expected block from baseline (900), got {decision.decision} — PRIORITY ENFORCEMENT BROKEN"
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
        assert decision.decision == "block", "Higher priority (499) must beat lower (100)"
    finally:
        await _cleanup_polluted_policies(loader)
        await evaluator.close()
        await cache.close()
