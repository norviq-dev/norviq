# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Shared fixtures for the Norviq test suite.

The evaluator-level unit tests (engine/sdk/sidecar) exercise OPA against `comprehensive.rego`.
They construct a bare `OPAEvaluator(cache)` which has no loader bound — so `_collect_candidates`
returns nothing and every decision falls to `default_allow`. `SeededClusterLoader` binds the
comprehensive policy as the `__cluster__:__baseline__` candidate, which applies to every agent
(no DB/Redis seeding required), so the deny rules actually fire.
"""

from __future__ import annotations

import json
import pathlib
import time
from datetime import datetime, timezone

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


_RUNTIME_PATTERNS = ("eval:*", "trust:*", "agent_history:*", "agent_profile:*", "agent_class:*", "agent_frozen:*", "trustcalc:*")


async def flush_runtime(cache) -> None:
    """Clear per-agent runtime keys so tests don't inherit each other's trust/cache state."""
    client = cache._client()
    for pattern in _RUNTIME_PATTERNS:
        keys = [key async for key in client.scan_iter(pattern)]
        if keys:
            await client.delete(*keys)


async def seed_low_trust(cache, spiffe_id: str, agent_class: str = "support", called_tool: str = "sensitive_tool") -> None:
    """Seed history + profile + class so the agent's COMPUTED trust drops below 0.4 (→ escalate).

    The evaluator recomputes trust from behavioral signals (it does not read a manually-set trust
    cache), so low-trust tests must seed the same Redis state the attack suite uses: 30 recent
    blocks (violation_rate→0), a profile whose known_tools/baseline make the called tool novel and
    high-entropy, and a class whose blocked_tools include the called tool (scope_drift→0).
    """
    client = cache._client()
    hist_key = f"agent_history:{spiffe_id}"
    prof_key = f"agent_profile:{spiffe_id}"
    class_key = f"agent_class:{agent_class}"
    await client.delete(hist_key, prof_key, class_key)

    now = time.time()
    members: dict[str, float] = {}
    for i in range(30):
        ts = now - i
        members[
            json.dumps(
                {
                    "i": i,
                    "tool_name": "noop_attack",
                    "decision": "block",
                    "timestamp": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                    "timestamp_unix": ts,
                }
            )
        ] = ts
    await client.zadd(hist_key, members)
    await client.hset(
        prof_key,
        mapping={
            "known_tools": json.dumps(["noop_tool"]),
            "param_entropy_baseline": json.dumps({"search_kb": {"mean": 1.0, "std": 0.2}}),
            "baseline_rpm": "10.0",
        },
    )
    await client.hset(class_key, mapping={"blocked_tools": json.dumps([called_tool])})


class SeededClusterLoader:
    """A minimal loader that applies one rego document as the cluster baseline for every agent."""

    def __init__(self, rego: str, priority: int = 100) -> None:
        self._policies = {
            "__cluster__:__baseline__": {"rego": rego, "priority": priority, "package_name": "norviq.strict"},
        }

    async def load_from_db(self, namespace: str, agent_class: str):  # noqa: D401 - loader contract
        """No DB lookups in unit tests; the cluster baseline covers every candidate."""
        return None

    async def close(self) -> None:
        return None


@pytest.fixture(scope="session")
def comprehensive_rego() -> str:
    """The production policy bundle used by the OPA-backed unit tests."""
    return (_REPO_ROOT / "comprehensive.rego").read_text(encoding="utf-8")


@pytest.fixture
def seeded_loader(comprehensive_rego: str) -> SeededClusterLoader:
    """A loader pre-seeded with comprehensive.rego as the cluster baseline."""
    return SeededClusterLoader(comprehensive_rego)
