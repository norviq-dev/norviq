# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""End-to-end tests for the L1+L2 hot-path optimization (in-proc eval cache + pipelined reads) against a
real Redis + comprehensive.rego. The load-bearing test is freeze-still-flips-a-stale-in-proc-allow: it
proves the latency optimization never weakens the incident-response kill switch."""

from __future__ import annotations

import os
import uuid

import pytest

from norviq.config import settings
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

pytestmark = pytest.mark.asyncio

_RUNTIME_PATTERNS = (
    "eval:*", "agent_frozen:*", "agent_trust_override:*", "trust:*",
    "trustcalc:*", "history:*", "profile:*", "callcount:*",
)


@pytest.fixture
def redis_url() -> str:
    url = os.environ.get("NRVQ_REDIS_URL") or os.environ.get("REDIS_URL")
    if not url:
        pytest.skip("NRVQ_REDIS_URL not set — L1+L2 e2e needs a real Redis")
    return url


async def _flush(cache: RedisCache) -> None:
    client = cache._client()
    for pattern in _RUNTIME_PATTERNS:
        keys = [k async for k in client.scan_iter(match=pattern)]
        if keys:
            await client.delete(*keys)


@pytest.fixture
async def l1l2_evaluator(redis_url: str, seeded_loader, monkeypatch: pytest.MonkeyPatch):
    """Evaluator with the in-process L1s ENABLED (ttl=5) + comprehensive.rego, on real Redis."""
    monkeypatch.setattr(settings, "evaluator_inproc_cache_ttl_s", 5.0)
    cache = RedisCache(url=redis_url)
    await cache.connect()
    await _flush(cache)
    engine = OPAEvaluator(cache)  # __init__ reads the patched setting -> all L1s enabled
    engine.bind_loader(seeded_loader)
    yield engine
    await engine.close()
    await cache.close()


def _event(spiffe: str, tool: str, params: dict, event_id: str) -> ToolCallEvent:
    return ToolCallEvent(
        event_id=event_id,
        tool_name=tool,
        tool_params=params,
        agent_identity=AgentIdentity(spiffe_id=spiffe, namespace="tenant-a", agent_class="support"),
        session_id="l1l2-sess",
    )


async def test_inproc_eval_cache_is_enabled_and_warms(l1l2_evaluator: OPAEvaluator) -> None:
    ev = l1l2_evaluator
    assert ev._inproc_eval_cache.enabled
    spiffe = f"spiffe://norviq/ns/tenant-a/sa/agent-{uuid.uuid4().hex}"
    d1 = await ev.evaluate(_event(spiffe, "search_kb", {"query": "refund policy"}, "e1"))
    assert d1.decision == "allow"
    assert len(ev._inproc_eval_cache) >= 1          # the base decision was mirrored into the per-pod L1


async def test_freeze_flips_a_stale_inproc_allow(l1l2_evaluator: OPAEvaluator) -> None:
    """THE invariant: a warm in-proc ALLOW + an admin freeze applied mid-session => block on the very next
    call. Proves freeze/cap are read FRESH (never cached) even when the eval decision is served from the L1."""
    ev = l1l2_evaluator
    spiffe = f"spiffe://norviq/ns/tenant-a/sa/agent-{uuid.uuid4().hex}"
    params = {"query": "refund policy"}

    d1 = await ev.evaluate(_event(spiffe, "search_kb", params, "e1"))
    assert d1.decision == "allow"                   # warms the in-proc eval cache with the base allow

    # Admin freezes this identity mid-session (writes the shared Redis kill-switch key directly).
    await ev._cache._client().set(f"agent_frozen:{spiffe}", "1")

    d2 = await ev.evaluate(_event(spiffe, "search_kb", params, "e2"))   # identical -> in-proc HIT
    assert d2.decision == "block"                   # ...but the FRESH freeze read flipped the cached allow
    assert "frozen" in d2.rule_id


async def test_warm_hit_skips_the_eval_read(l1l2_evaluator: OPAEvaluator) -> None:
    """The L2 win: a warm in-proc hit uses get_agent_flags (freeze/cap only), NOT get_eval_and_agent_flags
    (which carries the eval read). So the second identical call does not re-read the eval decision."""
    ev = l1l2_evaluator
    spiffe = f"spiffe://norviq/ns/tenant-a/sa/agent-{uuid.uuid4().hex}"
    params = {"query": "refund policy"}
    calls = {"eval_and_flags": 0, "flags_only": 0}
    real_eval_flags = ev._cache.get_eval_and_agent_flags
    real_flags = ev._cache.get_agent_flags

    async def _spy_eval_flags(*a, **k):
        calls["eval_and_flags"] += 1
        return await real_eval_flags(*a, **k)

    async def _spy_flags(*a, **k):
        calls["flags_only"] += 1
        return await real_flags(*a, **k)

    ev._cache.get_eval_and_agent_flags = _spy_eval_flags  # type: ignore[assignment]
    ev._cache.get_agent_flags = _spy_flags  # type: ignore[assignment]

    await ev.evaluate(_event(spiffe, "search_kb", params, "e1"))   # in-proc miss -> eval_and_flags
    await ev.evaluate(_event(spiffe, "search_kb", params, "e2"))   # in-proc hit  -> flags only
    assert calls["eval_and_flags"] == 1
    assert calls["flags_only"] == 1


async def test_policy_invalidation_clears_the_inproc_eval_cache(l1l2_evaluator: OPAEvaluator) -> None:
    ev = l1l2_evaluator
    spiffe = f"spiffe://norviq/ns/tenant-a/sa/agent-{uuid.uuid4().hex}"
    await ev.evaluate(_event(spiffe, "search_kb", {"query": "x"}, "e1"))
    assert len(ev._inproc_eval_cache) >= 1
    await ev._cache.invalidate_eval_scope("tenant-a", "support")   # fires the registered clear hook
    assert len(ev._inproc_eval_cache) == 0
