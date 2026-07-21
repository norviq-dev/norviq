# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Unit tests for the L1-collapse pipelined cache reads + the eval-invalidation hook (no real Redis)."""

from __future__ import annotations

import pytest

from norviq.engine.cache import RedisCache
from norviq.sdk.core.decisions import PolicyDecision

pytestmark = pytest.mark.asyncio


class _FakeRedis:
    def __init__(self, values: dict | None = None, raise_on: str | None = None) -> None:
        self.values = values or {}
        self.raise_on = raise_on  # "pipeline" to blow up the pipelined read

    def pipeline(self, transaction: bool = False):
        if self.raise_on == "pipeline":
            raise RuntimeError("redis down")
        return _FakePipe(self)


class _FakePipe:
    def __init__(self, client: _FakeRedis) -> None:
        self.client = client
        self.keys: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, key: str):
        self.keys.append(key)

    async def execute(self):
        if self.client.raise_on == "execute":
            raise RuntimeError("redis down mid-pipeline")
        return [self.client.values.get(k) for k in self.keys]


def _cache(fake: _FakeRedis) -> RedisCache:
    c = RedisCache(url="redis://unused")
    c._redis = fake  # type: ignore[assignment]
    return c


def _allow() -> PolicyDecision:
    return PolicyDecision(decision="allow", rule_id="default_allow", reason="ok")


async def test_get_agent_flags_reads_both_in_one_pipeline() -> None:
    c = _cache(_FakeRedis({"agent_frozen:sp": "1", "agent_trust_override:sp": "0.3"}))
    frozen, cap = await c.get_agent_flags("sp")
    assert frozen is True and cap == 0.3


async def test_get_agent_flags_absent_is_unfrozen_no_cap() -> None:
    frozen, cap = await _cache(_FakeRedis({})).get_agent_flags("sp")
    assert frozen is False and cap is None


async def test_get_agent_flags_fails_closed_on_error() -> None:
    frozen, cap = await _cache(_FakeRedis(raise_on="execute")).get_agent_flags("sp")
    assert frozen is True and cap is None          # Redis loss => frozen (fail-CLOSED), no cap


async def test_get_agent_flags_malformed_cap_fails_open() -> None:
    frozen, cap = await _cache(_FakeRedis({"agent_trust_override:sp": "not-a-float"})).get_agent_flags("sp")
    assert frozen is False and cap is None          # bad cap => no cap (fail-OPEN), matches _safe_override_only


async def test_get_eval_and_agent_flags_bundles_three_reads() -> None:
    c = _cache(_FakeRedis({}))
    key = c._eval_key("ns", "cls", "tool")
    c._redis.values = {key: _allow().model_dump_json(), "agent_frozen:sp": None, "agent_trust_override:sp": "0.9"}
    decision, frozen, cap = await c.get_eval_and_agent_flags("ns", "cls", "tool", "sp")
    assert decision is not None and decision.decision == "allow"
    assert frozen is False and cap == 0.9


async def test_get_eval_and_agent_flags_miss_returns_none_decision() -> None:
    decision, frozen, cap = await _cache(_FakeRedis({})).get_eval_and_agent_flags("ns", "cls", "tool", "sp")
    assert decision is None and frozen is False and cap is None


async def test_get_eval_and_agent_flags_fails_closed_on_error() -> None:
    decision, frozen, cap = await _cache(_FakeRedis(raise_on="pipeline")).get_eval_and_agent_flags("ns", "cls", "tool", "sp")
    assert decision is None and frozen is True and cap is None   # frozen=True forces a downstream block


async def test_invalidation_hook_fires_on_scope_and_all() -> None:
    fired: list = []

    class _NoKeysRedis(_FakeRedis):
        async def scan_iter(self, match=None):
            if False:
                yield  # empty async generator

    c = _cache(_NoKeysRedis({}))
    c.register_eval_invalidation_hook(lambda ns, cls: fired.append((ns, cls)))
    await c.invalidate_eval_scope("ns-x", "cls-y")     # even with zero Redis keys, the hook MUST fire
    await c.invalidate_all_eval()
    assert ("ns-x", "cls-y") in fired
    assert (None, None) in fired


async def test_invalidation_hook_error_never_breaks_invalidation() -> None:
    class _NoKeysRedis(_FakeRedis):
        async def scan_iter(self, match=None):
            if False:
                yield

    c = _cache(_NoKeysRedis({}))
    c.register_eval_invalidation_hook(lambda ns, cls: (_ for _ in ()).throw(RuntimeError("hook boom")))
    # Must not raise despite the throwing hook.
    assert await c.invalidate_eval_scope("ns", "cls") == 0
