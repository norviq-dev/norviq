# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""In-process L1 cache path of TrustCalculator.calculate (inproc_ttl_s > 0).

The security-critical invariant here: caching the two slow per-identity reads (history, profile) must
NOT cache the admin freeze/cap kill-switch — a freeze applied mid-window has to take effect on the very
next call, not after the TTL. These tests exercise the enabled path that production runs with, which the
default-off unit suite never touches.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from norviq.engine import inproc_cache
from norviq.engine.trust.calculator import TrustCalculator
from norviq.engine.trust.models import TrustInput

pytestmark = pytest.mark.asyncio


class _RedisStub:
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.hashes: dict[str, dict[str, str]] = {}

    async def get(self, key: str):
        return self.values.get(key)

    async def hgetall(self, key: str):
        return self.hashes.get(key, {})

    def pipeline(self, transaction: bool = False):
        return _PipelineStub(self)


class _PipelineStub:
    def __init__(self, client: _RedisStub) -> None:
        self.client = client
        self.ops: list[tuple[str, str]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def hgetall(self, key: str):
        self.ops.append(("hgetall", key))

    async def get(self, key: str):
        self.ops.append(("get", key))

    async def execute(self):
        out = []
        for op, key in self.ops:
            out.append(await (self.client.hgetall(key) if op == "hgetall" else self.client.get(key)))
        return out


class _CacheStub:
    def __init__(self) -> None:
        self.client = _RedisStub()

    def _client(self) -> _RedisStub:
        return self.client


class _CountingHistory:
    def __init__(self) -> None:
        self.calls = 0

    async def get_history(self, spiffe_id: str) -> list[dict]:
        self.calls += 1
        return [{"decision": "allow"}] * 20


class _ProfileStub:
    async def get_profile(self, spiffe_id: str, agent_class: str) -> dict:
        return {"known_tools": ["search_kb"], "baseline_rpm": 20}


def _ti(spiffe: str = "spiffe://a", tool: str = "search_kb") -> TrustInput:
    return TrustInput(
        spiffe_id=spiffe, namespace="default", agent_class="support", tool_name=tool,
        tool_params={"q": "x"}, session_id="s", chain_depth=0, timestamp=datetime.now(timezone.utc),
    )


async def test_history_read_is_served_from_l1_on_the_second_call() -> None:
    hist = _CountingHistory()
    calc = TrustCalculator(_CacheStub(), hist, _ProfileStub(), inproc_ttl_s=30.0)
    await calc.calculate(_ti())
    await calc.calculate(_ti())          # same spiffe within TTL -> L1 hit
    assert hist.calls == 1               # the slow ZRANGEBYSCORE ran exactly once


async def test_distinct_identities_do_not_share_l1_entries() -> None:
    hist = _CountingHistory()
    calc = TrustCalculator(_CacheStub(), hist, _ProfileStub(), inproc_ttl_s=30.0)
    await calc.calculate(_ti(spiffe="spiffe://a"))
    await calc.calculate(_ti(spiffe="spiffe://b"))
    assert hist.calls == 2               # per-identity keying, no cross-agent bleed


async def test_expiry_refetches_history(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    monkeypatch.setattr(inproc_cache.time, "monotonic", lambda: now[0])
    hist = _CountingHistory()
    calc = TrustCalculator(_CacheStub(), hist, _ProfileStub(), inproc_ttl_s=5.0)
    await calc.calculate(_ti())
    now[0] = 1006.0                       # past the 5s window
    await calc.calculate(_ti())
    assert hist.calls == 2               # stale entry expired -> fresh read


async def test_freeze_is_read_fresh_even_when_history_profile_are_cached() -> None:
    """The kill-switch invariant: warm the L1 with an unfrozen agent, then freeze it in Redis. The very
    next call must return `frozen` — proving freeze rides fresh Redis, not the cached inputs."""
    cache = _CacheStub()
    hist = _CountingHistory()
    calc = TrustCalculator(cache, hist, _ProfileStub(), inproc_ttl_s=30.0)

    first = await calc.calculate(_ti())
    assert first.category != "frozen"

    # Admin freezes the agent AFTER its history/profile are already cached in the pod.
    cache.client.values["agent_frozen:spiffe://a"] = "1"
    second = await calc.calculate(_ti())

    assert hist.calls == 1               # inputs still served from L1 (not re-read)
    assert second.category == "frozen"   # ...but the freeze took effect immediately
    assert second.recommendation == "freeze"


async def test_admin_cap_is_read_fresh_even_when_inputs_are_cached() -> None:
    """Same fresh-read guarantee for the tighten-only trust CAP (agent_trust_override)."""
    cache = _CacheStub()
    hist = _CountingHistory()
    calc = TrustCalculator(cache, hist, _ProfileStub(), inproc_ttl_s=30.0)

    first = await calc.calculate(_ti())
    assert first.score > 0.7             # clean agent, high trust

    cache.client.values["agent_trust_override:spiffe://a"] = "0.10"   # admin caps it down
    second = await calc.calculate(_ti())

    assert hist.calls == 1               # inputs cached
    assert second.score == 0.10          # cap applied fresh this call
    assert second.category == "low"


async def test_ttl_zero_takes_the_legacy_fresh_path_every_call() -> None:
    hist = _CountingHistory()
    calc = TrustCalculator(_CacheStub(), hist, _ProfileStub(), inproc_ttl_s=0.0)
    await calc.calculate(_ti())
    await calc.calculate(_ti())
    assert hist.calls == 2               # no L1 -> every call reads fresh (byte-identical to today)
