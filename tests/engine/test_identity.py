# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for SPIFFEResolver."""

from __future__ import annotations

import asyncio

from norviq.engine.identity import SPIFFEResolver


async def test_resolve_returns_identity_from_env(monkeypatch) -> None:
    """Resolver should map NRVQ environment variables into identity."""
    monkeypatch.setenv("NRVQ_NAMESPACE", "payments")
    monkeypatch.setenv("NRVQ_SERVICE_ACCOUNT", "agent-sa")
    monkeypatch.setenv("NRVQ_AGENT_CLASS", "planner")
    monkeypatch.setenv("HOSTNAME", "pod-1")
    identity = await SPIFFEResolver().resolve()
    assert identity.spiffe_id == "spiffe://norviq/ns/payments/sa/agent-sa"
    assert identity.namespace == "payments"
    assert identity.service_account == "agent-sa"
    assert identity.agent_class == "planner"
    assert identity.pod_name == "pod-1"


async def test_second_resolve_hits_cache_and_logs_code(monkeypatch) -> None:
    """Second resolve should hit cache and emit cache-hit code."""
    events: list[dict] = []

    class _Logger:
        def debug(self, _: str, **kwargs) -> None:
            events.append(kwargs)

        def info(self, _: str, **kwargs) -> None:
            events.append(kwargs)

        def error(self, _: str, **kwargs) -> None:
            events.append(kwargs)

        def warning(self, _: str, **kwargs) -> None:
            events.append(kwargs)

    resolver = SPIFFEResolver()
    monkeypatch.setattr("norviq.engine.identity.log", _Logger())
    first = await resolver.resolve()
    second = await resolver.resolve()
    assert first.spiffe_id == second.spiffe_id
    assert any(event.get("code") == "NRVQ-IDT-10001" for event in events)


async def test_fallback_identity_on_resolution_failure(monkeypatch) -> None:
    """Resolver should return fallback identity when mock resolution fails."""
    resolver = SPIFFEResolver()
    monkeypatch.setattr(resolver, "_mock_resolve", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    identity = await resolver.resolve()
    assert identity.spiffe_id == "spiffe://norviq/ns/unknown/sa/unknown"
    assert identity.namespace == "unknown"


async def test_clear_cache_removes_cached_identity() -> None:
    """clear_cache should remove all cached entries."""
    resolver = SPIFFEResolver()
    await resolver.resolve()
    assert resolver._get_cached() is not None
    resolver.clear_cache()
    assert resolver._get_cached() is None


async def test_concurrent_resolve_only_resolves_once(monkeypatch) -> None:
    """Concurrent resolves should share one socket resolution."""
    resolver = SPIFFEResolver()
    calls = {"count": 0}

    async def fake_resolve():
        calls["count"] += 1
        await asyncio.sleep(0.01)
        return resolver._mock_resolve()

    monkeypatch.setattr(resolver, "_resolve_from_socket", fake_resolve)
    identities = await asyncio.gather(*(resolver.resolve() for _ in range(12)))
    assert calls["count"] == 1
    assert len({identity.spiffe_id for identity in identities}) == 1
