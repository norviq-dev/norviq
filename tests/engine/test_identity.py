# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for SPIFFEResolver."""

from __future__ import annotations

import asyncio

import pytest

from norviq.config import settings
from norviq.engine.identity import (
    SPIFFEResolver,
    SpiffeResolutionError,
    _parse_norviq_spiffe_id,
)


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


# --- B2: workload-api mode (real SPIFFE SVID), fail-closed + spoof-resistant ---


class _FakeSvid:
    def __init__(self, spiffe_id: str) -> None:
        self._id = spiffe_id

    @property
    def spiffe_id(self):  # X509Svid.spiffe_id is a property (str() gives the spiffe:// id)
        return self._id


class _FakeSource:
    """Stands in for a pyspiffe WorkloadApiClient (the `_svid_source` seam)."""

    def __init__(self, spiffe_id: str | None = None, exc: Exception | None = None) -> None:
        self._id = spiffe_id
        self._exc = exc
        self.closed = False

    def fetch_x509_svid(self) -> _FakeSvid:
        if self._exc is not None:
            raise self._exc
        return _FakeSvid(self._id)

    def close(self) -> None:
        self.closed = True


def test_parse_norviq_spiffe_id() -> None:
    """Only well-formed norviq-trust-domain ids parse; others reject (None)."""
    assert _parse_norviq_spiffe_id("spiffe://norviq/ns/payments/sa/agent-sa") == ("payments", "agent-sa")
    assert _parse_norviq_spiffe_id("spiffe://evil/ns/payments/sa/agent-sa") is None
    assert _parse_norviq_spiffe_id("spiffe://norviq/ns/payments") is None
    assert _parse_norviq_spiffe_id("spiffe://norviq/ns//sa/x") is None


async def test_workload_api_svid_wins_over_env_spoof(monkeypatch) -> None:
    """SECURITY: in workload-api mode the attested SVID wins; spoofed NRVQ_* env is ignored."""
    monkeypatch.setattr(settings, "spiffe_mode", "workload-api")
    monkeypatch.setenv("NRVQ_NAMESPACE", "attacker")          # spoof attempt
    monkeypatch.setenv("NRVQ_SERVICE_ACCOUNT", "evil")        # spoof attempt
    resolver = SPIFFEResolver()
    monkeypatch.setattr(resolver, "_svid_source", lambda: _FakeSource("spiffe://norviq/ns/payments/sa/agent-sa"))
    identity = await resolver.resolve()
    assert identity.namespace == "payments"          # from SVID, NOT the env
    assert identity.service_account == "agent-sa"
    assert identity.spiffe_id == "spiffe://norviq/ns/payments/sa/agent-sa"


async def test_workload_api_socket_failure_fails_closed(monkeypatch) -> None:
    """A Workload API failure must FAIL CLOSED (raise) — never the env-var 'unknown' fallback."""
    monkeypatch.setattr(settings, "spiffe_mode", "workload-api")
    resolver = SPIFFEResolver()
    monkeypatch.setattr(resolver, "_svid_source", lambda: _FakeSource(exc=OSError("socket gone")))
    with pytest.raises(SpiffeResolutionError):
        await resolver.resolve()


async def test_workload_api_wrong_trust_domain_fails_closed(monkeypatch) -> None:
    """An SVID outside the norviq trust domain fails closed (no silent acceptance)."""
    monkeypatch.setattr(settings, "spiffe_mode", "workload-api")
    resolver = SPIFFEResolver()
    monkeypatch.setattr(resolver, "_svid_source", lambda: _FakeSource("spiffe://evil/ns/x/sa/y"))
    with pytest.raises(SpiffeResolutionError):
        await resolver.resolve()


async def test_workload_api_missing_pyspiffe_fails_closed(monkeypatch) -> None:
    """Without the optional pyspiffe dep, workload-api mode fails closed (not a degraded identity)."""
    monkeypatch.setattr(settings, "spiffe_mode", "workload-api")
    monkeypatch.setattr("norviq.engine.identity._PYSPIFFE_AVAILABLE", False)
    with pytest.raises(SpiffeResolutionError):
        await SPIFFEResolver().resolve()


async def test_mock_mode_is_default_and_unchanged(monkeypatch) -> None:
    """Default mode stays 'mock' so existing tests / attack suite / local dev are untouched."""
    assert settings.spiffe_mode == "mock"
    monkeypatch.setenv("NRVQ_NAMESPACE", "team-x")
    identity = await SPIFFEResolver().resolve()
    assert identity.namespace == "team-x"  # env-var identity preserved in mock mode
