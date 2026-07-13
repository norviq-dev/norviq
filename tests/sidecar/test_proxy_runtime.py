from __future__ import annotations

import asyncio

import pytest

from norviq.sidecar.proxy import SidecarProxy


class _FakeServer:
    def close(self) -> None:
        return None

    async def wait_closed(self) -> None:
        return None


class _FakeCache:
    async def connect(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def list_policy_entries(self) -> dict[str, dict]:
        return {
            'policy:default:customer-support': {
                "rego": 'package norviq\ndefault decision = "block"\nrule_id = "r"\nreason = "x"',
                "priority": 900,
                "version": 1,
            }
        }

    async def listen_policy_events(self, handler) -> None:
        # Keep listener alive until proxy shutdown cancels it.
        while True:
            await asyncio.sleep(0.1)


class _FakeEmitter:
    async def init(self) -> None:
        return None

    async def close(self) -> None:
        return None


class _FakeResolver:
    async def resolve(self):
        raise RuntimeError("not used")


@pytest.mark.asyncio
async def test_sidecar_start_binds_loader_and_hydrates(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # SIDE-2: this exercises the EMBEDDED path (local loader/cache); pin the mode since proxy is now default.
    monkeypatch.setattr("norviq.sidecar.proxy.settings.sidecar_mode", "embedded")
    fake_cache = _FakeCache()

    monkeypatch.setattr("norviq.sidecar.proxy.RedisCache", lambda: fake_cache)
    monkeypatch.setattr("norviq.sidecar.proxy.AuditEmitter", _FakeEmitter)
    monkeypatch.setattr("norviq.sidecar.proxy.SPIFFEResolver", _FakeResolver)

    async def _fake_start_unix_server(handler, path):
        return _FakeServer()

    monkeypatch.setattr("norviq.sidecar.proxy.asyncio.start_unix_server", _fake_start_unix_server, raising=False)

    # H2/HA: PolicyLoader.warm_cache() is now DB-authoritative (reads the real `policies` table via its own
    # Postgres engine) rather than hydrating from cache.list_policy_entries() — _FakeCache's canned single
    # entry above is therefore never read by warm_cache() itself, and the row count on a real (shared, long-
    # lived local dev) Postgres is not something this pure-unit test controls or should depend on. Stub
    # warm_cache() to populate `_policies` the same way the real DB-authoritative load would, keeping this
    # test hermetic (no real Postgres) while still proving SidecarProxy wires + binds + warms the loader.
    async def _fake_warm_cache(self) -> None:
        self._policies["default:customer-support"] = {
            "rego": 'package norviq\ndefault decision = "block"\nrule_id = "r"\nreason = "x"',
            "priority": 900,
            "enforcement_mode": "block",
        }
        self._warmed = True

    monkeypatch.setattr("norviq.engine.policy_loader.PolicyLoader.warm_cache", _fake_warm_cache)

    proxy = SidecarProxy(socket_path=str(tmp_path / "nrvq.sock"))
    await proxy.start()
    try:
        assert proxy._loader is not None
        assert proxy._evaluator is not None
        assert proxy._evaluator._loader is proxy._loader
        assert proxy._loader.policy_count == 1
        assert "default:customer-support" in proxy._loader._policies
    finally:
        await proxy.stop()


@pytest.mark.asyncio
async def test_sidecar_start_proxy_mode_uses_remote_evaluator(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    # SIDE-2 default: proxy mode wires a RemoteEvaluator and NO local Redis/loader/emitter.
    from norviq.sidecar.remote_evaluator import RemoteEvaluator

    monkeypatch.setattr("norviq.sidecar.proxy.settings.sidecar_mode", "proxy")
    monkeypatch.setattr("norviq.sidecar.proxy.SPIFFEResolver", _FakeResolver)

    async def _fake_connect(self):
        return None

    monkeypatch.setattr("norviq.sidecar.remote_evaluator.RemoteEvaluator.connect", _fake_connect)

    async def _fake_start_unix_server(handler, path):
        return _FakeServer()

    monkeypatch.setattr("norviq.sidecar.proxy.asyncio.start_unix_server", _fake_start_unix_server, raising=False)

    proxy = SidecarProxy(socket_path=str(tmp_path / "nrvq.sock"))
    await proxy.start()
    try:
        assert isinstance(proxy._evaluator, RemoteEvaluator)
        assert proxy._loader is None
        assert proxy._cache is None
        assert proxy._emitter is None  # central /evaluate emits the audit record
    finally:
        await proxy.stop()
