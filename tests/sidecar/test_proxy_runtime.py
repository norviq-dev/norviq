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
    fake_cache = _FakeCache()

    monkeypatch.setattr("norviq.sidecar.proxy.RedisCache", lambda: fake_cache)
    monkeypatch.setattr("norviq.sidecar.proxy.AuditEmitter", _FakeEmitter)
    monkeypatch.setattr("norviq.sidecar.proxy.SPIFFEResolver", _FakeResolver)

    async def _fake_start_unix_server(handler, path):
        return _FakeServer()

    monkeypatch.setattr("norviq.sidecar.proxy.asyncio.start_unix_server", _fake_start_unix_server, raising=False)

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
