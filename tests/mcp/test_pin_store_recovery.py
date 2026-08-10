# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A control-plane blip must not silence pin reporting forever.

`ControlPlanePinStore._degraded` was set on any load failure and never cleared, while `flush` returns
early whenever it is set. One transient 30-second outage therefore stopped this server reporting its
observed catalog PERMANENTLY: the MCP Servers page kept showing health "ok" with a stale last_seen_at,
and a later rug pull that the proxy detected locally was never surfaced. The outage was transient; the
silence was not, and nothing in the logs said so — every subsequent load logged success.
"""

from __future__ import annotations

import asyncio

from norviq.mcp.http import HttpProxy
from norviq.mcp.pins import ControlPlanePinStore


def _store() -> ControlPlanePinStore:
    return ControlPlanePinStore(api_url="http://control-plane.invalid", namespace="analytics",
                                server_id="srv-1", token="t")


async def test_load_failure_degrades(monkeypatch) -> None:
    s = _store()
    await s.load()  # unreachable host -> failure path
    assert s._degraded is True


async def test_a_successful_load_clears_the_latch(monkeypatch) -> None:
    """The recovery this never had: the load that succeeds is the evidence the control plane is back."""
    s = _store()
    s._degraded = True

    class _Resp:
        def raise_for_status(self): return None
        def json(self): return []

    class _Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **k): return _Resp()

    import httpx
    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: _Client())
    await s.load()
    assert s._degraded is False, "a successful load must clear the latch, or reporting stays silent"


async def test_flush_is_skipped_while_degraded_and_resumes_after(monkeypatch) -> None:
    s = _store()
    s._degraded = True
    s._pending = {"t1": {"name": "t1"}}
    await s.flush()          # must not raise, and must not report
    assert s._pending == {}  # cleared without sending, as before

    s._degraded = False
    assert s._degraded is False


# --- BUG-026: the TRANSPORT never retried either -----------------------------------------------------
#
# The latch above is one layer; this is the layer over it. `HttpProxy._install_pin_store` ran ONCE at
# startup, and on failure logged and returned — so a proxy that started while the control plane was
# briefly away held the local memory store for its entire process lifetime.
#
# Observed for real, and this is why it matters more than it sounds: three proxies ran eleven hours
# across several API rollouts, lost the control plane, and then refused every `tools/call` at Gate A.
# Nothing reached the engine, nothing reached the audit log, and the chat UI showed a red BLOCK badge
# — so a red-team run would have been scored as a defence that never happened. Restarting was the only
# cure and nothing anywhere said so.



def _proxy(monkeypatch) -> HttpProxy:
    monkeypatch.setattr("norviq.mcp.http.settings.mcp_pin_store", "control-plane", raising=False)
    monkeypatch.setattr("norviq.mcp.http.settings.mcp_pin_refresh_s", 0, raising=False)
    return HttpProxy(upstream="http://upstream/mcp", host="127.0.0.1", port=0, server_id="bug26")


async def test_a_failed_install_schedules_a_retry_instead_of_giving_up(monkeypatch) -> None:
    proxy = _proxy(monkeypatch)
    proxy._pin_store_kind = "control-plane"
    attempts = {"n": 0}

    async def never_works(self=None):
        attempts["n"] += 1
        return False

    monkeypatch.setattr(proxy, "_try_install_pin_store", never_works)
    await proxy._install_pin_store()
    assert attempts["n"] == 1, "the first attempt must still happen inline, before the listener binds"
    assert proxy._pin_retry_task is not None, "a failed install must leave a recovery loop running"
    proxy._pin_retry_task.cancel()


async def test_the_retry_installs_the_store_once_the_control_plane_returns(monkeypatch) -> None:
    proxy = _proxy(monkeypatch)
    proxy._pin_store_kind = "control-plane"
    calls = {"n": 0}

    async def works_on_the_third_try(self=None):
        calls["n"] += 1
        return calls["n"] >= 3

    monkeypatch.setattr(proxy, "_try_install_pin_store", works_on_the_third_try)
    await proxy._install_pin_store()
    assert proxy._pin_retry_task is not None
    await asyncio.wait_for(proxy._pin_retry_task, timeout=5)
    assert calls["n"] >= 3, "the loop must keep trying until the control plane answers"
    assert proxy._pin_retry_task.done()


async def test_the_recovery_loop_is_started_once_not_per_failure(monkeypatch) -> None:
    """Repeated failures must not fan out tasks — one degraded proxy, one retrier."""
    proxy = _proxy(monkeypatch)
    proxy._pin_store_kind = "control-plane"

    async def never_works(self=None):
        await asyncio.sleep(0.01)
        return False

    monkeypatch.setattr(proxy, "_try_install_pin_store", never_works)
    await proxy._install_pin_store()
    first = proxy._pin_retry_task
    proxy._schedule_pin_store_retry()
    proxy._schedule_pin_store_retry()
    assert proxy._pin_retry_task is first
    first.cancel()


async def test_a_local_store_kind_never_starts_a_retry(monkeypatch) -> None:
    """`memory`/`file` are already correct from __init__; a retry there would be pure noise."""
    proxy = _proxy(monkeypatch)
    proxy._pin_store_kind = "memory"
    await proxy._install_pin_store()
    assert proxy._pin_retry_task is None
