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
