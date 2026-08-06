# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A revoke has to reach a RUNNING proxy, not only the next one to start.

`ControlPlanePinStore.load()` was awaited ONCE at startup and never again. POST /mcp/pins/revoke sets
`approved=False` on the DB row, the console shows the pin quarantined, and the endpoint's docstring
promises the tool is "withheld from the model until re-approved" — but the proxy holding the startup
copy kept returning PIN_OK, so the tool stayed listed to the model and stayed callable until the pod
restarted. That is exactly the situation an operator reaches for revoke to stop.
"""

from __future__ import annotations

import asyncio

import pytest

from norviq.mcp.pins import ControlPlanePinStore, ToolPin

pytestmark = pytest.mark.asyncio


def _store() -> ControlPlanePinStore:
    return ControlPlanePinStore(namespace="payments", server_id="srv", api_url="http://api", token="t")


async def test_start_refresh_re_reads_the_control_plane() -> None:
    """FAIL-ON-BUG: without the refresh the process holds its startup copy forever."""
    store = _store()
    loads = 0

    async def _fake_load() -> None:
        nonlocal loads
        loads += 1

    store.load = _fake_load  # type: ignore[method-assign]
    store.start_refresh(1)
    try:
        await asyncio.sleep(2.4)
        assert loads >= 2, f"expected repeated reloads, saw {loads}"
    finally:
        await store.aclose()


async def test_a_revoked_pin_stops_being_approved_after_a_refresh() -> None:
    """The observable end of it: the in-memory verdict has to change, not just the DB row."""
    store = _store()
    store._pins = {"srv/send_email": ToolPin(pin="srv/send_email", server_id="srv", tool_name="send_email", digest="d", first_seen_at=0.0, approved=True)}

    async def _reload_as_revoked() -> None:
        store._pins = {"srv/send_email": ToolPin(pin="srv/send_email", server_id="srv", tool_name="send_email", digest="d", first_seen_at=0.0, approved=False)}

    store.load = _reload_as_revoked  # type: ignore[method-assign]
    assert store.get("srv/send_email").approved is True
    store.start_refresh(1)
    try:
        await asyncio.sleep(1.4)
        assert store.get("srv/send_email").approved is False, "the revoke never reached the proxy"
    finally:
        await store.aclose()


async def test_refresh_is_opt_out_and_idempotent() -> None:
    """0 disables it (an operator may not want the poll), and starting twice must not leak a task."""
    store = _store()
    store.start_refresh(0)
    assert store._refresh_task is None
    store.start_refresh(30)
    first = store._refresh_task
    store.start_refresh(30)
    assert store._refresh_task is first, "a second start must not spawn a second loop"
    await store.aclose()
    assert store._refresh_task is None


async def test_aclose_is_safe_without_a_refresh() -> None:
    store = _store()
    await store.aclose()
    await store.aclose()
