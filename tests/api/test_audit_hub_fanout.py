# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The live Audit Log must show decisions made by OTHER API processes.

`AuditHub` is per-process, and the API runs `api.workers: 4` across `api.replicas: 2` by default —
eight independent processes. A browser's /ws/audit socket is served by one of them; a tool call is
evaluated by whichever the load balancer picked. So the live Audit Log showed roughly one decision in
eight, and nothing on screen said the rest existed.

This was found by fixing what looked like a flaky test. Measured against a live cluster:
`NRVQ_API_WORKERS=4` delivered the broadcast on about 1 run in 5; `NRVQ_API_WORKERS=1` delivered it
5 times out of 5. The flake was the product telling the truth.
"""

from __future__ import annotations

import asyncio

import pytest

from norviq.api import audit_hub as hubmod
from norviq.api.audit_hub import AuditHub, bind_peer_publisher


@pytest.fixture(autouse=True)
def _unbind():
    yield
    bind_peer_publisher(None)


def test_local_delivery_is_synchronous_and_unconditional() -> None:
    """The caller's own subscribers must never wait on Redis, and must still work with no peer wiring."""
    hub = AuditHub()
    q = hub.subscribe()
    hub.publish({"tool_name": "search_kb"})
    assert q.qsize() == 1


async def test_publish_also_fans_out_to_peers() -> None:
    sent: list[tuple[dict, str]] = []

    async def fake_peer(record, origin):
        sent.append((record, origin))

    bind_peer_publisher(fake_peer)
    hub = AuditHub()
    q = hub.subscribe()
    hub.publish({"tool_name": "send_email"})

    assert q.qsize() == 1, "local delivery must still happen"
    await asyncio.sleep(0)  # let the fire-and-forget task run
    await asyncio.sleep(0)
    assert len(sent) == 1, "the record was not published to peer processes"
    assert sent[0][0]["tool_name"] == "send_email"
    assert sent[0][1] == hubmod._ORIGIN


async def test_a_peer_record_reaches_local_subscribers() -> None:
    hub = AuditHub()
    q = hub.subscribe()
    await hub.deliver_from_peer({"tool_name": "from_other_worker"}, origin="some-other-process")
    assert q.qsize() == 1
    assert (await q.get())["tool_name"] == "from_other_worker"


async def test_our_own_echo_is_not_redelivered() -> None:
    """Redis delivers to every subscriber including the publisher, which already fanned out locally.
    Without the origin check every record would appear twice in the operator's live feed."""
    hub = AuditHub()
    q = hub.subscribe()
    await hub.deliver_from_peer({"tool_name": "echo"}, origin=hubmod._ORIGIN)
    assert q.qsize() == 0


async def test_a_peer_publish_failure_never_loses_the_local_record() -> None:
    """A Redis outage must degrade to the old single-process behaviour, not drop the record."""
    async def exploding_peer(record, origin):
        raise RuntimeError("redis down")

    bind_peer_publisher(exploding_peer)
    hub = AuditHub()
    q = hub.subscribe()
    hub.publish({"tool_name": "still_local"})
    assert q.qsize() == 1
    await asyncio.sleep(0)
    await asyncio.sleep(0)


def test_the_startup_path_binds_and_listens() -> None:
    """Guard the wiring: the hub API is useless if lifespan never connects it."""
    import inspect

    from norviq.api import main

    src = inspect.getsource(main)
    assert "bind_peer_publisher(app.state.cache.publish_audit_record)" in src
    assert "listen_audit_records" in src
