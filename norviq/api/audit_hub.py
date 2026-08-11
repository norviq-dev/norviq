# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""In-process fan-out of live audit records to connected /ws/audit clients."""

import asyncio
import os
import uuid

import structlog

from norviq.api.synthetic import is_synthetic_identity  # the ONE shared synthetic/probe classifier (do not fork)
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent


# Identifies THIS process in the pub/sub stream, so a subscriber can skip the echo of its own publish
# (Redis delivers to every subscriber, including the publisher, which has already fanned out locally).
_ORIGIN = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"

# Set at startup when a cache is available; None keeps the hub single-process, which is what every unit
# test and any Redis-less deployment gets.
_peer_publisher = None


def bind_peer_publisher(publisher) -> None:
    """Wire the cross-process fan-out. `publisher(record, origin)` is awaited off the hot path."""
    global _peer_publisher
    _peer_publisher = publisher


log = structlog.get_logger()


class AuditHub:
    """Broadcasts each evaluated decision to all connected audit websocket subscribers.

    In-process only (single API worker); each subscriber gets a bounded queue so a slow
    client drops events instead of blocking the hot path.
    """

    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        """Register a subscriber and return its queue."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        """Remove a subscriber."""
        self._subscribers.discard(queue)

    def publish_local(self, record: dict) -> None:
        """Fan a record to THIS process's subscribers only; full queues drop the event."""
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(record)
            except asyncio.QueueFull:
                pass

    def publish(self, record: dict) -> None:
        """Fan a record to this process's subscribers AND to every peer API process.

        The hub is per-process, and the API runs `api.workers: 4` across `api.replicas: 2` by default —
        eight independent processes. A browser's /ws/audit socket lives in one of them; a tool call is
        evaluated by whichever the load balancer chose. So the live Audit Log showed roughly one
        decision in eight, with nothing on screen to say the rest were missing. Measured on a live
        cluster: with workers=4 the broadcast arrived for about 1 run in 5; with workers=1 it arrived
        5 times out of 5.

        Local delivery stays SYNCHRONOUS and first — the caller's own subscribers must not wait on
        Redis, and a Redis outage must degrade this to the old single-process behaviour rather than
        losing the record entirely. The cross-process hop is fire-and-forget.
        """
        self.publish_local(record)
        pub = _peer_publisher
        if pub is None:
            return
        try:
            asyncio.get_running_loop().create_task(pub(record, _ORIGIN))
        except RuntimeError:
            # No running loop — a synchronous caller (unit tests, a management script). Local delivery
            # above already happened, so nothing is lost; only the cross-process hop is skipped. Logged
            # rather than swallowed because in the SERVER this branch should be unreachable, and if it
            # ever fires there it means live records are silently staying on one worker again.
            log.debug("nrvq.audit_hub.peer_publish_skipped", reason="no_running_loop",
                      code="NRVQ-API-7103")

    async def deliver_from_peer(self, record: dict, origin: str) -> None:
        """Handle a record published by another process. Skips our own echo."""
        if origin == _ORIGIN:
            return
        self.publish_local(record)


def audit_record(event: ToolCallEvent, decision: PolicyDecision) -> dict:
    """Shape an event+decision into the record the UI audit feed consumes.

    `framework` and `non_real` exist because the Audit Log's live tail has to apply the SAME
    real-traffic-only predicate the server applies to fetched rows. It carried neither field, so the
    client's `framework === "redteam"` test compared `undefined` and never matched: with "Real traffic
    only" switched ON, red-team and probe rows still streamed into the tail. `framework` also backs the
    Source column, which was blank on streamed rows for the same reason.

    `non_real` is computed HERE, by the one shared classifier, rather than mirroring the synthetic
    class-name prefixes into TypeScript — a forked copy of that list would drift the moment a prefix is
    added on either side, and drift here means test traffic silently reappearing in a filtered audit view.
    """
    identity = event.agent_identity
    return {
        "id": event.event_id,
        "timestamp": event.timestamp_utc.isoformat(),
        "tool_name": event.tool_name,
        "decision": decision.decision,
        "rule_id": decision.rule_id,
        "namespace": identity.namespace,
        "agent_id": identity.spiffe_id,
        "agent_class": identity.agent_class,
        "reason": decision.reason,
        "session_id": event.session_id,
        "latency_ms": decision.latency_ms,
        "trust_score": decision.trust_score,
        # Decision source (sidecar / sdk / redteam / ...) — Source column + the red-team half of the filter.
        "framework": event.framework or "",
        # Server-side verdict of the SAME predicate audit_row_is_non_real applies to fetched rows:
        # red-team framework OR a synthetic/probe agent class.
        "non_real": (event.framework or "") == "redteam" or is_synthetic_identity(
            identity.agent_class, identity.spiffe_id
        ),
    }
