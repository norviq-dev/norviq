# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""In-process fan-out of live audit records to connected /ws/audit clients."""

import asyncio

from norviq.api.synthetic import is_synthetic_identity  # the ONE shared synthetic/probe classifier (do not fork)
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent


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

    def publish(self, record: dict) -> None:
        """Fan a record out to all subscribers; full queues drop the event."""
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(record)
            except asyncio.QueueFull:
                pass


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
