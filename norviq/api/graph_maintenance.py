# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""One implementation of "take this node out of the runtime asset graph".

Two endpoints need it and used to have only one of them: `DELETE /asset-graph/node` (explicit graph
housekeeping) and `DELETE /agents/{spiffe_id}` (deregistering a decommissioned identity).

The agent path was the broken one. `get_asset_graph` serves the union of a PERSISTED `asset_graph`
snapshot and the classes that are merely deployed (registry/policy), the latter rendered as dimmed
"awaiting first tool call" nodes. Deregistering deleted the registry row and nothing else, so:

  * an agent that had NEVER been observed vanished  — its node came from the registry, and
  * an agent that HAD been observed stayed on the graph — its node is baked into the snapshot,

while both returned ``{"deleted": true}``. The second case is the one that matters, because an agent
worth decommissioning is usually one that ran. The deregister docstring states its own purpose as
stopping an agent surfacing "as a phantom 'awaiting' node on the asset graph", so an operator had
every reason to read that success as "it is gone from the console" when it was still there.

Kept in its own module rather than imported router-to-router so `agents.py` and `graphs.py` share the
behaviour without importing each other.
"""

from __future__ import annotations

import structlog

log = structlog.get_logger()


async def remove_graph_node(request, namespace: str, node_id: str) -> bool:
    """Remove ``node_id`` and its incident edges from ``namespace``'s runtime asset graph.

    Returns True when a node was actually removed, False when the graph engine is unavailable or the
    node was not in the graph. Callers must report that answer rather than assume success — claiming a
    removal that did not happen is the defect this module exists to close.

    Operates on the evaluator's LIVE builder so in-memory state and the snapshot cannot diverge, and
    restores the persisted snapshot first when this process has not touched the namespace yet. The
    subsequent ``store.save`` re-snapshots and invalidates the per-namespace analysis caches, so every
    graph surface reflects the removal immediately.
    """
    evaluator = getattr(request.app.state, "evaluator", None)
    store = getattr(request.app.state, "graph_store", None)
    if evaluator is None:
        return False
    restore = getattr(evaluator, "_restore_graph", None)
    if restore is not None:
        await restore(namespace)
    graph = evaluator.get_graph(namespace)
    if not graph.remove_node(node_id):
        return False
    if store is not None:
        await store.save(namespace, graph)
    return True


async def try_remove_graph_node(request, namespace: str, node_id: str) -> bool:
    """Best-effort ``remove_graph_node`` for callers whose primary work has already been committed.

    Deregistration deletes the registry row first; if the graph prune then fails there is nothing to
    roll back, and failing the request would report the whole operation as unsuccessful when the row
    really is gone. So swallow the error, log it, and return False — the caller surfaces that False to
    the operator instead of a blanket success.
    """
    try:
        return await remove_graph_node(request, namespace, node_id)
    except Exception as exc:  # noqa: BLE001 - see docstring: the registry row is already committed
        log.warning("nrvq.api.graph.node_prune_failed", namespace=namespace, node_id=node_id,
                    error=str(exc), code="NRVQ-API-7122")
        return False
