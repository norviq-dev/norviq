# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Read-only endpoints for Asset Graph and Attack Graph UI."""

from datetime import datetime, timedelta, timezone
from typing import cast
from uuid import uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin
from norviq.api.db.session import get_session
from norviq.api.synthetic import is_synthetic_identity
from norviq.api.schemas.graphs import (
    AssetEdge,
    AssetGraphResponse,
    AssetNode,
    AttackPath,
    AttackPathsResponse,
    AttackStep,
)

log = structlog.get_logger()
router = APIRouter(prefix="/api/v1", tags=["graphs"])
RANGE_HOURS = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}

# Managed policy scopes that are NOT deployed agents: the namespace baseline / sector-pack overlay rows
# (see policies.py RESERVED) and namespace-target rows. Excluded from the "deployed, awaiting first tool
# call" derivation — otherwise every namespace would show a phantom awaiting agent for its baseline row.
_RESERVED_AGENT_CLASSES = {"__baseline__", "__pack__"}
# "__cluster__" is the managed cluster-baseline scope; "all" is the console's wildcard sentinel.
_RESERVED_NAMESPACES = {"__cluster__", "all"}


def _safe_json(value: object) -> dict:
    return dict(value or {}) if isinstance(value, dict) else {}


def _resolve_namespaces(user: dict, requested: str) -> list[str] | None:
    """Resolve the caller's effective namespace set for a graph read. None = unrestricted (every namespace).

    Mirrors auth.scoped_namespace, extended to "all" and comma lists:
      - admin (or a "*" namespace claim, or a machine `service` principal with no claim) may read any
        namespace; "all" -> None (unrestricted).
      - a scoped caller reading "all" gets exactly its own namespace — never everyone else's.
      - a scoped caller naming any namespace outside its claim is refused (403, fail-closed), and the
        F-06 floor holds: a non-admin human with NO namespace claim gets no tenant data at all.
    """
    role = str(user.get("role", "")).lower()
    claim = str(user.get("namespace", "") or "")
    wanted = (
        None
        if requested.strip().lower() == "all"
        else [ns.strip() for ns in requested.split(",") if ns.strip()]
    )
    if role == "admin" or claim == "*" or (role == "service" and not claim):
        return wanted
    if not claim:
        raise HTTPException(status_code=403, detail="No namespace scope")
    if wanted is None:
        return [claim]
    for ns in wanted:
        if ns != claim:
            log.warning("nrvq.api.asset_graph.scope_denied", requested=ns, claim=claim, code="NRVQ-API-7052")
            raise HTTPException(status_code=403, detail="Not authorized for this namespace")
    return [claim]


async def _latest_snapshots(session: AsyncSession, namespaces: list[str] | None) -> list[tuple[str, dict]]:
    """The latest asset_graph snapshot per namespace: [(namespace, graph_json)]. None = every namespace."""
    if namespaces is None:
        rows = (
            await session.execute(
                text(
                    "SELECT DISTINCT ON (namespace) namespace, graph_json FROM asset_graph "
                    "ORDER BY namespace, built_at DESC"
                )
            )
        ).mappings().all()
    else:
        rows = (
            await session.execute(
                text(
                    "SELECT DISTINCT ON (namespace) namespace, graph_json FROM asset_graph "
                    "WHERE namespace = ANY(:nss) ORDER BY namespace, built_at DESC"
                ),
                {"nss": namespaces},
            )
        ).mappings().all()
    return [
        (str(r["namespace"]), r["graph_json"])
        for r in rows
        if isinstance(r.get("graph_json"), dict) and str(r["namespace"]) not in _RESERVED_NAMESPACES
    ]


async def _deployed_classes(session: AsyncSession, namespaces: list[str] | None) -> dict[str, set[str]]:
    """{namespace: {agent_class}} an operator has DEPLOYED protection for — from policy rows and the
    agent registry — regardless of observed traffic. Drives the "awaiting first tool call" state."""
    deployed: dict[str, set[str]] = {}
    for sql in (
        "SELECT DISTINCT namespace, agent_class FROM policies",
        "SELECT DISTINCT namespace, agent_class FROM agent_registry",
    ):
        if namespaces is None:
            rows = (await session.execute(text(sql))).mappings().all()
        else:
            rows = (
                await session.execute(text(f"{sql} WHERE namespace = ANY(:nss)"), {"nss": namespaces})
            ).mappings().all()
        for r in rows:
            ns, klass = str(r.get("namespace") or ""), str(r.get("agent_class") or "")
            if (
                not ns
                or not klass
                or ns in _RESERVED_NAMESPACES
                or klass in _RESERVED_AGENT_CLASSES
                or klass.startswith("namespace:")
            ):
                continue
            deployed.setdefault(ns, set()).add(klass)
    return deployed


async def _decision_counts(session: AsyncSession, namespace: str, since: datetime) -> dict[tuple[str, str], dict]:
    """Batched per-(agent_id, tool_name) allow/block/escalate counts for one namespace's range window.
    One query per namespace instead of one per edge (same values the per-edge lookup produced)."""
    rows = (
        await session.execute(
            text(
                """
                SELECT agent_id, tool_name,
                    COUNT(*) FILTER (WHERE decision = 'allow') AS allow_count,
                    COUNT(*) FILTER (WHERE decision = 'block') AS block_count,
                    COUNT(*) FILTER (WHERE decision = 'escalate') AS escalate_count,
                    COUNT(*) FILTER (WHERE decision = 'audit') AS would_block_count
                FROM audit_log
                WHERE namespace = :ns AND timestamp_utc >= :since
                GROUP BY agent_id, tool_name
                """
            ),
            {"ns": namespace, "since": since},
        )
    ).mappings().all()
    # 'audit' = a Monitor-mode would-block (the evaluator softens block/escalate → audit when a namespace is
    # in Monitor mode). Previously dropped from every bucket, so a Monitor namespace's graphs showed 0
    # blocked traffic and its edges looked inert. Surface it as `would_block` so the UI can render it.
    return {
        (str(r["agent_id"]), str(r["tool_name"])): {
            "allow": int(r.get("allow_count") or 0),
            "block": int(r.get("block_count") or 0),
            "escalate": int(r.get("escalate_count") or 0),
            "would_block": int(r.get("would_block_count") or 0),
        }
        for r in rows
    }


def _snapshot_to_assets(
    namespace: str,
    graph_json: dict,
    counts: dict[tuple[str, str], dict],
    *,
    prefix_ids: bool,
) -> tuple[list[AssetNode], list[AssetEdge], set[str]]:
    """Convert one namespace's snapshot into response nodes/edges (+ the observed agent classes).

    Every node is tagged with its namespace (properties.namespace) for per-namespace clustering/color
    in the console. In a multi-namespace union, ids are namespace-qualified ("{ns}::{id}") so tool/data
    ids that repeat across namespaces (e.g. tool:search_kb) don't collide between snapshots.
    """
    qualify = (lambda i: f"{namespace}::{i}") if prefix_ids else (lambda i: i)
    nodes: list[AssetNode] = []
    edges: list[AssetEdge] = []
    observed_classes: set[str] = set()
    for node in graph_json.get("nodes", []):
        if not isinstance(node, dict):
            continue
        node_id = str(node.get("id", ""))
        if not node_id:
            continue
        props = _safe_json(node.get("properties"))
        props["namespace"] = str(node.get("namespace") or "") or namespace
        node_type = str(node.get("type", "data"))
        name = str(node.get("name") or node.get("label") or node_id)
        if node_type == "agent":
            # Identity sub-grouping: one SPIFFE id may host several agent_classes (distinct chatbots on
            # one service account). Render each class as a distinguishable sub-node keyed (spiffe, class),
            # linked to a shared identity node — so they never collapse into one dot.
            classes = [str(c) for c in (props.get("agent_classes") or []) if c]
            for klass in classes:
                observed_classes.add(klass)
            if len(classes) > 1:
                props["spiffe_id"] = node_id
                nodes.append(
                    AssetNode(
                        id=qualify(node_id),
                        type="agent",
                        name=node_id.split("/")[-1],
                        properties={**props, "is_identity": True, "agent_class": ""},
                    )
                )
                for klass in classes:
                    nodes.append(
                        AssetNode(
                            id=qualify(f"{node_id}#{klass}"),
                            type="agent",
                            name=klass,
                            properties={**props, "agent_class": klass, "agent_classes": [klass], "spiffe_id": node_id},
                        )
                    )
                    # Structural link: sub-node belongs_to the shared SPIFFE identity (not a fabricated call).
                    edges.append(
                        AssetEdge(
                            source=qualify(f"{node_id}#{klass}"),
                            target=qualify(node_id),
                            type="belongs_to",
                            weight=1.0,
                            properties={"namespace": props["namespace"]},
                        )
                    )
                continue
            if props.get("agent_class"):
                observed_classes.add(str(props["agent_class"]))
        nodes.append(
            AssetNode(
                id=qualify(node_id),
                type=node_type,
                # Builder snapshots carry the display label under "label"; fall back to the raw id.
                name=name,
                properties=props,
            )
        )
    for edge in graph_json.get("edges", []):
        if not isinstance(edge, dict):
            continue
        source_id = str(edge.get("source", ""))
        target_id = str(edge.get("target", ""))
        if not source_id or not target_id:
            continue
        # Builder call-edges never carried "target_name" (so decision_history was always zeros) — derive
        # the tool from the canonical "tool:{name}" target id so edges get their REAL decision counts.
        tool_name = str(edge.get("target_name", "")) or (
            target_id.removeprefix("tool:") if target_id.startswith("tool:") else ""
        )
        props = _safe_json(edge.get("properties"))
        props["decision_history"] = counts.get(
            (source_id, tool_name), {"allow": 0, "block": 0, "escalate": 0}
        )
        edges.append(
            AssetEdge(
                source=qualify(source_id),
                target=qualify(target_id),
                type=str(edge.get("type", "calls")),
                weight=float(edge.get("weight") or 1.0),
                properties=props,
            )
        )
    return nodes, edges, observed_classes


def _awaiting_nodes(namespace: str, classes: set[str], *, prefix_ids: bool) -> list[AssetNode]:
    """Synthesize dimmed 'deployed, awaiting first tool call' agent nodes — never omitted silently."""
    qualify = (lambda i: f"{namespace}::{i}") if prefix_ids else (lambda i: i)
    return [
        AssetNode(
            id=qualify(f"awaiting:{klass}"),
            type="agent",
            name=klass,
            properties={"namespace": namespace, "agent_class": klass, "awaiting": True},
        )
        for klass in sorted(classes)
    ]


def _filter_synthetic_assets(nodes: list[AssetNode], edges: list[AssetEdge]) -> tuple[list[AssetNode], list[AssetEdge], int]:
    """A1: drop synthetic/probe AGENT nodes, their edges, and any tool/data node left orphaned (so no lone
    dots linger). Real agents — including quiet/awaiting ones — are always kept. Returns the filtered lists +
    the count of hidden synthetic agents (drives the 'N test/probe agents hidden — Show' chip)."""
    synthetic_ids = {
        n.id
        for n in nodes
        if n.type == "agent"
        and is_synthetic_identity(n.properties.get("agent_class"), n.properties.get("spiffe_id"), n.properties)
    }
    if not synthetic_ids:
        return nodes, edges, 0
    kept_edges = [e for e in edges if e.source not in synthetic_ids and e.target not in synthetic_ids]
    connected: set[str] = set()
    for e in kept_edges:
        connected.add(e.source)
        connected.add(e.target)
    kept_nodes = [
        n
        for n in nodes
        if n.id not in synthetic_ids and (n.type == "agent" or n.id in connected)
    ]
    return kept_nodes, kept_edges, len(synthetic_ids)


def _attach_source_capability(nodes: list[AssetNode], edges: list[AssetEdge]) -> None:
    """CAP-1: annotate each DATA node with the verb surface its source EXPOSES, classified against the
    REAL signals already in the graph. The observed/defended signal for a tool lives on the AGENT→TOOL
    ``calls`` edge (which carries the decision history), NOT the TOOL→DATA ``accesses`` edge (which has
    none), so we attribute a tool's traffic from its incoming calls edges and map it onto the source via
    the accesses edge:
      * observed  = the tool for that verb produced traffic (its calls history allow+block+escalate > 0)
      * granted   = the tool for that verb reaches the source (accesses edge exists) even if silent → dormant
      * defended  = policy acted on that tool at least once (calls history block/escalate > 0) → a rule guards it
    Attaches node.properties.capability = {source_class, findings[], worst}. Read-only enrichment; nodes
    whose source type isn't in the registry are left untouched. No fabricated data. Also tags each
    accesses-edge with its resolved verb so the UI can colour tool→data edges by operation."""
    from norviq.engine.capability import classify_source, source_type_of, worst_open_verb
    from norviq.engine.capability.source_registry import Verb, source_meta, verb_of_tool

    tool_name_by_id = {n.id: n.name for n in nodes if n.type == "tool"}
    data_node_by_id = {n.id: n for n in nodes if n.type == "data"}
    agent_class_by_id = {
        n.id: str(n.properties.get("agent_class") or "")
        for n in nodes
        if n.type == "agent" and n.properties.get("agent_class")
    }

    # A tool's observed/guarded posture AND its calling agent-classes from its INCOMING calls edges
    # (agent→tool carry the counts + the source agent's class). The agent-class is needed so a capability
    # finding can offer a one-click "defend for class X" policy — X is the class exercising the verb.
    tool_traffic: dict[str, dict[str, bool]] = {}
    tool_callers: dict[str, set[str]] = {}
    for e in edges:
        if e.type != "calls" or e.target not in tool_name_by_id:
            continue
        hist = e.properties.get("decision_history") or {}
        touched = int(hist.get("allow", 0)) + int(hist.get("block", 0)) + int(hist.get("escalate", 0))
        guarded = int(hist.get("block", 0)) + int(hist.get("escalate", 0)) > 0
        slot = tool_traffic.setdefault(e.target, {"touched": False, "guarded": False})
        slot["touched"] = slot["touched"] or touched > 0
        slot["guarded"] = slot["guarded"] or guarded
        klass = agent_class_by_id.get(e.source)
        if klass:
            tool_callers.setdefault(e.target, set()).add(klass)

    # data_id -> {verb -> {"granted","observed","defended", "classes": set[str]}}
    signals: dict[str, dict[Verb, dict[str, object]]] = {}
    for e in edges:
        if e.type != "accesses" or e.target not in data_node_by_id:
            continue
        data_node = data_node_by_id[e.target]
        stype = source_type_of(data_node.name)
        if not stype:
            continue
        tool = tool_name_by_id.get(e.source, "")
        verb = verb_of_tool(tool, stype)
        if verb == Verb.UNKNOWN:
            continue
        traffic = tool_traffic.get(e.source, {"touched": False, "guarded": False})
        slot = signals.setdefault(e.target, {}).setdefault(
            verb, {"granted": True, "observed": False, "defended": False, "classes": set()}
        )
        slot["observed"] = bool(slot["observed"]) or traffic["touched"]
        slot["defended"] = bool(slot["defended"]) or traffic["guarded"]
        cast(set, slot["classes"]).update(tool_callers.get(e.source, set()))
        # Tag the edge itself with its verb for per-operation edge colouring.
        e.properties["verb"] = verb.value

    for data_id, node in data_node_by_id.items():
        stype = source_type_of(node.name)
        meta = source_meta(stype) if stype else None
        if not meta:
            continue
        per_verb = signals.get(data_id, {})
        findings = classify_source(
            stype,
            granted_verbs={v for v, s in per_verb.items() if s["granted"]},
            observed_verbs={v for v, s in per_verb.items() if s["observed"]},
            defended_verbs={v for v, s in per_verb.items() if s["defended"]},
        )
        # Attach the agent-classes exercising each verb so the UI can target a "defend" action.
        finding_dicts = []
        for f in findings:
            d = f.as_dict()
            d["agent_classes"] = sorted(cast(set, per_verb.get(f.verb, {}).get("classes", set())))
            finding_dicts.append(d)
        worst = worst_open_verb(findings)
        worst_dict = None
        if worst:
            worst_dict = worst.as_dict()
            worst_dict["agent_classes"] = sorted(cast(set, per_verb.get(worst.verb, {}).get("classes", set())))
        node.properties["capability"] = {
            "source_type": stype,
            "source_class": meta["source_class"],
            "source_display": meta["display"],
            "findings": finding_dicts,
            "worst": worst_dict,
        }


@router.delete("/asset-graph/node")
async def remove_asset_graph_node(
    request: Request,
    namespace: str = Query(...),
    node_id: str = Query(...),
    user: dict = Depends(get_current_user),
) -> dict:
    """Admin HOUSEKEEPING: remove one node (and its incident edges) from a namespace's runtime asset
    graph — a decommissioned tool, a probe artifact, a junk identity. The graph is otherwise append-only
    (nodes persist until LRU-cap eviction), so without this an operator has no way to clean it up.
    Removes from the LIVE builder (restoring the persisted snapshot first if the pod just started) and
    saves — the save re-snapshots and invalidates the per-namespace analysis caches, so every graph
    surface reflects the removal immediately. Audited via the log line; graph-only (no audit rows,
    policies, or decisions are touched)."""
    require_admin(user)
    evaluator = getattr(request.app.state, "evaluator", None)
    store = getattr(request.app.state, "graph_store", None)
    if evaluator is None:
        raise HTTPException(status_code=503, detail="Graph engine is unavailable")
    # Work on the evaluator's live builder so in-memory state and the snapshot can't diverge; restore
    # the persisted snapshot first when this process hasn't touched the namespace yet.
    restore = getattr(evaluator, "_restore_graph", None)
    if restore is not None:
        await restore(namespace)
    graph = evaluator.get_graph(namespace)
    if not graph.remove_node(node_id):
        raise HTTPException(status_code=404, detail=f"node '{node_id}' not found in namespace '{namespace}'")
    if store is not None:
        await store.save(namespace, graph)
    log.info("nrvq.api.graph.node_removed", namespace=namespace, node_id=node_id,
             by=str(user.get("sub") or ""), code="NRVQ-API-7112")
    return {"removed": True, "namespace": namespace, "node_id": node_id,
            "nodes": graph.graph.number_of_nodes(), "edges": graph.graph.number_of_edges()}


@router.get("/asset-graph", response_model=AssetGraphResponse)
async def get_asset_graph(
    namespace: str = Query("default"),
    range: str = Query("24h"),
    include_synthetic: bool = Query(False),  # A1: default-hide seeded probe/test identities
    include_awaiting: bool = Query(False),   # A2: default-hide real-but-never-observed (awaiting) agents
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Return nodes + edges for a namespace, a comma list, or "all" (union of the caller's namespaces).

    Multi-namespace responses union the LATEST snapshot per namespace, tag every node with its
    namespace, and namespace-qualify ids. Namespaces whose agents are deployed (policy/registry) but
    have produced no observed traffic yet appear as dimmed "awaiting first tool call" agent nodes.
    Caller scoping is enforced server-side: a scoped viewer only ever receives its own namespace.
    """
    try:
        namespaces = _resolve_namespaces(user, namespace)
        hours = RANGE_HOURS.get(range, 24)
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        snapshots = await _latest_snapshots(session, namespaces)
        deployed = await _deployed_classes(session, namespaces)
        # A multi-namespace response (union or wildcard) namespace-qualifies ids; a single named
        # namespace keeps today's exact single-namespace shape.
        multi = namespaces is None or len(namespaces) != 1
        nodes: list[AssetNode] = []
        edges: list[AssetEdge] = []
        seen_namespaces: set[str] = set()
        for ns, graph_json in snapshots:
            counts = await _decision_counts(session, ns, since)
            ns_nodes, ns_edges, observed_classes = _snapshot_to_assets(
                ns, graph_json, counts, prefix_ids=multi
            )
            nodes.extend(ns_nodes)
            edges.extend(ns_edges)
            seen_namespaces.add(ns)
            # Deployed-but-silent classes in a namespace that HAS traffic (e.g. a second chatbot added later).
            nodes.extend(_awaiting_nodes(ns, deployed.get(ns, set()) - observed_classes, prefix_ids=multi))
        # Namespaces with deployed agents and NO snapshot at all (zero traffic ever) — the hr-bot case.
        for ns, classes in sorted(deployed.items()):
            if ns not in seen_namespaces:
                nodes.extend(_awaiting_nodes(ns, classes, prefix_ids=multi))
                seen_namespaces.add(ns)
        # A1: hide synthetic/probe agents by default; ?include_synthetic=true brings them back (the UI toggle).
        synthetic_hidden = 0
        if not include_synthetic:
            nodes, edges, synthetic_hidden = _filter_synthetic_assets(nodes, edges)
        # A2: hide real-but-awaiting agents by default (registered, never observed — noisy inline);
        # ?include_awaiting=true reveals them. Orthogonal to include_synthetic (composes independently).
        awaiting_hidden = 0
        if not include_awaiting:
            awaiting_ids = {n.id for n in nodes if n.type == "agent" and n.properties.get("awaiting")}
            if awaiting_ids:
                nodes = [n for n in nodes if n.id not in awaiting_ids]
                edges = [e for e in edges if e.source not in awaiting_ids and e.target not in awaiting_ids]
                awaiting_hidden = len(awaiting_ids)
        # CAP-1: enrich the (now filtered) data nodes with their source's verb-capability posture.
        _attach_source_capability(nodes, edges)
        log.info(
            "nrvq.api.asset_graph.served",
            namespace=namespace,
            resolved=sorted(seen_namespaces),
            range=range,
            node_count=len(nodes),
            edge_count=len(edges),
            synthetic_hidden=synthetic_hidden,
            awaiting_hidden=awaiting_hidden,
            code="NRVQ-API-7050",
        )
        return AssetGraphResponse(
            nodes=nodes, edges=edges, namespaces=sorted(seen_namespaces),
            synthetic_hidden=synthetic_hidden, awaiting_hidden=awaiting_hidden,
        )
    except HTTPException:
        raise
    except Exception as exc:
        import traceback

        tb = traceback.format_exc()
        log.error(
            "nrvq.api.asset_graph.error",
            error=str(exc),
            error_type=type(exc).__name__,
            traceback=tb,
            code="NRVQ-API-7050-ERR",
        )
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}")


@router.get("/attack-paths", response_model=AttackPathsResponse)
async def get_attack_paths(
    namespace: str = Query("default"),
    severity: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    _user: dict = Depends(get_current_user),
):
    """Return precomputed attack paths sorted by risk score plus referenced nodes."""
    # Scope the read to the caller's namespace(s) BEFORE the try (so the 403 propagates and is not swallowed into a
    # 500 by the broad except): a non-admin naming another tenant's namespace is refused, never served their attack
    # paths. Mirrors the asset-graph reads; admin/'*'/service-no-claim resolve unrestricted (None) or to exactly the
    # requested namespace.
    nss = _resolve_namespaces(_user, namespace)
    try:
        if nss is None:
            sql = "SELECT path_json, risk_score FROM attack_paths ORDER BY computed_at DESC LIMIT 200"
            params: dict = {}
        else:
            sql = ("SELECT path_json, risk_score FROM attack_paths "
                   "WHERE namespace = ANY(:nss) ORDER BY computed_at DESC LIMIT 200")
            params = {"nss": nss}
        rows = (await session.execute(text(sql), params)).mappings().all()
        paths: list[AttackPath] = []
        referenced_nodes: set[str] = set()
        for row in rows:
            path_json = row.get("path_json") or {}
            if not isinstance(path_json, dict):
                continue
            source_id = str(path_json.get("source_id", ""))
            target_id = str(path_json.get("target_id", ""))
            if not source_id or not target_id:
                continue
            steps = []
            for idx, step in enumerate(path_json.get("steps", []), start=1):
                if not isinstance(step, dict):
                    continue
                node_id = str(step.get("node_id") or step.get("node") or "")
                if node_id:
                    referenced_nodes.add(node_id)
                steps.append(
                    AttackStep(
                        step_num=int(step.get("step_num", idx)),
                        node_id=node_id,
                        action=str(step.get("action", step.get("tool", "traverse"))),
                        policy_check=str(step.get("policy_check", "no_policy")),
                    )
                )
            sev = str(path_json.get("severity", "medium"))
            if severity and sev != severity:
                continue
            risk = float(path_json.get("risk_score", row.get("risk_score") or 0.0))
            p = AttackPath(
                path_id=str(path_json.get("path_id", uuid4())),
                source_id=source_id,
                target_id=target_id,
                steps=steps,
                risk_score=risk,
                severity=sev,
                mitre_techniques=[str(v) for v in path_json.get("mitre_techniques", []) if isinstance(v, str)],
                blocked_by_policy=bool(path_json.get("blocked_by_policy", False)),
            )
            paths.append(p)
            referenced_nodes.add(source_id)
            referenced_nodes.add(target_id)
        paths.sort(key=lambda p: p.risk_score, reverse=True)
        nodes: list[AssetNode] = [
            AssetNode(id=node_id, type="data", name=node_id, properties={"namespace": namespace}) for node_id in sorted(referenced_nodes)
        ]
        log.info(
            "nrvq.api.attack_paths.served",
            namespace=namespace,
            path_count=len(paths),
            node_count=len(nodes),
            code="NRVQ-API-7051",
        )
        return AttackPathsResponse(paths=paths[:100], nodes=nodes)
    except Exception as exc:
        import traceback

        tb = traceback.format_exc()
        log.error(
            "nrvq.api.attack_paths.error",
            error=str(exc),
            error_type=type(exc).__name__,
            traceback=tb,
            code="NRVQ-API-7051-ERR",
        )
        raise HTTPException(status_code=500, detail=f"{type(exc).__name__}: {exc}")
