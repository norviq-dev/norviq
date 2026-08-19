# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Attack Graph endpoints (feat/attack-graph): enriched kill-chains + positive-security intent coverage.

Three endpoints, all additive and namespace-scoped (they reuse the asset-graph helpers so ``ns=all``,
tenant scoping, and real audit decision-history come for free):

  GET  /api/v1/threats/attack-paths     — enriched kill-chains for the ranked list + d3 canvas + inspector.
  POST /api/v1/threats/intent-coverage  — generate a default-deny intent policy and dry-run it against the
                                          current paths (n/total denied + residual). Eval-only, no persistence.
  POST /api/v1/threats/intent-draft      — validate + persist a DRY-RUN DRAFT (in the dedicated ``intent_drafts``
                                          table, never read by the evaluator) and deep-link to Policies for the
                                          operator to review/apply. It NEVER enforces on its own.
  GET  /api/v1/threats/intent-drafts     — list pending drafts (so the Policies page can surface + apply them).
  GET  /api/v1/threats/intent-suggest    — suggest the intended allowlist (tools the class actually calls).

Security (auditor): coverage/draft generation is dry-run/eval only. A draft is deliberately NOT written to
the ``policies`` table — the evaluator lazy-loads any policy row for a real agent_class (no draft flag), so a
persisted row WOULD enforce. Drafts therefore live in a separate ``intent_drafts`` table (which the evaluator's
``_collect_candidates`` never queries); enforcement happens only when an operator explicitly creates+applies the
rego in Policies (the existing gated flow). The draft's priority == the namespace comprehensive
baseline priority, so an applied draft stays tighten-only under ``_resolve_precedence``'s most-restrictive tie-break.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import cast

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin, require_target_cluster
from norviq.api.db.models import IntentDraft, McpServer
from norviq.api.db.session import get_session
from norviq.api.retention import draft_expiry, enforce_draft_cap, gc_expired_drafts
from norviq.api.synthetic import is_synthetic_identity
from norviq.config import settings
from norviq.api.routers.graphs import (
    RANGE_HOURS,
    _decision_counts,
    _latest_snapshots,
    _resolve_namespaces,
    _snapshot_to_assets,
)
from norviq.api.schemas.threats import (
    IntentCoverageRequest,
    IntentCoverageResponse,
    IntentDraftPage,
    IntentDraftRequest,
    IntentDraftResponse,
    IntentDraftSummary,
    IntentSuggestResponse,
    IntentSuggestTool,
    ReachAsset,
    ThreatPath,
    ThreatPathsResponse,
    ThreatStep,
)
from norviq.api.threat_intent import (
    EGRESS_TOOLS,
    Intent,
    generate_capability_rego,
    generate_intent_rego,
    mitre_for_tool,
    opa_input_for_step,
    recommended_fix,
)
from norviq.engine.capability import (
    Verb,
    classify_tool,
    default_risk_of_verb,
    defense_meta,
    mutating_verbs_of,
    source_type_of,
    verb_fragments,
    verb_of_tool,
    verb_risk,
)

log = structlog.get_logger()
router = APIRouter(prefix="/api/v1", tags=["threats"])

# Per-chokepoint fan-out bound: a single tool that reaches many data targets contributes at most this
# many kill-chains, so a high-fan-out tool (execute_sql -> N tables) can never crowd a sibling
# destructive tool-terminal (delete_record) out of the ranked view.
_MAX_CHAINS_PER_CHOKEPOINT = 3
# Distinct chokepoints (tools) represented per agent. Visited worst-risk-first, so when an agent has
# more reachable tools than this, the most dangerous ones are the ones kept — never dropped by
# arbitrary graph-iteration order.
_MAX_CHOKEPOINTS_PER_AGENT = 16
_MAX_PATHS = 200
# How many of those slots a NON-AGENT origin may take.
#
# `input.mcp.server` is PEP-reported and unvalidated, so an agent that can call /evaluate chooses the
# server names that become graph nodes — and every one of them is a path origin now. Measured: 300
# fabricated servers pushed all five real agent kill-chains out of the 200-path view. The cap ranks
# before truncating, so this was not "the worst findings survive"; it was "the worst findings are
# whatever the attacker minted most of".
#
# A sub-cap rather than a smaller total: MCP origins are real findings and must still be shown, they
# simply cannot be allowed to occupy the budget reserved for the agent estate. `non_agent_paths` on
# the response reports the true count, so a truncated view still states its own size.
_MAX_NON_AGENT_PATHS = 40
_MAX_DEPTH = 4
_RESERVED_CLASSES = {"__baseline__", "__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__"}
_SENSITIVE = {"critical", "high"}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_STATUS_ORDER = {"exploitable": 0, "unsimulated": 1, "blocked": 2}
# RiskLevel.value -> rank; higher is more dangerous. Orders an agent's chokepoints so a destructive
# tool outranks a read when the per-agent chokepoint budget truncates.
_RISK_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _severity_from(risk: float) -> str:
    if risk >= 0.75:
        return "critical"
    if risk >= 0.5:
        return "high"
    if risk >= 0.25:
        return "medium"
    return "low"


def _dec_from_counts(allow: int, block: int) -> str:
    if block > 0 and allow == 0:
        return "block"
    if block > 0:
        return "mixed"
    return "allow"


def _short_id(*parts: str) -> str:
    # Non-security: a stable, collision-tolerant display/id token for a derived path/draft — not a
    # credential or integrity check (usedforsecurity=False so SAST + the runtime treat it as such).
    return "p" + hashlib.sha1("|".join(parts).encode(), usedforsecurity=False).hexdigest()[:10]


async def _assemble(session: AsyncSession, namespaces: list[str] | None, hours: int = 24):
    """Union the latest asset-graph snapshot(s) into nodes/edges with real decision history (like
    get_asset_graph). Returns (nodes_by_id, out_edges, seen_namespaces).

    `hours` is the DECISION-HISTORY window and must come from the caller's `range`. It used to be
    hardcoded to 24 here while /threats/attack-paths discarded its own `range` into `_`, each site
    commenting that the OTHER one handled it — so selecting 7d or 30d changed nothing and any chain
    whose only decisions were older than 24h rendered "unsimulated" (no history) even though the
    history existed inside the range the user asked for.
    """
    snapshots = await _latest_snapshots(session, namespaces)
    multi = namespaces is None or len(namespaces) != 1
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    nodes_by_id: dict[str, dict] = {}
    out_edges: dict[str, list[dict]] = {}
    seen: set[str] = set()
    for ns, graph_json in snapshots:
        counts = await _decision_counts(session, ns, since)
        ns_nodes, ns_edges, _ = _snapshot_to_assets(ns, graph_json, counts, prefix_ids=multi)
        for n in ns_nodes:
            nodes_by_id[n.id] = {
                "id": n.id,
                "type": n.type,
                "name": n.name,
                "props": dict(n.properties or {}),
            }
        for e in ns_edges:
            if e.type == "belongs_to":
                continue
            out_edges.setdefault(e.source, []).append(
                {"target": e.target, "type": e.type, "hist": dict((e.properties or {}).get("decision_history") or {})}
            )
        seen.add(ns)
    return nodes_by_id, out_edges, sorted(seen)


def _is_source_agent(node: dict) -> bool:
    return (
        node["type"] == "agent"
        and not node["props"].get("is_identity")
        and not node["props"].get("awaiting")
        and bool(node["props"].get("agent_class"))
    )


#: Node types that can START a kill-chain, and what the path reports as its origin kind.
#:
#: An MCP server is an origin because the question "if this server were compromised, what does it
#: reach" is the one the registry work makes askable, and it is not answerable from any agent's row:
#: a poisoned definition steers whichever agent happens to be connected, so the blast radius belongs
#: to the SERVER. The `serves` edge (server -> tool) added with the graph node is what makes the walk
#: possible, and it points the same way the traversal already goes.
_ORIGIN_KINDS = ("agent", "mcp_server")


def _origin_kind(node: dict) -> str:
    """The path-origin kind for a node, or "" if it cannot start a path.

    Deliberately NOT a widening of `_is_source_agent`. That predicate has four conjuncts and three of
    them encode real properties of AGENTS — an identity super-node has no outgoing edges, an awaiting
    agent has made no calls, and a class-less agent cannot be governed by an agent-class policy.
    Loosening them to admit a different kind of node would have quietly changed what counts as an
    agent origin too. An MCP server answers to none of those, so it gets its own arm.
    """
    if _is_source_agent(node):
        return "agent"
    if node["type"] == "mcp_server":
        return "mcp_server"
    return ""


def _node_sensitive(node: dict) -> bool:
    if node["type"] == "data":
        return True
    sens = str(node["props"].get("sensitivity") or node["props"].get("risk_level") or "").lower()
    return sens in _SENSITIVE


def _reachable(source: str, out_edges: dict[str, list[dict]]) -> set[str]:
    seen: set[str] = set()
    stack = [source]
    while stack:
        cur = stack.pop()
        for e in out_edges.get(cur, []):
            t = e["target"]
            if t not in seen:
                seen.add(t)
                stack.append(t)
    return seen


def _chokepoint_risk_rank(tool_id: str, nodes_by_id: dict[str, dict]) -> int:
    """Higher = more dangerous. Orders an agent's chokepoints so a destructive tool (delete/exec)
    survives per-agent truncation ahead of a read — a security operator must never lose sight of the
    worst reachable tool because a benign one was walked first."""
    name = (nodes_by_id.get(tool_id) or {}).get("name") or tool_id.split(":", 1)[-1]
    _verb, risk = classify_tool(name)
    return _RISK_RANK.get(getattr(risk, "value", ""), 0)


def _walk_paths(source: str, out_edges: dict[str, list[dict]], nodes_by_id: dict[str, dict]) -> list[list[str]]:
    """DFS simple kill-chains from an agent to a data node (or a terminal tool), depth <= _MAX_DEPTH.

    Every DISTINCT first-hop chokepoint (a tool the agent can reach) is walked under its OWN fan-out
    budget (`_MAX_CHAINS_PER_CHOKEPOINT`), so a high-fan-out tool (execute_sql -> many data targets)
    can never consume a shared per-agent budget and starve a sibling destructive tool-terminal
    (delete_record) out of the ranked kill-chain.

    A destructive chokepoint is NEVER capped away. A class node here is the UNION of every same-class
    identity's tools, so a busy tenant can expose 20+ high/critical chokepoints; a flat per-agent cap
    would silently hide a reachable delete/exec tool (e.g. delete_record) behind its siblings — exactly
    what a security graph must not do. So we keep EVERY high/critical-risk chokepoint and only cap the
    lower-risk tail (reads an operator can safely see fewer of).
    """
    out: list[list[str]] = []
    first_hops = [
        e["target"] for e in out_edges.get(source, []) if e["target"] in nodes_by_id and e["target"] != source
    ]
    # de-dup preserving first appearance, then order worst-risk-first
    ranked = sorted(dict.fromkeys(first_hops), key=lambda t: -_chokepoint_risk_rank(t, nodes_by_id))
    high = [t for t in ranked if _chokepoint_risk_rank(t, nodes_by_id) >= _RISK_RANK["high"]]
    low = [t for t in ranked if _chokepoint_risk_rank(t, nodes_by_id) < _RISK_RANK["high"]]
    # keep ALL destructive chokepoints; fill the remaining budget with the low-risk tail
    ordered_tools = high + low[: max(0, _MAX_CHOKEPOINTS_PER_AGENT - len(high))]

    def _chains_through(tool: str) -> list[list[str]]:
        local: list[list[str]] = []

        def dfs(node: str, path: list[str]) -> None:
            if len(local) >= _MAX_CHAINS_PER_CHOKEPOINT or len(path) > _MAX_DEPTH + 1:
                return
            nxt = out_edges.get(node, [])
            terminal = nodes_by_id.get(node, {}).get("type") == "data"
            if (terminal or not nxt) and len(path) >= 2:
                local.append(list(path))
                return
            for e in nxt:
                t = e["target"]
                if t in path or t not in nodes_by_id:  # no cycles / unknown nodes
                    continue
                path.append(t)
                dfs(t, path)
                path.pop()
                if len(local) >= _MAX_CHAINS_PER_CHOKEPOINT:
                    return

        dfs(tool, [source, tool])
        return local

    for tool in ordered_tools:
        out.extend(_chains_through(tool))
    return out


#: Origin risk for a non-agent origin, in the same 0..1 units as `1.0 - trust`.
#:
#: These are the registry states an operator sets on the MCP Servers page, so the number the Attack
#: Graph shows moves when they make a decision — which is the point. An unreviewed server is the
#: highest because "nobody has looked at this" is the state the whole registry exists to distinguish
#: from "looked at and fine"; the same reasoning that makes Gate A report `scan_severity: "unknown"`
#: rather than `"none"`.
#:
#: `blocked` is NOT the maximum. A blocked server's tools are withheld at discovery, so the path is
#: real topology that enforcement already covers — ranking it above the servers nobody has reviewed
#: would push the reviewed-and-refused ones to the top of a list whose job is to surface what is NOT
#: handled.
_MCP_ORIGIN_RISK = {
    "discovered": 1.0,   # nobody has reviewed it
    "registered": 0.5,   # an operator vouched for it; it can still be compromised
    "blocked": 0.1,      # refused at discovery — the topology exists, the reach does not
}
#: An origin kind with no registry behind it at all. Worst case on purpose: a new origin kind that
#: nobody has taught this function about must not arrive scoring as safe.
_UNKNOWN_ORIGIN_RISK = 1.0


def _origin_risk(src_kind: str, src_node: dict, registry: dict[tuple[str, str], dict] | None) -> float:
    """The severity term for an origin that has no behavioural trust score.

    Reads the LIVE registry rather than anything cached on the graph node. That is deliberate and
    matches the decision taken when the node was added: `add_mcp_server` carries no registration
    state, because a copy on a node refreshed by traffic goes stale the moment somebody clicks Block,
    and two answers to "is this server registered" is worse than one lookup.
    """
    if src_kind != "mcp_server":
        return _UNKNOWN_ORIGIN_RISK
    server_id = str(src_node["props"].get("server_id") or "")
    namespace = str(src_node["props"].get("namespace") or "")
    row = (registry or {}).get((namespace, server_id))
    # No row means no decision has been recorded, which IS `discovered` — the same equivalence the
    # registry API reports as `previous_status` for a server nobody has decided about.
    status = str((row or {}).get("status") or "discovered")
    return _MCP_ORIGIN_RISK.get(status, _UNKNOWN_ORIGIN_RISK)


async def _mcp_registry(session: AsyncSession, namespaces: list[str]) -> dict[tuple[str, str], dict]:
    """The MCP server decisions for these namespaces, keyed (namespace, server_id).

    One query per request, like `_governing_policies` beside it — not per path, and never per hop.
    Failure returns an empty map rather than raising: an attack-path list that 500s because the
    registry table was unreachable would be a worse outcome than one whose MCP origins fall back to
    `discovered`, which is also the honest default.
    """
    if not namespaces:
        return {}
    try:
        rows = (await session.scalars(
            select(McpServer).where(McpServer.namespace.in_(namespaces))
        )).all()
    except Exception as exc:  # noqa: BLE001 — see the docstring
        log.warning("nrvq.api.threats.mcp_registry_unavailable", error=str(exc),
                    code="NRVQ-API-7113")
        return {}
    return {(r.namespace, r.server_id): {"status": r.status, "writable": bool(r.writable)}
            for r in rows}


def _build_path(
    node_ids: list[str],
    nodes_by_id: dict[str, dict],
    out_edges: dict[str, list[dict]],
    verb_overrides: dict[str, tuple[str, str]] | None = None,
    verb_evidence: dict[str, dict] | None = None,
    mcp_registry: dict[tuple[str, str], dict] | None = None,
) -> ThreatPath:
    src_node = nodes_by_id[node_ids[0]]
    tgt_node = nodes_by_id[node_ids[-1]]
    ns = str(src_node["props"].get("namespace") or "")
    src_kind = _origin_kind(src_node) or "agent"
    # Agent-shaped facts ONLY when the origin is an agent. `cls or ""` and `trust or 0.8` used to run
    # unconditionally, so a non-agent origin got an empty class that read as "unknown agent" and a
    # fabricated 0.8 trust that rendered green and capped its severity below "critical".
    cls: str | None = str(src_node["props"].get("agent_class") or "") if src_kind == "agent" else None
    # ABSENT, not falsy. `or 0.8` reported a genuinely frozen agent (trust 0.0) as 0.80 — the same
    # class of defect as the fabricated trust this change removed for non-agent origins, and on the
    # one input where being wrong matters most.
    _raw_trust = src_node["props"].get("trust_score")
    trust: float | None = (
        float(_raw_trust if _raw_trust is not None else 0.8) if src_kind == "agent" else None
    )

    steps: list[ThreatStep] = []
    chokepoint = ""
    any_allow_all = True
    blocked = False
    would_blocked = False  # a Monitor-mode would-block covers a hop (logged, not enforced) — not a gap
    for a, b in zip(node_ids, node_ids[1:]):
        bnode = nodes_by_id[b]
        hist = next((e["hist"] for e in out_edges.get(a, []) if e["target"] == b), {})
        allow = int(hist.get("allow") or 0)
        block = int(hist.get("block") or 0)
        wb = int(hist.get("would_block") or 0)
        dec = "would_block" if (wb > 0 and block == 0) else _dec_from_counts(allow, block)
        if bnode["type"] == "tool":
            chokepoint = bnode["name"]
        if allow == 0:
            any_allow_all = False
        if dec == "block" and allow == 0:
            blocked = True
        if wb > 0 and allow == 0:
            would_blocked = True
        # On a tool→data hop, resolve the ACTUAL operation (read/write/delete/send) + its risk from
        # the capability registry, so a destructive hop is distinguishable from a read. `a` is the tool
        # reaching data node `b`; None-safe when the source/verb isn't in the registry.
        op_val: str | None = None
        op_risk_val: str | None = None
        op_src_val: str | None = None
        inferred_verb: str | None = None
        inferred_count = 0
        observed_calls = 0
        if bnode["type"] == "data":
            tool_name = nodes_by_id[a]["name"]
            # A PROMOTED verb (admin-confirmed from observed evidence) outranks every inference.
            ov = (verb_overrides or {}).get(tool_name)
            if ov:
                op_val, op_risk_val = ov
                op_src_val = "learned"
            if op_val is None:
                stype = source_type_of(bnode["name"])
                if stype:
                    v = verb_of_tool(tool_name, stype)
                    if v != Verb.UNKNOWN:
                        op_val = v.value
                        r = verb_risk(stype, v)
                        op_risk_val = r.value if r else None
                        op_src_val = "registry"
            # Fallback for an unmodelled/cloud data source: classify the tool by its name so the hop still
            # says what operation it performs (aws_s3_delete → delete) instead of a generic "reaches".
            if op_val is None:
                gv, gr = classify_tool(tool_name)
                if gv != Verb.UNKNOWN:
                    op_val = gv.value
                    op_risk_val = gr.value if gr else None
                    op_src_val = "registry"
        elif bnode["type"] == "tool":
            # Lifecycle visibility on the TOOL hop itself (agent→tool): promoted verb → name classifier →
            # observation evidence, so a kill-chain hop shows what the tool DOES (or that it's still observing).
            tname = bnode["name"]
            ov = (verb_overrides or {}).get(tname)
            if ov:
                op_val, op_risk_val, op_src_val = ov[0], ov[1], "learned"
            else:
                gv, gr = classify_tool(tname)
                if gv != Verb.UNKNOWN:
                    op_val = gv.value
                    op_risk_val = gr.value if gr else None
                    op_src_val = "registry"
                else:
                    ev = (verb_evidence or {}).get(tname)
                    if ev:
                        observed_calls = int(ev.get("calls") or 0)
                        inferred_verb, inferred_count = _top_verb(ev)
        steps.append(
            ThreatStep(
                **{"from": src_node["name"] if a == node_ids[0] else nodes_by_id[a]["name"]},
                to=bnode["name"],
                verb=("reaches" if bnode["type"] == "data" else "calls"),
                dec=dec,
                kind=bnode["type"],
                deny=block,
                allow=allow,
                would_block=wb,
                op=op_val,
                op_risk=op_risk_val,
                op_src=op_src_val,
                inferred_verb=inferred_verb,
                inferred_count=inferred_count,
                observed_calls=observed_calls,
            )
        )
    if not chokepoint:
        chokepoint = tgt_node["name"]

    reach_ids = _reachable(node_ids[0], out_edges)
    reach: list[ReachAsset] = []
    for rid in reach_ids:
        rn = nodes_by_id.get(rid)
        if not rn or rn["type"] == "agent":
            continue
        # The blast radius is what's reachable BEYOND this path's target — the target itself is the
        # compromise premise, not part of its own blast. Including it inflated every count by one and,
        # on a tool-terminal path, drew the terminal a second time as its own phantom satellite.
        if rid == node_ids[-1]:
            continue
        reach.append(ReachAsset(n=rn["name"], s=1 if _node_sensitive(rn) else 0))
    reach.sort(key=lambda r: (-r.s, r.n))
    blast = len([r for r in reach])

    tgt_sens = 1.0 if _node_sensitive(tgt_node) else 0.4
    # THE ORIGIN TERM. For an agent it is behavioural trust, which is measured. For anything else there
    # is no trust score, and the question is what to put in its place.
    #
    # NOT 0.8, which is what the old `or 0.8` produced: the best-but-one value, contributing 0.10 to a
    # formula whose other terms cap at 0.50, so an unreviewed MCP server reaching a crown jewel could
    # never exceed "high". A number nobody measured must not be the reason a path looks survivable.
    #
    # NOT a constant worst case either — that would rank a knowledge base an operator registered
    # read-only alongside one they have never looked at, and the operator has already told us the
    # difference. `_origin_risk` reads the registry they populated, so the decisions taken on the MCP
    # Servers page are what move this number.
    if trust is not None:
        risk = min(1.0, (1.0 - trust) * 0.5 + tgt_sens * 0.35 + (0.15 if chokepoint else 0.0))
    else:
        # A DIFFERENT WEIGHTING for a non-agent origin, and the live output is what forced it.
        #
        # Reusing the agent weights looked right and was measured wrong: every MCP-origin path ends at
        # a data node (sensitive, 0.35) through a chokepoint (0.15), so `origin * 0.5 + 0.5` is >= 0.75
        # for any origin risk above 0.5 — and all eight paths on the kind cluster rendered "critical",
        # including the two servers an operator had REGISTERED. The registry term was real, computed,
        # and invisible: a control that reads an operator's decisions and changes nothing they can see.
        #
        # The weights differ because the QUESTION differs. For an agent the origin is a given — it is
        # supposed to be there — and the target's sensitivity is what makes the path severe. For an MCP
        # server "should this be here at all" IS the finding, so the origin term dominates and the
        # constant terms make room for it. Agent paths are untouched, so nothing that existed before
        # this change moves.
        origin_risk = _origin_risk(src_kind, src_node, mcp_registry)
        risk = min(1.0, origin_risk * 0.6 + tgt_sens * 0.25 + (0.1 if chokepoint else 0.0))
    sev = _severity_from(risk)

    if blocked:
        status, verdict = "blocked", f"Policy blocks the chokepoint '{chokepoint}' — path neutralized."
    elif would_blocked:
        # A policy covers the chokepoint but the namespace is in Monitor mode — logged, not enforced. This
        # is NOT an open path; rank it with blocked (covered) but tell the operator it isn't enforcing.
        status, verdict = (
            "blocked",
            f"Monitor mode: '{chokepoint}' would be blocked (logged, not enforced) — switch to Block to enforce.",
        )
    elif any_allow_all and len(steps) > 0:
        status, verdict = "exploitable", f"Every hop has allowed traffic — '{chokepoint}' is reachable end-to-end."
    elif src_kind != "agent":
        # SAME status value, different sentence. The value is load-bearing in two places that must not
        # be disturbed: `_STATUS_ORDER[p.status]` is a DIRECT index in the dedupe (a new string raises
        # KeyError), and the same map drives the pre-cap ranking, so inventing a rank would decide by
        # accident whether these displace agent findings in the 200-path view.
        #
        # The SENTENCE had to change. Decision history is keyed (agent_id, tool_name) from the audit
        # log, and no audit row will ever carry `agent_id = "mcp:<server>"` — so this path is
        # permanently "unsimulated" and "simulate to confirm" asks the operator to do something that
        # cannot work. What is true is that the reach is structural: the server serves the tool
        # whether or not anyone has called it.
        status = "unsimulated"
        verdict = (
            f"Reachable by construction: this MCP server serves '{chokepoint}', which reaches "
            f"{tgt_node['name']}. No traffic is attributable to a server (audit rows name the calling "
            "agent), so this is topology, not observed exploitation."
        )
    else:
        status, verdict = "unsimulated", "No end-to-end traffic yet — simulate to confirm reachability."

    return ThreatPath(
        id=_short_id(ns, node_ids[0], node_ids[-1], str(len(node_ids))),
        sev=sev,
        src=src_node["name"],
        tgt=tgt_node["name"],
        ns=ns,
        src_kind=src_kind,
        cls=cls,
        mitre=mitre_for_tool(chokepoint),
        hops=len(node_ids) - 1,
        trust=round(trust, 2) if trust is not None else None,
        blast=blast,
        status=status,
        tool=chokepoint,
        reach=reach[:8],
        steps=steps,
        verdict=verdict,
        # The prescription has to match the origin. `recommended_fix` is agent-class-only in all four
        # of its arms ("scope <class> to…"), so on an MCP-origin path the card told the operator to do
        # something to a class that does not exist — directly contradicting the note underneath it,
        # which says an agent-class intent does not apply.
        fix=(
            recommended_fix(chokepoint)
            if src_kind == "agent"
            else f"Register '{src_node['name']}' read-only, or block it, on the MCP Servers page — "
                 f"blocking withholds its tools at discovery so '{chokepoint}' never reaches the model."
        ),
    )


# Mirrors coverage.py's marker parser — see the note at the fallback below.
_INTENT_TOOLS_RE = re.compile(r"(?m)^#\s*nrvq:intent-tools\s+(\[.*\])\s*$")
_POLICY_ALLOW_RE = re.compile(r"allow_names\s*:=\s*\{([^}]*)\}")
_POLICY_QUOTED_RE = re.compile(r'"([^"]+)"')


async def _governing_policies(session: AsyncSession, namespaces: list[str] | None) -> dict[str, dict]:
    """{agent_class: {kind, allow, readonly}} of APPLIED intent/capability policies — so a path can say
    'a defense is applied here' even while its audit-derived status still reads exploitable (no post-apply
    traffic yet). Precise: an intent policy governs a chokepoint only when it actually DENIES it (tool not
    in the allowlist, or allowlisted-but-refined-out); a capability policy is a verb forward-guard."""
    where = "agent_class !~ '^__.*__$'"
    params: dict = {}
    if namespaces is not None:
        where += " AND namespace = ANY(:nss)"
        params["nss"] = namespaces
    try:
        rows = (
            (
                await session.execute(
                    text(
                        f"SELECT DISTINCT ON (namespace, agent_class) agent_class, rego_source FROM policies "  # nosec B608 (constant WHERE fragments; namespaces bound as :nss) # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                        f"WHERE {where} ORDER BY namespace, agent_class, version DESC"
                    ),
                    params,
                )
            )
            .mappings()
            .all()
        )
    except Exception:
        return {}
    out: dict[str, dict] = {}
    for r in rows:
        rego = str(r["rego_source"] or "")
        pkg = re.search(r"package\s+([\w.]+)", rego)
        pkg_s = pkg.group(1) if pkg else ""
        if pkg_s.startswith("norviq.intent."):
            kind = "intent"
        elif pkg_s.startswith("norviq.remediation.capability."):
            kind = "capability"
        else:
            continue  # a plain custom policy — don't claim to reason about its chokepoint coverage
        allow: set[str] = set()
        # Same fallback coverage.py grew: an INTENT-compiled policy has no `allow_names := {...}` —
        # its scoping lives in per-rule predicates — so `allow` came back empty and every
        # intent-compiled policy read as governing NOTHING (or, read the other way by callers that
        # treat an empty allow as unrestricted, as governing EVERYTHING). Both registers parse the same
        # marker or they disagree about what a policy covers.
        am = _POLICY_ALLOW_RE.search(rego)
        if not am:
            im = _INTENT_TOOLS_RE.search(rego or "")
            if im:
                try:
                    parsed = json.loads(im.group(1))
                except ValueError:
                    parsed = []
                if isinstance(parsed, list):
                    # LOWER-CASED, matching the `allow_names` branch below and the only consumer:
                    # `_path_governed_by` lower-cases the chokepoint before the membership test. Storing
                    # raw case here meant an intent admitting `sendEmail` was compared against `sendemail`
                    # and missed — so a chokepoint the intent ALLOWS was reported as DEFENDED, which is
                    # the wrong direction for an attack-path badge.
                    allow = {str(v).lower() for v in parsed}
                    out[str(r["agent_class"])] = {
                        "kind": kind, "allow": allow, "readonly": "is_read " in rego,
                        # An EMPTY marker means "this intent does not scope by tool name" (the compiler
                        # says so in its own header), NOT "it admits nothing". Those read identically as
                        # an empty `allow`, and the consumer treats an absent name as DENIED — so an
                        # intent scoping by verb or destination badged EVERY chokepoint as defended.
                        # Claiming a defence that does not exist is the wrong direction for this badge.
                        "name_scoped": bool(allow),
                    }
                    continue
        if am:
            allow = {a.lower() for a in _POLICY_QUOTED_RE.findall(am.group(1))}
        out[str(r["agent_class"])] = {"kind": kind, "allow": allow, "readonly": "is_read " in rego}
    return out


def _path_governed_by(gov: dict, cls: str, chokepoint: str, choke_verb: str | None) -> str:
    """Does an applied policy for `cls` DENY this chokepoint? Returns the policy kind or ""."""
    p = gov.get(cls)
    if not p:
        return ""
    if p["kind"] == "capability":
        return "capability"  # verb forward-guard blocks destructive tools by name pattern
    # intent (default-deny): denies any tool NOT allowlisted; an allowlisted MUTATING tool is denied only
    # when Read-only is on. A permitted (allowlisted, non-refined) chokepoint is NOT governed — be honest.
    # An intent that does not scope by tool name says nothing about this chokepoint, so it cannot be
    # claimed as the thing defending it. Only a name-scoped allowlist supports "not listed => denied".
    if not p.get("name_scoped", True):
        return ""
    name = (chokepoint or "").lower()
    if name not in p["allow"]:
        return "intent"
    if p["readonly"] and choke_verb in ("write", "delete", "send"):
        return "intent"
    return ""


async def _derive_paths(
    session: AsyncSession, namespaces: list[str] | None, cls: str | None, hours: int = 24,
    cap: int | None = _MAX_PATHS,
) -> tuple[list[ThreatPath], list[str], int]:
    nodes_by_id, out_edges, seen = await _assemble(session, namespaces, hours)
    overrides = await _verb_overrides(session, namespaces)
    evidence = await _verb_evidence(session, namespaces)
    governing = await _governing_policies(session, namespaces)
    registry = await _mcp_registry(session, seen)
    paths: list[ThreatPath] = []
    non_agent_hidden_ids: set[str] = set()
    for nid, node in nodes_by_id.items():
        if not _origin_kind(node):
            continue
        for chain in _walk_paths(nid, out_edges, nodes_by_id):
            p = _build_path(chain, nodes_by_id, out_edges, verb_overrides=overrides,
                            verb_evidence=evidence, mcp_registry=registry)
            if cls and cls.lower() != "all" and p.cls != cls:
                # A non-agent origin has no class, so an agent-class filter legitimately excludes it —
                # but silently, which is the part that had to change. Counted here and reported on the
                # response so the console can say "N non-agent origins hidden", exactly as it already
                # does for probe traffic. An exclusion nobody can see is indistinguishable from an
                # estate that has none.
                if p.cls is None:
                    # By ID, not per chain. The dedupe below collapses chains that share
                    # (ns, src, tgt, hops) into one path, and `synthetic_hidden` / `non_agent_paths`
                    # are both computed AFTER it — so counting raw chains here put this number on a
                    # different denominator from the ones it is meant to reconcile with. Measured: one
                    # server serving two tools that both reach the same data reported 2 hidden where
                    # the unfiltered view holds 1.
                    non_agent_hidden_ids.add(p.id)
                continue
            # Mark whether an APPLIED policy governs this chokepoint (audit-derived status can lag a fresh
            # apply). Chokepoint verb: promoted override → name classifier.
            ov = overrides.get(p.tool)
            choke_verb = ov[0] if ov else (lambda v: v.value if v != Verb.UNKNOWN else None)(classify_tool(p.tool)[0])
            # "n/a", not "". `_path_governed_by` looks the class up in a per-class map and misses for a
            # class-less path, returning "" — which the console renders as "no defense applied". An
            # agent-class intent policy is not a thing that COULD govern a non-agent origin, so "we did
            # not find one" would be a false negative wearing the clothes of a finding.
            p.governed_by = (
                _path_governed_by(governing, p.cls, p.tool, choke_verb) if p.cls is not None else "n/a"
            )
            paths.append(p)
    # Dedup by id (an agent can reach the same target via distinct-length chains — keep worst).
    by_id: dict[str, ThreatPath] = {}
    for p in paths:
        cur = by_id.get(p.id)
        if cur is None or _STATUS_ORDER[p.status] < _STATUS_ORDER[cur.status]:
            by_id[p.id] = p
    ordered = sorted(
        by_id.values(),
        key=lambda p: (_STATUS_ORDER.get(p.status, 1), _SEVERITY_ORDER.get(p.sev, 3), -p.blast),
    )
    # Cap AFTER ranking so the global truncation drops the LEAST severe paths — never hides a
    # worst-first (exploitable / critical) path behind arbitrary graph-iteration order. Per-agent
    # fan-out is already bounded (chokepoint + chain budgets) and the asset graph is node-bounded,
    # so building all paths before the cap stays bounded.
    #
    # `cap=None` returns the UNCAPPED ranked list. The paths endpoint needs it so it can count each
    # class BEFORE truncating: counting inside a capped list answers "how many survived the cap",
    # which is not the class's exposure. Callers that want the capped view keep the default.
    return (ordered if cap is None else ordered[:cap]), seen, len(non_agent_hidden_ids)


@router.get("/threats/attack-paths", response_model=ThreatPathsResponse)
async def get_threat_paths(
    ns: str | None = Query(None),
    namespace: str | None = Query(None),  # alias — the sibling graph endpoints spell it `namespace`
    cls: str | None = Query(None),
    range: str = Query("24h"),
    include_synthetic: bool = Query(False),  # default-hide kill-chains rooted at seeded probe/test agents
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Enriched kill-chains for the console, worst-first (exploitable → unsimulated → blocked, severity
    tiebreak). Namespace-scoped: ``ns=all`` unions the caller's namespaces; a scoped viewer only ever
    sees its own. status/dec/deny/allow come from REAL audit decision history (no side-effecting eval).

    P2-1: this route named its scope param ``ns`` while ``/asset-graph`` and ``/attack-paths`` name it
    ``namespace`` — so a caller sending ``?namespace=X`` had it SILENTLY ignored and received every
    namespace's kill-chains. ``namespace`` is now an accepted alias. ``ns`` stays canonical (the console,
    the e2e specs and the intent routes all send it). Merged with ``is not None`` so the existing
    ``?ns=`` (empty string → no namespaces → 0 paths) edge is preserved rather than flipped to "all".
    Supplying BOTH with different values is a caller bug → 400, never a silently-dropped scope filter.
    """
    hours = RANGE_HOURS.get(range, 24)  # the caller's range IS the decision-history window
    if ns is not None and namespace is not None and ns != namespace:
        raise HTTPException(status_code=400, detail="conflicting 'ns' and 'namespace' query parameters")
    requested = ns if ns is not None else (namespace if namespace is not None else "all")
    namespaces = _resolve_namespaces(user, requested)
    # UNCAPPED, then filter, then count, then cap — in that order. Doing it the other way round is
    # what made the console disagree with itself: the class picker counted inside an already-truncated
    # 200 and reported 22 paths for a class the coverage denominator scored out of 49.
    all_paths, seen, non_agent_hidden = await _derive_paths(session, namespaces, cls, hours, cap=None)
    # A kill-chain rooted at a synthetic/probe agent is test noise — hide it by default (toggle brings it back).
    synthetic_hidden = 0
    if not include_synthetic:
        # `cls or ""` because the classifier takes an optional class and a non-agent origin now sends
        # None. It falls through to the SVID parse, which cannot match `mcp:<server>`, so a non-agent
        # origin is never mistaken for a probe — asserted in the tests rather than assumed.
        # Only AGENT origins are classified. `is_synthetic_identity` takes an agent class and a SPIFFE
        # id; an MCP server label is neither, and feeding it one means a server an operator happens to
        # name `test-kb` or `probe-mcp` would be silently hidden as fabricated traffic — a real
        # integration disappearing because of its name.
        kept = [
            p for p in all_paths
            if p.cls is None or not is_synthetic_identity(p.cls, p.src)
        ]
        synthetic_hidden = len(all_paths) - len(kept)
        all_paths = kept
    class_totals: dict[str, int] = {}
    non_agent_paths = 0
    for p in all_paths:
        if p.cls:
            class_totals[p.cls] = class_totals.get(p.cls, 0) + 1
        elif p.cls is None:
            # Counted SEPARATELY rather than under a synthetic "mcp_server" key: `class_totals` is
            # keyed by agent class, and a key that is not one would collide with a real class of that
            # name and break the map's contract. This keeps the invariant restatable —
            # sum(class_totals) + non_agent_paths == total_paths — which `if p.cls:` alone silently
            # broke, since `total_paths` counts what the loop skipped.
            non_agent_paths += 1
    total_paths = len(all_paths)
    # Truncate the two origin kinds against separate budgets, preserving the ranked order within each.
    # See `_MAX_NON_AGENT_PATHS`: origin names are attacker-influenced, and a single shared cap let a
    # flood of fabricated MCP servers evict every real agent finding from the view.
    # The reservation is DYNAMIC: non-agent origins take at most `_MAX_NON_AGENT_PATHS` of the budget,
    # and whatever they do not use goes to agents. Subtracting the sub-cap unconditionally shrank the
    # agent view from 200 to 160 on every estate — including the overwhelming majority that have no
    # MCP servers at all — which is paying for a defence against a population that does not exist.
    # Caught by the existing class-totals test, which asserts the full 200 on an agent-only fixture.
    non_agent_slice = [p for p in all_paths if p.cls is None][:_MAX_NON_AGENT_PATHS]
    agent_slice = [p for p in all_paths if p.cls is not None][:_MAX_PATHS - len(non_agent_slice)]
    kept_ids = {id(p) for p in agent_slice} | {id(p) for p in non_agent_slice}
    # Re-emitted in the ORIGINAL ranked order rather than agents-then-servers: the page's contract is
    # worst-first, and concatenating the slices would sort by origin kind instead.
    paths = [p for p in all_paths if id(p) in kept_ids]
    log.info(
        "nrvq.api.attack_paths.served",
        ns=requested,
        cls=cls,
        count=len(paths),
        total_paths=total_paths,
        synthetic_hidden=synthetic_hidden,
        non_agent_paths=non_agent_paths,
        non_agent_hidden=non_agent_hidden,
        resolved=seen,
        code="NRVQ-API-7101",
    )
    return ThreatPathsResponse(paths=paths, namespaces=seen, synthetic_hidden=synthetic_hidden,
                               non_agent_hidden=non_agent_hidden, non_agent_paths=non_agent_paths,
                               class_totals=class_totals, total_paths=total_paths)


async def _coverage(
    request: Request,
    session: AsyncSession,
    namespaces: list[str] | None,
    cls: str,
    allow_tools: list[str],
    intent: Intent,
) -> tuple[str, list[str], list[str]]:
    """Generate the default-deny intent rego and DRY-RUN it against each path's chokepoint. Returns
    (rego, covered_ids, residual_ids). Uses the evaluator's isolated dry-run key — no persistence.
    Admin-PROMOTED verbs flow into the generation so the toggles honour them (a tool learned as delete
    is never treated as a read by Read-only, whatever its name says)."""
    overrides = await _verb_overrides(session, namespaces)
    learned = {tool: verb for tool, (verb, _risk) in overrides.items()}
    rego = generate_intent_rego(cls, allow_tools, intent, learned_verbs=learned)
    # UNCAPPED. This omitted `cap` and so took the `_MAX_PATHS = 200` default, which is a DISPLAY cap
    # for the graph's path list — the class filter is applied inside the walk, so it capped this
    # class's paths at 200 and `total = len(covered) + len(residual)` became min(real, 200). The same
    # endpoint's `class_totals` is computed with `cap=None`, so the Attack Graph could report a class
    # with 240 paths while the intent modal's coverage denominator said 200, and an operator who
    # neutralised every path would be shown 200/200 with 40 paths still live.
    #
    # This is the second place the display cap leaked into a COUNT; the path-list endpoint had the
    # same defect and was fixed by deriving uncapped, counting, then capping. Coverage never renders a
    # list, so it simply must not cap at all.
    paths, _, _ = await _derive_paths(session, namespaces, cls, cap=None)
    evaluator = request.app.state.evaluator
    covered: list[str] = []
    residual: list[str] = []
    dry_key = f"dryrun:threat:{cls}"
    for p in paths:
        opa_input = opa_input_for_step(p.tool, p.ns, p.cls)
        try:
            result = await evaluator._evaluate_opa(dry_key, p.ns, p.cls, opa_input, rego)
            denied = str(result.get("decision")) == "block"
        except Exception as exc:  # a malformed rego must fail-closed to "not covered", never crash the page
            log.warning("nrvq.api.intent.coverage_eval_failed", error=str(exc), code="NRVQ-API-7102")
            denied = False
        (covered if denied else residual).append(p.id)
    return rego, covered, residual


@router.post("/threats/intent-coverage", response_model=IntentCoverageResponse)
async def intent_coverage(
    body: IntentCoverageRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Generate a positive-security (default-deny) intent policy for an agent class and count how many of
    the current attack paths it DENIES (dry-run only — nothing is persisted or enforced)."""
    if body.cls in _RESERVED_CLASSES:
        raise HTTPException(status_code=422, detail=f"'{body.cls}' is a managed scope, not an agent class.")
    namespaces = _resolve_namespaces(user, body.ns)
    intent = Intent.from_dict(body.intent.model_dump())
    rego, covered, residual = await _coverage(request, session, namespaces, body.cls, body.allow_tools, intent)
    total = len(covered) + len(residual)
    log.info(
        "nrvq.api.intent.coverage",
        cls=body.cls,
        enabled=intent.enabled_keys(),
        covered=len(covered),
        total=total,
        code="NRVQ-API-7102",
    )
    return IntentCoverageResponse(
        rego=rego,
        covered=covered,
        residual=residual,
        covered_count=len(covered),
        total=total,
    )


async def _baseline_priority(session: AsyncSession, ns: str) -> int:
    """The comprehensive-baseline priority for a namespace — the priority a drafted intent policy MUST
    inherit so, once applied, ``_resolve_precedence``'s most-restrictive tie-break keeps the baseline
    block winning (tighten-only). Prefer the namespace baseline, fall back to the cluster baseline, else 1.
    Read-only SELECT against ``policies`` — never writes."""
    row = (
        await session.execute(
            text("SELECT priority FROM policies WHERE namespace = :ns AND agent_class = '__baseline__' LIMIT 1"),
            {"ns": ns},
        )
    ).scalar()
    if row is not None:
        return int(row)
    row = (
        await session.execute(
            text(
                "SELECT priority FROM policies WHERE namespace = '__cluster__' AND agent_class = '__baseline__' LIMIT 1"
            )
        )
    ).scalar()
    if row is not None:
        return int(row)
    return 1


@router.post("/threats/intent-draft", response_model=IntentDraftResponse)
async def intent_draft(
    body: IntentDraftRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
    _target: None = Depends(require_target_cluster),
):
    """Create a DRY-RUN DRAFT of the generated intent policy and deep-link to Policies. This NEVER
    enforces: the draft is persisted ONLY in the dedicated ``intent_drafts`` table (which the evaluator's
    ``_collect_candidates`` never reads), NEVER in ``policies``; an operator must explicitly review + apply
    it in Policies (existing gated flow). Its priority == the namespace baseline (tighten-only)."""
    require_admin(user)
    if body.cls in _RESERVED_CLASSES:
        raise HTTPException(status_code=422, detail=f"'{body.cls}' is a managed scope — draft a real agent class.")
    namespaces = _resolve_namespaces(user, body.ns)
    intent = Intent.from_dict(body.intent.model_dump())
    allow_tools = [t for t in (body.allow_tools or []) if t and t.strip()]
    # Nothing to draft unless there's at least one allowlisted tool OR one refinement toggle.
    if not allow_tools and not intent.any_enabled:
        raise HTTPException(
            status_code=422,
            detail="Add at least one allowlisted tool or enable one refinement toggle before drafting.",
        )
    rego, covered, residual = await _coverage(request, session, namespaces, body.cls, allow_tools, intent)
    total = len(covered) + len(residual)
    priority = await _baseline_priority(session, body.ns)

    # Validate the generated rego compiles by probing it once through the isolated dry-run key.
    evaluator = request.app.state.evaluator
    errors: list[str] = []
    valid = True
    try:
        probe = opa_input_for_step("search_kb", body.ns, body.cls)
        await evaluator._evaluate_opa(f"dryrun:threat:{body.cls}", body.ns, body.cls, probe, rego)
    except Exception as exc:
        valid = False
        errors = [str(exc)]

    draft_id = _short_id("draft", body.ns, body.cls, ",".join(allow_tools), ",".join(intent.enabled_keys())).replace(
        "p", "d", 1
    )
    created_at = datetime.now(timezone.utc)
    # DEDUPE BY CLASS — a (namespace, agent_class) keeps at most ONE pending Attack-Graph intent draft (the
    # latest). Prior drafts for the same class are cleared before insert so re-drafting overwrites instead of
    # piling up. Scope the delete to Attack-Graph drafts (source_control_id IS NULL) so it never clobbers a
    # compliance draft, which is deduped separately by (framework, control, class). Drafts are dry-run only.
    await session.execute(
        text("DELETE FROM intent_drafts WHERE namespace = :ns AND agent_class = :cls AND source_control_id IS NULL"),
        {"ns": body.ns, "cls": body.cls},
    )
    session.add(
        IntentDraft(
            id=draft_id,
            namespace=body.ns,
            agent_class=body.cls,
            rego_source=rego,
            allow_tools=allow_tools,
            toggles=intent.enabled_keys(),
            priority=priority,
            covered_count=len(covered),
            total=total,
            would_block=len(covered),
            would_allow=len(residual),
            created_by=str(user.get("sub") or ""),
            created_at=created_at,
            expires_at=draft_expiry(body.cls, created_at),  # TTL (24h test / 14d real)
        )
    )
    await session.commit()
    await enforce_draft_cap(session, body.ns)  # hard ceiling per namespace (evict oldest beyond it)
    log.info(
        "nrvq.api.intent.draft_created",
        draft_id=draft_id,
        ns=body.ns,
        cls=body.cls,
        allow_tools=allow_tools,
        enabled=intent.enabled_keys(),
        covered=len(covered),
        priority=priority,
        enforcement="draft",
        actor=user.get("sub"),
        code="NRVQ-API-7103",
    )
    return IntentDraftResponse(
        draft_id=draft_id,
        policy=f"{body.ns}/{body.cls}",
        ns=body.ns,
        cls=body.cls,
        deeplink=f"/policies/catalog?intent_draft={draft_id}",
        priority=priority,
        enforcement="draft",
        valid=valid,
        errors=errors,
        would_block=len(covered),
        would_allow=len(residual),
        covered_count=len(covered),
        total=total,
    )


class CapabilityDefendRequest(BaseModel):
    """CAP→POLICY: defend a source's mutating verbs for an agent class. verbs empty ⇒ ALL mutating verbs
    the source exposes (make the class read-only)."""

    ns: str
    cls: str
    source_type: str
    verbs: list[str] = Field(default_factory=list)


class CapabilityDefendResponse(BaseModel):
    draft_id: str
    deeplink: str
    ns: str
    cls: str
    source_type: str
    verbs: list[str]
    blocked_tools: list[str]  # concrete tools observed reaching the source today (belt-and-suspenders)
    # CAP-FIX: the policy also blocks these verbs by NAME PATTERN — a forward guard that catches a
    # destructive tool appearing later, so the defense is real even when blocked_tools is empty.
    forward_guard_verbs: list[str] = Field(default_factory=list)
    read_only: bool
    valid: bool
    errors: list[str] = Field(default_factory=list)


def _tools_reaching_source(nodes, edges, source_type: str, agent_class: str, target_verbs: set) -> list[str]:
    """The concrete tool NAMES that (a) agent_class calls and (b) reach source_type with a target verb —
    the exact set a capability policy blocks (resolved at generation time; OPA input has no source field)."""
    tool_name_by_id = {n.id: n.name for n in nodes if n.type == "tool"}
    data_by_id = {n.id: n for n in nodes if n.type == "data"}
    class_by_id = {n.id: str(n.properties.get("agent_class") or "") for n in nodes if n.type == "agent"}
    cls_tools = {
        e.target
        for e in edges
        if e.type == "calls" and e.target in tool_name_by_id and class_by_id.get(e.source) == agent_class
    }
    blocked: set[str] = set()
    for e in edges:
        if e.type != "accesses" or e.target not in data_by_id or e.source not in cls_tools:
            continue
        if source_type_of(data_by_id[e.target].name) != source_type:
            continue
        name = tool_name_by_id.get(e.source, "")
        if verb_of_tool(name, source_type) in target_verbs:
            blocked.add(name)
    return sorted(blocked)


@router.post("/capability/defend", response_model=CapabilityDefendResponse)
async def capability_defend(
    body: CapabilityDefendRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
    _target: None = Depends(require_target_cluster),
):
    """CAP→POLICY bridge: turn a source-capability finding into a DRY-RUN policy draft that blocks the
    target verbs on the source for one agent class. NEVER enforces — the draft lands in ``intent_drafts``
    (which the evaluator never reads) and the operator reviews + applies it via the gated Policies flow,
    exactly like a compliance/attack-graph draft. Provenance: source_framework='capability'."""
    require_admin(user)
    if body.cls in _RESERVED_CLASSES:
        raise HTTPException(status_code=422, detail=f"'{body.cls}' is a managed scope — pick a real agent class.")
    # Resolve target verbs: explicit, else ALL mutating verbs the source exposes (make read-only).
    if body.verbs:
        target_verbs = [Verb(v) for v in body.verbs if v in {vb.value for vb in Verb}]
    else:
        target_verbs = mutating_verbs_of(body.source_type)
    meta = defense_meta(body.source_type, target_verbs)
    if not meta:
        raise HTTPException(
            status_code=422,
            detail=f"Nothing to defend: '{body.source_type}' exposes no blockable (write/delete/send) verb.",
        )
    verbs = cast(list, meta["verbs"])

    # Resolve the concrete tool set from the live snapshot (OPA input has no source field).
    namespaces = _resolve_namespaces(user, body.ns)
    snapshots = await _latest_snapshots(session, namespaces)
    blocked_tools: list[str] = []
    for ns, graph_json in snapshots:
        counts = await _decision_counts(session, ns, datetime.now(timezone.utc) - timedelta(hours=24))
        nodes, edges, _ = _snapshot_to_assets(ns, graph_json, counts, prefix_ids=False)
        blocked_tools.extend(_tools_reaching_source(nodes, edges, body.source_type, body.cls, {Verb(v) for v in verbs}))
    blocked_tools = sorted(set(blocked_tools))

    # Forward-guard fragments for the target verbs (so the policy blocks unobserved/renamed destructive
    # tools too, not just the ones seen today) — resolved from the same registry verbs the defense targets.
    frags = verb_fragments(body.source_type, [Verb(v) for v in verbs])
    rego = generate_capability_rego(
        body.source_type,
        cast(str, meta["source_display"]),
        body.cls,
        verbs,
        blocked_tools,
        cast(str, meta["rule_id"]),
        cast(str, meta["reason"]),
        verb_frags=frags,
    )

    # Validate the generated rego compiles via the isolated dry-run key (never touches the live module).
    evaluator = request.app.state.evaluator
    errors: list[str] = []
    valid = True
    try:
        probe = opa_input_for_step("search_kb", body.ns, body.cls)
        await evaluator._evaluate_opa(f"dryrun:capability:{body.cls}", body.ns, body.cls, probe, rego)
    except Exception as exc:
        valid = False
        errors = [str(exc)]

    priority = await _baseline_priority(session, body.ns)
    verb_tok = "+".join(verbs)
    control_id = f"{body.source_type}:{verb_tok}"
    draft_id = _short_id("draft", body.ns, body.cls, "cap", control_id).replace("p", "d", 1)
    created_at = datetime.now(timezone.utc)
    # Dedupe by (ns, class, capability control) — re-defending the same verbs/source/class overwrites.
    await session.execute(
        text(
            "DELETE FROM intent_drafts WHERE namespace = :ns AND agent_class = :cls "
            "AND source_framework = 'capability' AND source_control_id = :cid"
        ),
        {"ns": body.ns, "cls": body.cls, "cid": control_id},
    )
    session.add(
        IntentDraft(
            id=draft_id,
            namespace=body.ns,
            agent_class=body.cls,
            rego_source=rego,
            allow_tools=blocked_tools,
            toggles=verbs,
            priority=priority,
            covered_count=len(blocked_tools),
            total=len(blocked_tools),
            would_block=len(blocked_tools),
            would_allow=0,
            created_by=str(user.get("sub") or ""),
            created_at=created_at,
            source_framework="capability",
            source_control_id=control_id,
            source_control_name=f"{'/'.join(verbs)} on {meta['source_display']}",
            expires_at=draft_expiry(body.cls, created_at),
        )
    )
    await session.commit()
    await enforce_draft_cap(session, body.ns)
    log.info(
        "nrvq.api.capability.defend",
        draft_id=draft_id,
        ns=body.ns,
        cls=body.cls,
        source=body.source_type,
        verbs=verbs,
        blocked_tools=blocked_tools,
        priority=priority,
        enforcement="draft",
        actor=user.get("sub"),
        code="NRVQ-API-7110",
    )
    return CapabilityDefendResponse(
        draft_id=draft_id,
        deeplink=f"/policies/catalog?intent_draft={draft_id}",
        ns=body.ns,
        cls=body.cls,
        source_type=body.source_type,
        verbs=verbs,
        blocked_tools=blocked_tools,
        forward_guard_verbs=verbs,
        read_only=bool(meta["read_only"]),
        valid=valid,
        errors=errors,
    )


@router.get("/threats/intent-drafts", response_model=IntentDraftPage)
async def list_intent_drafts(
    ns: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int | None = Query(None, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """A BOUNDED, paginated page of pending intent drafts (non-enforcing) + the total count, so the
    Policy Catalog never renders the whole list at once. Reads from the dedicated table — never ``policies``.

    SECURITY (IDOR + read-causes-cross-tenant-write): the caller's namespace set is resolved FAIL-CLOSED via
    _resolve_namespaces (a scoped tenant naming another namespace gets 403; "all"/none → only its own), so this
    endpoint cannot enumerate/read every tenant's drafts, and the lazy GC is scoped to that same set so a
    read-only viewer cannot DELETE another namespace's rows through a GET."""
    namespaces = _resolve_namespaces(user, ns if ns is not None else "all")  # None = unrestricted (admin/service)
    # Lazy GC of expired (non-enforcing) drafts — scoped to the caller's OWN namespaces only. The background
    # RetentionPruner also sweeps these globally, so a viewer never needs (and never gets) cross-tenant reach.
    if namespaces is None:
        await gc_expired_drafts(session, None)
    else:
        for _n in namespaces:
            await gc_expired_drafts(session, _n)
    page = int(limit or settings.drafts_page_size)
    where = ""
    params: dict = {}
    if namespaces is not None:
        where = " WHERE namespace = ANY(:nslist)"
        params["nslist"] = namespaces
    total = int((await session.execute(text(f"SELECT COUNT(*) FROM intent_drafts{where}"), params)).scalar() or 0)  # nosec B608 (constant WHERE fragment; namespaces bound as :nslist) # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
    rows = (
        (
            await session.execute(
                text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                    "SELECT id, namespace, agent_class, affected_class, allow_tools, toggles, covered_count, total, "  # nosec B608 (constant WHERE; namespaces/offset/limit bound :nslist/:off/:lim)
                    "created_by, created_at, source_framework, source_control_id, source_control_name, expires_at "
                    f"FROM intent_drafts{where} ORDER BY created_at DESC OFFSET :off LIMIT :lim"
                ),
                {**params, "off": int(offset), "lim": page},
            )
        )
        .mappings()
        .all()
    )
    drafts = [
        IntentDraftSummary(
            draft_id=r["id"],
            ns=r["namespace"],
            cls=r["agent_class"],
            # For a remediation draft, `agent_class`/`cls` is the compound persistence
            # overlay key ("<class>__remediation__") — `affected_class` carries the real class for display.
            affected_class=r["affected_class"],
            enabled=list(r["toggles"] or []),
            allow_tools=list(r["allow_tools"] or []),
            covered_count=r["covered_count"],
            total=r["total"],
            created_by=r["created_by"] or "",
            created_at=r["created_at"].isoformat() if r["created_at"] else "",
            source_framework=r["source_framework"],
            source_control_id=r["source_control_id"],
            source_control_name=r["source_control_name"],
            expires_at=r["expires_at"].isoformat() if r["expires_at"] else "",
        )
        for r in rows
    ]
    log.info("nrvq.api.intent.draft_listed", returned=len(drafts), total=total, offset=offset, code="NRVQ-API-7104")
    return IntentDraftPage(drafts=drafts, total=total, returned=len(drafts), offset=int(offset), limit=page)


@router.delete("/threats/intent-drafts/{draft_id}")
async def dismiss_intent_draft(
    draft_id: str,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Manually dismiss ONE pending draft. Non-enforcing only (the evaluator never reads this table),
    so this can never change enforcement. Admin-gated like the other draft mutations."""
    require_admin(user)
    result = await session.execute(text("DELETE FROM intent_drafts WHERE id = :id"), {"id": draft_id})
    await session.commit()
    dismissed = int(result.rowcount or 0)
    log.info(
        "nrvq.api.intent.draft_dismissed",
        draft_id=draft_id,
        dismissed=dismissed,
        actor=user.get("sub"),
        code="NRVQ-API-7114",
    )
    if not dismissed:
        raise HTTPException(status_code=404, detail="draft not found")
    return {"dismissed": True, "draft_id": draft_id}


@router.post("/threats/intent-drafts/gc")
async def gc_intent_drafts(
    ns: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Bulk "Clear expired" — delete all expired non-enforcing drafts on demand. Safe: never touches
    an enforcing policy or version (drafts live in the dedicated non-enforcing table)."""
    require_admin(user)
    removed = await gc_expired_drafts(session, ns)
    return {"cleared": removed, "namespace": ns}


@router.get("/threats/intent-drafts/{draft_id}")
async def get_intent_draft(
    draft_id: str, session: AsyncSession = Depends(get_session), user: dict = Depends(get_current_user)
) -> dict:
    """Fetch one pending draft in full (incl. the generated rego) so the Policies page can review + apply
    it via the existing gated create/apply flow. Read-only SELECT from ``intent_drafts`` — never enforces."""
    r = (
        (
            await session.execute(
                text(
                    "SELECT id, namespace, agent_class, affected_class, rego_source, allow_tools, toggles, priority, "
                    "covered_count, total, would_block, would_allow, created_by, created_at, "
                    "source_framework, source_control_id, source_control_name "
                    "FROM intent_drafts WHERE id = :id LIMIT 1"
                ),
                {"id": draft_id},
            )
        )
        .mappings()
        .first()
    )
    if r is None:
        raise HTTPException(status_code=404, detail="draft not found (regenerate from Attack Graph)")
    # SECURITY (IDOR): a scoped tenant must not read another namespace's draft (full generated rego + classes).
    # Resolve the caller's allowed set fail-closed; a draft outside it is reported as 404 (never leak existence).
    _allowed = _resolve_namespaces(user, "all")  # None = unrestricted (admin/service)
    if _allowed is not None and r["namespace"] not in _allowed:
        raise HTTPException(status_code=404, detail="draft not found (regenerate from Attack Graph)")
    return {
        "draft_id": r["id"],
        "ns": r["namespace"],
        "cls": r["agent_class"],
        # Real affected class for display (== agent_class for non-remediation drafts, where
        # affected_class is NULL — the UI falls back to `cls` in that case).
        "affected_class": r["affected_class"],
        "rego": r["rego_source"],
        "allow_tools": list(r["allow_tools"] or []),
        "enabled": list(r["toggles"] or []),
        "priority": r["priority"],
        "covered_count": r["covered_count"],
        "total": r["total"],
        "would_block": r["would_block"],
        "would_allow": r["would_allow"],
        "created_by": r["created_by"] or "",
        "created_at": r["created_at"].isoformat() if r["created_at"] else "",
        "enforcement": "draft",
        # Provenance so the Policy Catalog review header can show "from OWASP LLM · LLM07 …".
        "source_framework": r["source_framework"],
        "source_control_id": r["source_control_id"],
        "source_control_name": r["source_control_name"],
    }


# ── Tool-verb promotion lifecycle (observe → infer → promote) ────────────────────────────────────────
# An unclassified tool stays in the OBSERVATION phase: its calls are logged (Monitor mode blocks nothing),
# and when the params reveal the operation the evaluate route stamps that verb as evidence on the audit row.
# These routes aggregate the evidence and let an admin PROMOTE the tool to a defined verb — a persisted
# override that from then on classifies the tool everywhere (allowlist chips, kill-chain hops).

_PROMOTABLE_VERBS = {"read", "write", "delete", "send"}
_EVIDENCE_WINDOW_DAYS = 7
_RISK_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


async def _verb_overrides(session: AsyncSession, namespaces: list[str] | None) -> dict[str, tuple[str, str]]:
    """{tool_name: (verb, risk)} of PROMOTED verbs in scope. On a multi-ns union the worst risk wins, so a
    tool promoted differently in two namespaces can never display the weaker classification."""
    if namespaces is None:
        rows = (await session.execute(text("SELECT tool_name, verb, risk FROM tool_verb_overrides"))).mappings().all()
    else:
        rows = (
            (
                await session.execute(
                    text("SELECT tool_name, verb, risk FROM tool_verb_overrides WHERE namespace = ANY(:nss)"),
                    {"nss": namespaces},
                )
            )
            .mappings()
            .all()
        )
    out: dict[str, tuple[str, str]] = {}
    for r in rows:
        cur = out.get(str(r["tool_name"]))
        if cur is None or _RISK_RANK.get(str(r["risk"]), 0) > _RISK_RANK.get(cur[1], 0):
            out[str(r["tool_name"])] = (str(r["verb"]), str(r["risk"]))
    return out


async def _verb_evidence(session: AsyncSession, namespaces: list[str] | None) -> dict[str, dict]:
    """OBSERVATION evidence per tool from the last 7 days of audit rows whose params revealed the
    operation: {tool: {"calls": N, "verbs": {"read": 12, "send": 2}}}."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=_EVIDENCE_WINDOW_DAYS)
    ns_filter = "" if namespaces is None else "AND namespace = ANY(:nss) "
    params: dict = {"cutoff": cutoff}
    if namespaces is not None:
        params["nss"] = namespaces
    rows = (
        (
            await session.execute(
                text(  # nosemgrep: python.sqlalchemy.security.audit.avoid-sqlalchemy-text.avoid-sqlalchemy-text
                    "SELECT tool_name, payload->>'op' AS op, count(*) AS n FROM audit_log "  # nosec B608 - ns_filter is a constant fragment; cutoff/namespaces bound via :cutoff/:nss params
                    "WHERE timestamp_utc >= :cutoff AND payload->>'op_src' = 'params' "
                    + ns_filter
                    + "GROUP BY tool_name, payload->>'op'"
                ),
                params,
            )
        )
        .mappings()
        .all()
    )
    out: dict[str, dict] = {}
    for r in rows:
        d = out.setdefault(str(r["tool_name"]), {"calls": 0, "verbs": {}})
        d["calls"] += int(r["n"])
        if r["op"]:
            d["verbs"][str(r["op"])] = d["verbs"].get(str(r["op"]), 0) + int(r["n"])
    return out


_VERB_RANK = {"read": 0, "write": 1, "send": 2, "delete": 3}


def _top_verb(evidence: dict | None) -> tuple[str | None, int]:
    """The MOST DESTRUCTIVE verb the observed params revealed, with its evidence count.

    Ranked by destructiveness first, frequency only as a tie-break. This used to sort by count first,
    which under-stated a tool's capability exactly when it mattered: a tool observed doing 4 reads and
    2 deletes was suggested to an admin as `read` / risk `low`, and promoting that suggestion would
    register a destructive tool as a harmless one. For an authorization decision the question is what
    the tool CAN do, not what it usually does — one observed delete makes it a delete tool.

    The full histogram travels alongside as `verbs`, so the admin still sees the frequency split; the
    headline just no longer rounds it toward safe.
    """
    verbs = (evidence or {}).get("verbs") or {}
    if not verbs:
        return None, 0
    verb, count = max(verbs.items(), key=lambda kv: (_VERB_RANK.get(kv[0], 0), kv[1]))
    return verb, count


@router.get("/threats/tool-verbs")
async def tool_verbs(
    ns: str = Query("all"),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """The classification lifecycle state for the scope: PROMOTED overrides + OBSERVATION-phase candidates
    (tools unclassifiable by name whose observed params revealed a verb, with the evidence histogram).
    Read-only — promotion itself is the admin-gated POST below."""
    namespaces = _resolve_namespaces(user, ns)
    if namespaces is None:
        orows = (
            (
                await session.execute(
                    text(
                        "SELECT namespace, tool_name, verb, risk, promoted_by, evidence, created_at "
                        "FROM tool_verb_overrides ORDER BY created_at DESC"
                    )
                )
            )
            .mappings()
            .all()
        )
    else:
        orows = (
            (
                await session.execute(
                    text(
                        "SELECT namespace, tool_name, verb, risk, promoted_by, evidence, created_at "
                        "FROM tool_verb_overrides WHERE namespace = ANY(:nss) ORDER BY created_at DESC"
                    ),
                    {"nss": namespaces},
                )
            )
            .mappings()
            .all()
        )
    promoted_names = {str(r["tool_name"]) for r in orows}
    evidence = await _verb_evidence(session, namespaces)
    candidates = []
    for tool, d in evidence.items():
        if tool in promoted_names or classify_tool(tool)[0] is not Verb.UNKNOWN:
            continue  # already promoted, or the name classifier resolves it now — not a candidate
        verb, count = _top_verb(d)
        risk = default_risk_of_verb(Verb(verb)) if verb else None
        candidates.append(
            {
                "tool_name": tool,
                "calls": d["calls"],
                "verbs": d["verbs"],
                "inferred_verb": verb,
                "inferred_count": count,
                "suggested_risk": risk.value if risk else None,
            }
        )
    candidates.sort(key=lambda c: -c["calls"])
    return {
        "namespaces": namespaces or [],
        "overrides": [
            {
                "namespace": str(r["namespace"]),
                "tool_name": str(r["tool_name"]),
                "verb": str(r["verb"]),
                "risk": str(r["risk"]),
                "promoted_by": str(r["promoted_by"] or ""),
                "evidence": r["evidence"],
                "created_at": r["created_at"].isoformat() if r["created_at"] else "",
            }
            for r in orows
        ],
        "candidates": candidates,
    }


class PromoteToolVerbRequest(BaseModel):
    ns: str
    tool_name: str
    verb: str  # read | write | delete | send


async def warm_verb_overrides(evaluator, session) -> int:
    """Seed the evaluator's in-proc promoted-verb map from `tool_verb_overrides`.

    Called at startup and after each promotion AND demotion. Without it a promotion is CONSOLE-ONLY:
    the Threats screen shows the tool classified, and `input.derived.verb` in a policy still reads
    `unknown`, so promoting looks effective and changes nothing about enforcement.

    Demotion needs it just as much, and asymmetrically worse. `_derived_input` resolves the verb as
    `max((classifier_verb, promoted), key=_PROMOTION_RANK)`, so a promoted entry left in the map WINS
    over the `unknown` a demotion restores — the retracted verb keeps enforcing.

    Best-effort — a DB hiccup must not block startup or fail an admin's promote/demote. On a missed
    promote the map stays as it was, which is stale but never wrong-by-invention. On a missed DEMOTE
    "as it was" means still promoted, so the map keeps asserting a verb the operator retracted; that is
    the price of not failing a request whose row is already durably committed, and the next
    promote/demote or a restart re-seeds it.
    """
    try:
        rows = (await session.execute(
            text("SELECT namespace, tool_name, verb FROM tool_verb_overrides")
        )).mappings().all()
        return await evaluator.refresh_verb_overrides(rows)
    except Exception as exc:  # noqa: BLE001 - warm is best-effort; never block startup or a promote
        log.warning("nrvq.api.verb_overrides.warm_failed", error=str(exc), code="NRVQ-API-7093")
        return 0


@router.post("/threats/tool-verbs/promote")
async def promote_tool_verb(
    body: PromoteToolVerbRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """PROMOTE an observed tool to a defined verb (admin): persists the override with the evidence that
    justified it. Risk follows the canonical verb→risk map (delete=critical, write/send=high, read=low) so
    a promotion can never under-declare.

    The promotion also reaches ENFORCEMENT: the evaluator's in-proc map is re-seeded here so
    `input.derived.verb` reports the promoted verb on the very next call. Before this it did not, and a
    promotion was console-only — the Threats screen showed the tool classified while a verb-gated policy
    still saw `unknown`, so promoting looked effective and changed nothing."""
    require_admin(user)
    ns_val = body.ns.strip()
    tool = body.tool_name.strip()
    verb = body.verb.strip().lower()
    if not ns_val or not tool:
        raise HTTPException(status_code=400, detail="ns and tool_name are required")
    if verb not in _PROMOTABLE_VERBS:
        raise HTTPException(status_code=400, detail=f"verb must be one of {sorted(_PROMOTABLE_VERBS)}")
    risk = default_risk_of_verb(Verb(verb))
    evidence = (await _verb_evidence(session, [ns_val])).get(tool)
    await session.execute(
        text(
            "INSERT INTO tool_verb_overrides (namespace, tool_name, verb, risk, promoted_by, evidence, created_at) "
            "VALUES (:ns, :tool, :verb, :risk, :by, CAST(:ev AS JSONB), now()) "
            "ON CONFLICT (namespace, tool_name) DO UPDATE SET verb = EXCLUDED.verb, risk = EXCLUDED.risk, "
            "promoted_by = EXCLUDED.promoted_by, evidence = EXCLUDED.evidence, created_at = now()"
        ),
        {
            "ns": ns_val,
            "tool": tool,
            "verb": verb,
            "risk": risk.value if risk else "low",
            "by": str(user.get("sub") or user.get("username") or ""),
            "ev": json.dumps(evidence) if evidence else None,
        },
    )
    await session.commit()
    log.info(
        "nrvq.api.toolverb.promote",
        ns=ns_val,
        tool=tool,
        verb=verb,
        calls=(evidence or {}).get("calls", 0),
        code="NRVQ-API-7110",
    )
    # Re-seed the enforcement map so the promotion takes effect immediately rather than at the next
    # restart. Best-effort by construction: a failure here leaves the map stale, never wrong, and
    # must not fail a promotion that is already durably committed above.
    evaluator = getattr(getattr(request.app, "state", None), "evaluator", None)
    if evaluator is not None:
        await warm_verb_overrides(evaluator, session)
    return {"promoted": True, "ns": ns_val, "tool_name": tool, "verb": verb, "risk": risk.value if risk else "low"}


@router.delete("/threats/tool-verbs")
async def demote_tool_verb(
    request: Request,
    ns: str = Query(...),
    tool_name: str = Query(...),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """DEMOTE a promoted tool back to the observation phase (admin) — deletes the override; the tool shows
    as 'unclassified · observing' again and keeps accruing evidence."""
    require_admin(user)
    res = await session.execute(
        text("DELETE FROM tool_verb_overrides WHERE namespace = :ns AND tool_name = :tool"),
        {"ns": ns, "tool": tool_name},
    )
    await session.commit()
    removed = int(getattr(res, "rowcount", 0) or 0)
    log.info("nrvq.api.toolverb.demote", ns=ns, tool=tool_name, removed=removed, code="NRVQ-API-7111")
    # Re-seed for the SAME reason promote does, and this direction is the dangerous one. `_derived_input`
    # resolves the verb as `max((classifier_verb, promoted), key=_PROMOTION_RANK)`, so a stale promoted
    # verb WINS over the `unknown` the demotion was supposed to restore. Without this the row is gone,
    # the Threats screen reads the DB and shows the tool back as observing, and enforcement keeps using
    # the retracted verb until the pod restarts or some unrelated promote happens to rebuild the whole
    # map. Which way that breaks depends on the rule: a grant keyed on `verb == "read"` stays live after
    # the admin revoked it, and a tool demoted from "send" keeps tripping the shipped egress block with
    # no console remedy.
    evaluator = getattr(getattr(request.app, "state", None), "evaluator", None)
    if evaluator is not None:
        await warm_verb_overrides(evaluator, session)
    return {"demoted": removed > 0, "ns": ns, "tool_name": tool_name}


@router.get("/threats/intent-suggest", response_model=IntentSuggestResponse)
async def intent_suggest(
    ns: str = Query("all"),
    cls: str = Query(...),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Suggest the intended ALLOWLIST for an agent class: the tools agents of the class ACTUALLY call
    (from the asset-graph edges + real 24h decision history), tagged egress/chokepoint and flagged if they
    sit on a derived attack path. Read-only — this only reads the graph + audit history, never writes or
    enforces. The operator seeds the intent allowlist from this, then drafts (default-deny) around it."""
    namespaces = _resolve_namespaces(user, ns)
    nodes_by_id, out_edges, seen = await _assemble(session, namespaces)
    paths, _, _ = await _derive_paths(session, namespaces, cls)

    # This class's chokepoint tools + the target each reaches on an attack path, and the tools on any step.
    chokepoints: set[str] = set()
    tool_target: dict[str, str] = {}
    path_step_tools: set[str] = set()
    for p in paths:
        if p.cls != cls:
            continue
        if p.tool:
            chokepoints.add(p.tool)
            # A tool-terminal path's target IS the tool — a self-referential "reached X via X" flag is
            # noise, so only record a target the tool actually goes on to reach.
            if p.tgt != p.tool:
                tool_target.setdefault(p.tool, p.tgt)
        for s in p.steps:
            if s.kind == "tool":
                path_step_tools.add(s.to)

    egress_lower = {t.lower() for t in EGRESS_TOOLS}
    agg: dict[str, dict] = {}
    for node in nodes_by_id.values():
        if node["type"] != "agent" or str(node["props"].get("agent_class") or "") != cls:
            continue
        for e in out_edges.get(node["id"], []):
            tgt = nodes_by_id.get(e["target"])
            if not tgt or tgt["type"] != "tool":
                continue
            name = tgt["name"]
            hist = e.get("hist") or {}
            allow = int(hist.get("allow") or 0)
            block = int(hist.get("block") or 0)
            cur = agg.setdefault(name, {"name": name, "allow": 0, "block": 0})
            cur["allow"] += allow
            cur["block"] += block

    # Classification lifecycle inputs: PROMOTED verbs outrank the name classifier; a tool neither
    # promoted nor name-classifiable surfaces its OBSERVATION evidence (inferred verb + call counts)
    # so the operator can promote it right from the allowlist row.
    overrides = await _verb_overrides(session, namespaces)
    evidence = await _verb_evidence(session, namespaces)

    tools: list[IntentSuggestTool] = []
    for name, d in agg.items():
        low = name.lower()
        if low in egress_lower:
            tag = "egress"
        elif name in chokepoints:
            tag = "chokepoint"
        else:
            tag = "normal"
        # Infer WHAT the tool does (read/write/delete/send) + risk — resolved even for cloud/opensource
        # tools whose data source isn't modelled, so the operator sees the operation while choosing an allowlist.
        op_val: str | None = None
        op_risk_val: str | None = None
        op_src: str | None = None
        observed_calls = 0
        inferred_verb: str | None = None
        inferred_count = 0
        ov = overrides.get(name)
        if ov:
            op_val, op_risk_val, op_src = ov[0], ov[1], "learned"
        else:
            op, op_risk = classify_tool(name)
            if op != Verb.UNKNOWN:
                op_val = op.value
                op_risk_val = op_risk.value if op_risk else None
                op_src = "registry"
            else:
                ev = evidence.get(name)
                if ev:
                    observed_calls = int(ev.get("calls") or 0)
                    inferred_verb, inferred_count = _top_verb(ev)
        tools.append(
            IntentSuggestTool(
                name=name,
                allow=d["allow"],
                block=d["block"],
                tag=tag,
                target=tool_target.get(name),
                in_attack_path=(name in path_step_tools or name in chokepoints),
                op=op_val,
                op_risk=op_risk_val,
                op_src=op_src,
                observed_calls=observed_calls,
                inferred_verb=inferred_verb,
                inferred_count=inferred_count,
            )
        )
    # Chokepoint/egress first (they most need an explicit intent decision), then by real traffic volume.
    _tag_rank = {"chokepoint": 0, "egress": 0, "normal": 1}
    tools.sort(key=lambda t: (_tag_rank.get(t.tag, 1), -(t.block + t.allow), t.name))
    log.info("nrvq.api.intent.suggest", ns=ns, cls=cls, count=len(tools), resolved=seen, code="NRVQ-API-7105")
    return IntentSuggestResponse(ns=seen, cls=cls, tools=tools)
