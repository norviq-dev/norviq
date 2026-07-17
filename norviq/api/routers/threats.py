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
rego in Policies (the existing F-40/F-51/R2-gated flow). The draft's priority == the namespace comprehensive
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
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin, require_target_cluster
from norviq.api.db.models import IntentDraft
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

_MAX_PATHS_PER_AGENT = 6
_MAX_PATHS = 200
_MAX_DEPTH = 4
_RESERVED_CLASSES = {"__baseline__", "__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__"}
_SENSITIVE = {"critical", "high"}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_STATUS_ORDER = {"exploitable": 0, "unsimulated": 1, "blocked": 2}


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


async def _assemble(session: AsyncSession, namespaces: list[str] | None):
    """Union the latest asset-graph snapshot(s) into nodes/edges with real decision history (like
    get_asset_graph). Returns (nodes_by_id, out_edges, seen_namespaces)."""
    snapshots = await _latest_snapshots(session, namespaces)
    multi = namespaces is None or len(namespaces) != 1
    hours = 24  # decision-history window handled by caller's range; assembly uses a wide-enough default
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    nodes_by_id: dict[str, dict] = {}
    out_edges: dict[str, list[dict]] = {}
    seen: set[str] = set()
    for ns, graph_json in snapshots:
        counts = await _decision_counts(session, ns, since)
        ns_nodes, ns_edges, _ = _snapshot_to_assets(ns, graph_json, counts, prefix_ids=multi)
        for n in ns_nodes:
            nodes_by_id[n.id] = {
                "id": n.id, "type": n.type, "name": n.name, "props": dict(n.properties or {}),
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


def _walk_paths(source: str, out_edges: dict[str, list[dict]], nodes_by_id: dict[str, dict]) -> list[list[str]]:
    """DFS simple kill-chains from an agent to a data node (or a terminal tool), depth <= _MAX_DEPTH."""
    out: list[list[str]] = []

    def dfs(node: str, path: list[str]) -> None:
        if len(out) >= _MAX_PATHS_PER_AGENT or len(path) > _MAX_DEPTH + 1:
            return
        nxt = out_edges.get(node, [])
        terminal = nodes_by_id.get(node, {}).get("type") == "data"
        if (terminal or not nxt) and len(path) >= 2:
            out.append(list(path))
            return
        for e in nxt:
            t = e["target"]
            if t in path:  # no cycles
                continue
            if t not in nodes_by_id:
                continue
            path.append(t)
            dfs(t, path)
            path.pop()
            if len(out) >= _MAX_PATHS_PER_AGENT:
                return

    dfs(source, [source])
    return out


def _build_path(
    node_ids: list[str],
    nodes_by_id: dict[str, dict],
    out_edges: dict[str, list[dict]],
    verb_overrides: dict[str, tuple[str, str]] | None = None,
    verb_evidence: dict[str, dict] | None = None,
) -> ThreatPath:
    src_node = nodes_by_id[node_ids[0]]
    tgt_node = nodes_by_id[node_ids[-1]]
    ns = str(src_node["props"].get("namespace") or "")
    cls = str(src_node["props"].get("agent_class") or "")
    trust = float(src_node["props"].get("trust_score") or 0.8)

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
        # CAP-2: on a tool→data hop, resolve the ACTUAL operation (read/write/delete/send) + its risk from
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
                to=bnode["name"], verb=("reaches" if bnode["type"] == "data" else "calls"),
                dec=dec, kind=bnode["type"], deny=block, allow=allow, would_block=wb,
                op=op_val, op_risk=op_risk_val, op_src=op_src_val,
                inferred_verb=inferred_verb, inferred_count=inferred_count, observed_calls=observed_calls,
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
    risk = min(1.0, (1.0 - trust) * 0.5 + tgt_sens * 0.35 + (0.15 if chokepoint else 0.0))
    sev = _severity_from(risk)

    if blocked:
        status, verdict = "blocked", f"Policy blocks the chokepoint '{chokepoint}' — path neutralized."
    elif would_blocked:
        # A policy covers the chokepoint but the namespace is in Monitor mode — logged, not enforced. This
        # is NOT an open path; rank it with blocked (covered) but tell the operator it isn't enforcing.
        status, verdict = "blocked", f"Monitor mode: '{chokepoint}' would be blocked (logged, not enforced) — switch to Block to enforce."
    elif any_allow_all and len(steps) > 0:
        status, verdict = "exploitable", f"Every hop has allowed traffic — '{chokepoint}' is reachable end-to-end."
    else:
        status, verdict = "unsimulated", "No end-to-end traffic yet — simulate to confirm reachability."

    return ThreatPath(
        id=_short_id(ns, node_ids[0], node_ids[-1], str(len(node_ids))),
        sev=sev, src=src_node["name"], tgt=tgt_node["name"], ns=ns, cls=cls,
        mitre=mitre_for_tool(chokepoint), hops=len(node_ids) - 1, trust=round(trust, 2),
        blast=blast, status=status, tool=chokepoint,
        reach=reach[:8], steps=steps, verdict=verdict, fix=recommended_fix(chokepoint),
    )


_POLICY_ALLOW_RE = re.compile(r'allow_names\s*:=\s*\{([^}]*)\}')
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
        rows = (await session.execute(
            text(f"SELECT DISTINCT ON (namespace, agent_class) agent_class, rego_source FROM policies "
                 f"WHERE {where} ORDER BY namespace, agent_class, version DESC"),
            params,
        )).mappings().all()
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
        am = _POLICY_ALLOW_RE.search(rego)
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
    name = (chokepoint or "").lower()
    if name not in p["allow"]:
        return "intent"
    if p["readonly"] and choke_verb in ("write", "delete", "send"):
        return "intent"
    return ""


async def _derive_paths(session: AsyncSession, namespaces: list[str] | None, cls: str | None) -> tuple[list[ThreatPath], list[str]]:
    nodes_by_id, out_edges, seen = await _assemble(session, namespaces)
    overrides = await _verb_overrides(session, namespaces)
    evidence = await _verb_evidence(session, namespaces)
    governing = await _governing_policies(session, namespaces)
    paths: list[ThreatPath] = []
    for nid, node in nodes_by_id.items():
        if not _is_source_agent(node):
            continue
        for chain in _walk_paths(nid, out_edges, nodes_by_id):
            p = _build_path(chain, nodes_by_id, out_edges, verb_overrides=overrides, verb_evidence=evidence)
            if cls and cls.lower() != "all" and p.cls != cls:
                continue
            # Mark whether an APPLIED policy governs this chokepoint (audit-derived status can lag a fresh
            # apply). Chokepoint verb: promoted override → name classifier.
            ov = overrides.get(p.tool)
            choke_verb = ov[0] if ov else (lambda v: v.value if v != Verb.UNKNOWN else None)(classify_tool(p.tool)[0])
            p.governed_by = _path_governed_by(governing, p.cls, p.tool, choke_verb)
            paths.append(p)
            if len(paths) >= _MAX_PATHS:
                break
        if len(paths) >= _MAX_PATHS:
            break
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
    return ordered, seen


@router.get("/threats/attack-paths", response_model=ThreatPathsResponse)
async def get_threat_paths(
    ns: str | None = Query(None),
    namespace: str | None = Query(None),  # P2-1: alias — the sibling graph endpoints spell it `namespace`
    cls: str | None = Query(None),
    range: str = Query("24h"),
    include_synthetic: bool = Query(False),  # A1: default-hide kill-chains rooted at seeded probe/test agents
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
    _ = RANGE_HOURS.get(range, 24)  # range validated; decision window handled in _assemble
    if ns is not None and namespace is not None and ns != namespace:
        raise HTTPException(status_code=400, detail="conflicting 'ns' and 'namespace' query parameters")
    requested = ns if ns is not None else (namespace if namespace is not None else "all")
    namespaces = _resolve_namespaces(user, requested)
    paths, seen = await _derive_paths(session, namespaces, cls)
    # A1: a kill-chain rooted at a synthetic/probe agent is test noise — hide it by default (toggle brings it back).
    synthetic_hidden = 0
    if not include_synthetic:
        kept = [p for p in paths if not is_synthetic_identity(p.cls, p.src)]
        synthetic_hidden = len(paths) - len(kept)
        paths = kept
    log.info("nrvq.api.attack_paths.served", ns=requested, cls=cls, count=len(paths),
             synthetic_hidden=synthetic_hidden, resolved=seen, code="NRVQ-API-7101")
    return ThreatPathsResponse(paths=paths, namespaces=seen, synthetic_hidden=synthetic_hidden)


async def _coverage(request: Request, session: AsyncSession, namespaces: list[str] | None,
                    cls: str, allow_tools: list[str], intent: Intent) -> tuple[str, list[str], list[str]]:
    """Generate the default-deny intent rego and DRY-RUN it against each path's chokepoint. Returns
    (rego, covered_ids, residual_ids). Uses the evaluator's isolated dry-run key — no persistence.
    Admin-PROMOTED verbs flow into the generation so the toggles honour them (a tool learned as delete
    is never treated as a read by Read-only, whatever its name says)."""
    overrides = await _verb_overrides(session, namespaces)
    learned = {tool: verb for tool, (verb, _risk) in overrides.items()}
    rego = generate_intent_rego(cls, allow_tools, intent, learned_verbs=learned)
    paths, _ = await _derive_paths(session, namespaces, cls)
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
    log.info("nrvq.api.intent.coverage", cls=body.cls, enabled=intent.enabled_keys(),
             covered=len(covered), total=total, code="NRVQ-API-7102")
    return IntentCoverageResponse(
        rego=rego, covered=covered, residual=residual, covered_count=len(covered), total=total,
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
            text("SELECT priority FROM policies WHERE namespace = '__cluster__' AND agent_class = '__baseline__' LIMIT 1")
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
    it in Policies (existing F-40/F-51/R2-gated flow). Its priority == the namespace baseline (tighten-only)."""
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

    draft_id = _short_id("draft", body.ns, body.cls, ",".join(allow_tools), ",".join(intent.enabled_keys())).replace("p", "d", 1)
    created_at = datetime.now(timezone.utc)
    # E1: DEDUPE BY CLASS — a (namespace, agent_class) keeps at most ONE pending Attack-Graph intent draft (the
    # latest). Prior drafts for the same class are cleared before insert so re-drafting overwrites instead of
    # piling up. F4: scope the delete to Attack-Graph drafts (source_control_id IS NULL) so it never clobbers a
    # compliance draft, which is deduped separately by (framework, control, class). Drafts are dry-run only.
    await session.execute(
        text("DELETE FROM intent_drafts WHERE namespace = :ns AND agent_class = :cls "
             "AND source_control_id IS NULL"),
        {"ns": body.ns, "cls": body.cls},
    )
    session.add(
        IntentDraft(
            id=draft_id, namespace=body.ns, agent_class=body.cls, rego_source=rego,
            allow_tools=allow_tools, toggles=intent.enabled_keys(), priority=priority,
            covered_count=len(covered), total=total, would_block=len(covered), would_allow=len(residual),
            created_by=str(user.get("sub") or ""), created_at=created_at,
            expires_at=draft_expiry(body.cls, created_at),  # Part B: TTL (24h test / 14d real)
        )
    )
    await session.commit()
    await enforce_draft_cap(session, body.ns)  # Part B: hard ceiling per namespace (evict oldest beyond it)
    log.info("nrvq.api.intent.draft_created", draft_id=draft_id, ns=body.ns, cls=body.cls,
             allow_tools=allow_tools, enabled=intent.enabled_keys(), covered=len(covered),
             priority=priority, enforcement="draft", actor=user.get("sub"), code="NRVQ-API-7103")
    return IntentDraftResponse(
        draft_id=draft_id, policy=f"{body.ns}/{body.cls}", ns=body.ns, cls=body.cls,
        deeplink=f"/policies/catalog?intent_draft={draft_id}", priority=priority, enforcement="draft",
        valid=valid, errors=errors, would_block=len(covered), would_allow=len(residual),
        covered_count=len(covered), total=total,
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
        e.target for e in edges
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
        blocked_tools.extend(
            _tools_reaching_source(nodes, edges, body.source_type, body.cls, {Verb(v) for v in verbs})
        )
    blocked_tools = sorted(set(blocked_tools))

    # Forward-guard fragments for the target verbs (so the policy blocks unobserved/renamed destructive
    # tools too, not just the ones seen today) — resolved from the same registry verbs the defense targets.
    frags = verb_fragments(body.source_type, [Verb(v) for v in verbs])
    rego = generate_capability_rego(
        body.source_type, cast(str, meta["source_display"]), body.cls, verbs, blocked_tools,
        cast(str, meta["rule_id"]), cast(str, meta["reason"]), verb_frags=frags,
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
        text("DELETE FROM intent_drafts WHERE namespace = :ns AND agent_class = :cls "
             "AND source_framework = 'capability' AND source_control_id = :cid"),
        {"ns": body.ns, "cls": body.cls, "cid": control_id},
    )
    session.add(
        IntentDraft(
            id=draft_id, namespace=body.ns, agent_class=body.cls, rego_source=rego,
            allow_tools=blocked_tools, toggles=verbs, priority=priority,
            covered_count=len(blocked_tools), total=len(blocked_tools),
            would_block=len(blocked_tools), would_allow=0,
            created_by=str(user.get("sub") or ""), created_at=created_at,
            source_framework="capability", source_control_id=control_id,
            source_control_name=f"{'/'.join(verbs)} on {meta['source_display']}",
            expires_at=draft_expiry(body.cls, created_at),
        )
    )
    await session.commit()
    await enforce_draft_cap(session, body.ns)
    log.info("nrvq.api.capability.defend", draft_id=draft_id, ns=body.ns, cls=body.cls,
             source=body.source_type, verbs=verbs, blocked_tools=blocked_tools, priority=priority,
             enforcement="draft", actor=user.get("sub"), code="NRVQ-API-7110")
    return CapabilityDefendResponse(
        draft_id=draft_id, deeplink=f"/policies/catalog?intent_draft={draft_id}",
        ns=body.ns, cls=body.cls, source_type=body.source_type, verbs=verbs,
        blocked_tools=blocked_tools, forward_guard_verbs=verbs,
        read_only=bool(meta["read_only"]), valid=valid, errors=errors,
    )


@router.get("/threats/intent-drafts", response_model=IntentDraftPage)
async def list_intent_drafts(
    ns: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int | None = Query(None, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Part B (B6): a BOUNDED, paginated page of pending intent drafts (non-enforcing) + the total count, so the
    Policy Catalog never renders the whole list at once. Reads from the dedicated table — never ``policies``.

    SECURITY (IDOR + read-causes-cross-tenant-write): the caller's namespace set is resolved FAIL-CLOSED via
    _resolve_namespaces (a scoped tenant naming another namespace gets 403; "all"/none → only its own), so this
    endpoint can no longer enumerate/read every tenant's drafts, and the lazy GC is scoped to that same set so a
    read-only viewer can no longer DELETE another namespace's rows through a GET."""
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
    total = int((await session.execute(text(f"SELECT COUNT(*) FROM intent_drafts{where}"), params)).scalar() or 0)
    rows = (await session.execute(
        text("SELECT id, namespace, agent_class, affected_class, allow_tools, toggles, covered_count, total, "
             "created_by, created_at, source_framework, source_control_id, source_control_name, expires_at "
             f"FROM intent_drafts{where} ORDER BY created_at DESC OFFSET :off LIMIT :lim"),
        {**params, "off": int(offset), "lim": page},
    )).mappings().all()
    drafts = [IntentDraftSummary(
        draft_id=r["id"], ns=r["namespace"], cls=r["agent_class"],
        # COMP-GEN-01 fix: for a remediation draft, `agent_class`/`cls` is now the compound persistence
        # overlay key ("<class>__remediation__") — `affected_class` carries the real class for display.
        affected_class=r["affected_class"],
        enabled=list(r["toggles"] or []), allow_tools=list(r["allow_tools"] or []),
        covered_count=r["covered_count"], total=r["total"],
        created_by=r["created_by"] or "",
        created_at=r["created_at"].isoformat() if r["created_at"] else "",
        source_framework=r["source_framework"], source_control_id=r["source_control_id"],
        source_control_name=r["source_control_name"],
        expires_at=r["expires_at"].isoformat() if r["expires_at"] else "",
    ) for r in rows]
    log.info("nrvq.api.intent.draft_listed", returned=len(drafts), total=total, offset=offset, code="NRVQ-API-7104")
    return IntentDraftPage(drafts=drafts, total=total, returned=len(drafts), offset=int(offset), limit=page)


@router.delete("/threats/intent-drafts/{draft_id}")
async def dismiss_intent_draft(
    draft_id: str,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Part B (B7): manually dismiss ONE pending draft. Non-enforcing only (the evaluator never reads this table),
    so this can never change enforcement. Admin-gated like the other draft mutations."""
    require_admin(user)
    result = await session.execute(text("DELETE FROM intent_drafts WHERE id = :id"), {"id": draft_id})
    await session.commit()
    dismissed = int(result.rowcount or 0)
    log.info("nrvq.api.intent.draft_dismissed", draft_id=draft_id, dismissed=dismissed, actor=user.get("sub"),
             code="NRVQ-API-7114")
    if not dismissed:
        raise HTTPException(status_code=404, detail="draft not found")
    return {"dismissed": True, "draft_id": draft_id}


@router.post("/threats/intent-drafts/gc")
async def gc_intent_drafts(
    ns: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """Part B (B7): bulk "Clear expired" — delete all expired non-enforcing drafts on demand. Safe: never touches
    an enforcing policy or version (drafts live in the dedicated non-enforcing table)."""
    require_admin(user)
    removed = await gc_expired_drafts(session, ns)
    return {"cleared": removed, "namespace": ns}


@router.get("/threats/intent-drafts/{draft_id}")
async def get_intent_draft(draft_id: str, session: AsyncSession = Depends(get_session),
                           user: dict = Depends(get_current_user)) -> dict:
    """Fetch one pending draft in full (incl. the generated rego) so the Policies page can review + apply
    it via the existing gated create/apply flow. Read-only SELECT from ``intent_drafts`` — never enforces."""
    r = (
        await session.execute(
            text(
                "SELECT id, namespace, agent_class, affected_class, rego_source, allow_tools, toggles, priority, "
                "covered_count, total, would_block, would_allow, created_by, created_at, "
                "source_framework, source_control_id, source_control_name "
                "FROM intent_drafts WHERE id = :id LIMIT 1"
            ),
            {"id": draft_id},
        )
    ).mappings().first()
    if r is None:
        raise HTTPException(status_code=404, detail="draft not found (regenerate from Attack Graph)")
    # SECURITY (IDOR): a scoped tenant must not read another namespace's draft (full generated rego + classes).
    # Resolve the caller's allowed set fail-closed; a draft outside it is reported as 404 (never leak existence).
    _allowed = _resolve_namespaces(user, "all")  # None = unrestricted (admin/service)
    if _allowed is not None and r["namespace"] not in _allowed:
        raise HTTPException(status_code=404, detail="draft not found (regenerate from Attack Graph)")
    return {
        "draft_id": r["id"], "ns": r["namespace"], "cls": r["agent_class"],
        # COMP-GEN-01 fix: real affected class for display (== agent_class for non-remediation drafts, where
        # affected_class is NULL — the UI falls back to `cls` in that case).
        "affected_class": r["affected_class"], "rego": r["rego_source"],
        "allow_tools": list(r["allow_tools"] or []), "enabled": list(r["toggles"] or []),
        "priority": r["priority"], "covered_count": r["covered_count"], "total": r["total"],
        "would_block": r["would_block"], "would_allow": r["would_allow"],
        "created_by": r["created_by"] or "",
        "created_at": r["created_at"].isoformat() if r["created_at"] else "", "enforcement": "draft",
        # F2: provenance so the Policy Catalog review header can show "from OWASP LLM · LLM07 …".
        "source_framework": r["source_framework"], "source_control_id": r["source_control_id"],
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
        rows = (await session.execute(
            text("SELECT tool_name, verb, risk FROM tool_verb_overrides")
        )).mappings().all()
    else:
        rows = (await session.execute(
            text("SELECT tool_name, verb, risk FROM tool_verb_overrides WHERE namespace = ANY(:nss)"),
            {"nss": namespaces},
        )).mappings().all()
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
    rows = (await session.execute(
        text(
            "SELECT tool_name, payload->>'op' AS op, count(*) AS n FROM audit_log "
            "WHERE timestamp_utc >= :cutoff AND payload->>'op_src' = 'params' "
            + ns_filter
            + "GROUP BY tool_name, payload->>'op'"
        ),
        params,
    )).mappings().all()
    out: dict[str, dict] = {}
    for r in rows:
        d = out.setdefault(str(r["tool_name"]), {"calls": 0, "verbs": {}})
        d["calls"] += int(r["n"])
        if r["op"]:
            d["verbs"][str(r["op"])] = d["verbs"].get(str(r["op"]), 0) + int(r["n"])
    return out


_VERB_RANK = {"read": 0, "write": 1, "send": 2, "delete": 3}


def _top_verb(evidence: dict | None) -> tuple[str | None, int]:
    """The verb the observed params suggest most often; an evidence-count tie breaks to the MORE
    destructive verb, so a promotion suggestion never under-states what the tool can do."""
    verbs = (evidence or {}).get("verbs") or {}
    if not verbs:
        return None, 0
    verb, count = max(verbs.items(), key=lambda kv: (kv[1], _VERB_RANK.get(kv[0], 0)))
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
        orows = (await session.execute(text(
            "SELECT namespace, tool_name, verb, risk, promoted_by, evidence, created_at "
            "FROM tool_verb_overrides ORDER BY created_at DESC"
        ))).mappings().all()
    else:
        orows = (await session.execute(text(
            "SELECT namespace, tool_name, verb, risk, promoted_by, evidence, created_at "
            "FROM tool_verb_overrides WHERE namespace = ANY(:nss) ORDER BY created_at DESC"
        ), {"nss": namespaces})).mappings().all()
    promoted_names = {str(r["tool_name"]) for r in orows}
    evidence = await _verb_evidence(session, namespaces)
    candidates = []
    for tool, d in evidence.items():
        if tool in promoted_names or classify_tool(tool)[0] is not Verb.UNKNOWN:
            continue  # already promoted, or the name classifier resolves it now — not a candidate
        verb, count = _top_verb(d)
        risk = default_risk_of_verb(Verb(verb)) if verb else None
        candidates.append({
            "tool_name": tool, "calls": d["calls"], "verbs": d["verbs"],
            "inferred_verb": verb, "inferred_count": count,
            "suggested_risk": risk.value if risk else None,
        })
    candidates.sort(key=lambda c: -c["calls"])
    return {
        "namespaces": namespaces or [],
        "overrides": [
            {
                "namespace": str(r["namespace"]), "tool_name": str(r["tool_name"]),
                "verb": str(r["verb"]), "risk": str(r["risk"]),
                "promoted_by": str(r["promoted_by"] or ""), "evidence": r["evidence"],
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


@router.post("/threats/tool-verbs/promote")
async def promote_tool_verb(
    body: PromoteToolVerbRequest,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> dict:
    """PROMOTE an observed tool to a defined verb (admin): persists the override with the evidence that
    justified it. Risk follows the canonical verb→risk map (delete=critical, write/send=high, read=low) so
    a promotion can never under-declare. Classification-only — the evaluator never reads this table."""
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
            "ns": ns_val, "tool": tool, "verb": verb, "risk": risk.value if risk else "low",
            "by": str(user.get("sub") or user.get("username") or ""),
            "ev": json.dumps(evidence) if evidence else None,
        },
    )
    await session.commit()
    log.info("nrvq.api.toolverb.promote", ns=ns_val, tool=tool, verb=verb,
             calls=(evidence or {}).get("calls", 0), code="NRVQ-API-7110")
    return {"promoted": True, "ns": ns_val, "tool_name": tool, "verb": verb,
            "risk": risk.value if risk else "low"}


@router.delete("/threats/tool-verbs")
async def demote_tool_verb(
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
    paths, _ = await _derive_paths(session, namespaces, cls)

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
        tools.append(IntentSuggestTool(
            name=name, allow=d["allow"], block=d["block"], tag=tag,
            target=tool_target.get(name),
            in_attack_path=(name in path_step_tools or name in chokepoints),
            op=op_val, op_risk=op_risk_val, op_src=op_src,
            observed_calls=observed_calls, inferred_verb=inferred_verb, inferred_count=inferred_count,
        ))
    # Chokepoint/egress first (they most need an explicit intent decision), then by real traffic volume.
    _tag_rank = {"chokepoint": 0, "egress": 0, "normal": 1}
    tools.sort(key=lambda t: (_tag_rank.get(t.tag, 1), -(t.block + t.allow), t.name))
    log.info("nrvq.api.intent.suggest", ns=ns, cls=cls, count=len(tools),
             resolved=seen, code="NRVQ-API-7105")
    return IntentSuggestResponse(ns=seen, cls=cls, tools=tools)
