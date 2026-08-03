# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Intent endpoints — observe → propose → dry-run → draft.

    POST /api/v1/intents/compile   validate + compile to Rego. Nothing is stored.
    POST /api/v1/intents/propose   build a candidate intent from what a class actually did.
    POST /api/v1/intents/dry-run   replay recorded calls against a candidate. Nothing is stored.
    POST /api/v1/intents/drafts    persist a NON-ENFORCING draft for the gated Policies flow.
    GET  /api/v1/intents/drafts    list pending drafts.

There is no apply endpoint here, deliberately. A draft is persisted to ``intent_drafts`` — the
dedicated table the evaluator's ``_collect_candidates`` never reads — and applying it stays the
existing gated Policies flow. Adding a second path to ``policies`` would mean two ways to start
enforcing, one of which nobody reviews.

Relationship to ``/threats/intent-*``: those endpoints generate the original tool-allowlist intent
and count attack-path coverage. These compile the richer per-argument intent of DESIGN-NOTE §13 and
replay it against real traffic. Both write the same table and are applied the same way.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, require_admin
from norviq.api.db.models import AuditLogEntry, IntentDraft
from norviq.api.db.session import get_session
from norviq.api.routers.graphs import _resolve_namespaces
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.intent import IntentError, compile_intent, dry_run, propose_intent

log = structlog.get_logger()
router = APIRouter()

# Managed scopes that are not agent classes. Mirrors threats.py; drafting against one would target a
# policy row the catalog owns.
_RESERVED_CLASSES = {"__baseline__", "__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__"}

_MAX_SAMPLE_CALLS = 2000
_DRAFT_TTL_DAYS = 14


class SampleCall(BaseModel):
    """One call to replay. `tool_params` is optional — see `params_available` on the response."""

    tool_name: str = Field(max_length=255)
    tool_params: dict = Field(default_factory=dict)
    server: str = Field(default="", max_length=255)


class CompileRequest(BaseModel):
    intent: dict


class ProposeRequest(BaseModel):
    ns: str = "all"
    cls: str = Field(max_length=255)
    name: str = Field(default="proposed-intent", max_length=63)
    limit: int = Field(default=500, ge=1, le=_MAX_SAMPLE_CALLS)
    # Callers may supply calls directly when audit param capture is off (the default).
    calls: list[SampleCall] = Field(default_factory=list)


class DryRunRequest(BaseModel):
    ns: str = "all"
    cls: str = Field(max_length=255)
    intent: dict
    limit: int = Field(default=500, ge=1, le=_MAX_SAMPLE_CALLS)
    calls: list[SampleCall] = Field(default_factory=list)


class DraftRequest(BaseModel):
    ns: str = Field(max_length=255)
    cls: str = Field(max_length=255)
    intent: dict


def _policy_input(tool_name: str, tool_params: dict, agent_class: str, namespace: str, server: str = "") -> dict:
    """Build the same document the evaluator builds, so a replay exercises the real contract."""
    ev = OPAEvaluator.__new__(OPAEvaluator)  # only the pure derived-input helpers are used
    event = type("E", (), {"tool_name": tool_name, "tool_params": tool_params, "agent_identity": None})()
    return {
        "tool_name": tool_name,
        "tool_params": tool_params,
        "derived": ev._derived_input(event),
        "agent": {"agent_class": agent_class, "namespace": namespace},
        "trust_category": "high",
        "mcp": {"server": server} if server else {},
        "direction": "call",
    }


async def _recorded_calls(
    session: AsyncSession, namespaces: list[str] | None, agent_class: str, limit: int
) -> tuple[list[dict], bool]:
    """Recent audit rows for a class, as policy input documents.

    Returns (calls, params_available). Audit rows carry parameters only when
    ``NRVQ_AUDIT_PERSIST_PARAMS`` is on, and even then they are MASKED. Without them a proposal can
    only reach tool names and the verb derived from them — no recipient domains, no data classes, no
    SQL tables. That is a real ceiling on how tight an intent can be proposed, so it is reported
    rather than hidden: a caller seeing ``params_available: false`` should supply `calls` directly or
    turn param capture on before trusting a destination-level rule.
    """
    stmt = select(AuditLogEntry).where(AuditLogEntry.agent_class == agent_class)
    if namespaces is not None:
        stmt = stmt.where(AuditLogEntry.namespace.in_(namespaces))
    stmt = stmt.order_by(desc(AuditLogEntry.timestamp_utc)).limit(limit)
    rows = (await session.execute(stmt)).scalars().all()

    calls: list[dict] = []
    saw_params = False
    for row in rows:
        payload = row.payload or {}
        params = payload.get("masked_params") if isinstance(payload, dict) else None
        if isinstance(params, dict) and params:
            saw_params = True
        else:
            params = {}
        mcp = payload.get("mcp") if isinstance(payload, dict) else None
        server = str((mcp or {}).get("server", "")) if isinstance(mcp, dict) else ""
        calls.append(_policy_input(row.tool_name, params, agent_class, row.namespace, server))
    return calls, saw_params


def _sample_calls(body_calls: list[SampleCall], agent_class: str, namespace: str) -> list[dict]:
    return [
        _policy_input(c.tool_name, c.tool_params, agent_class, namespace, c.server)
        for c in body_calls
    ]


async def _opa_evaluator(request_scope_id: str):
    """An evaluator backed by the shared OPA server, loading the candidate under a scratch package.

    The module is removed afterwards. It is never written to ``policies``, so it cannot be picked up
    by the policy loader even transiently.
    """
    from norviq.engine.opa_client import OpaClient, rewrite_package

    client = OpaClient()
    package = f"norviq.intent_dryrun.{request_scope_id}"
    module_id = f"intent-dryrun-{request_scope_id}"

    async def evaluate(rego: str, payload: dict) -> dict:
        return await client.query(package, payload) or {}

    async def load(rego: str) -> None:
        await client.push_policy(module_id, rewrite_package(rego, package))

    async def unload() -> None:
        await client.delete_policy(module_id)

    return evaluate, load, unload, client


@router.post("/intents/compile")
async def compile_endpoint(body: CompileRequest, user: dict = Depends(get_current_user)):
    """Validate and compile. Returns the Rego an operator would be asked to approve."""
    try:
        compiled = compile_intent(body.intent)
    except IntentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "rego": compiled.rego,
        "rule_ids": list(compiled.rule_ids),
        "labels": compiled.labels,
        "sha256": hashlib.sha256(compiled.rego.encode()).hexdigest(),
    }


@router.post("/intents/propose")
async def propose_endpoint(
    body: ProposeRequest,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Propose a candidate intent from what the class actually did. Nothing is stored."""
    if body.cls in _RESERVED_CLASSES:
        raise HTTPException(status_code=422, detail=f"'{body.cls}' is a managed scope, not an agent class.")
    namespaces = _resolve_namespaces(user, body.ns)
    calls, params_available = await _recorded_calls(session, namespaces, body.cls, body.limit)
    if body.calls:
        ns = (namespaces or [""])[0]
        calls.extend(_sample_calls(body.calls, body.cls, ns))
        params_available = True
    if not calls:
        raise HTTPException(
            status_code=422,
            detail=f"no recorded traffic for class '{body.cls}'; run it in monitor mode first, or supply calls",
        )
    intent = propose_intent(body.name, body.cls, calls)
    log.info("nrvq.api.intent.proposed", cls=body.cls, rules=len(intent["call"]),
             sampled=len(calls), params_available=params_available, code="NRVQ-API-7110")
    return {"intent": intent, "sampled": len(calls), "params_available": params_available}


@router.post("/intents/dry-run")
async def dry_run_endpoint(
    body: DryRunRequest,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Replay recorded calls against a candidate intent. Enforces nothing, stores nothing."""
    if body.cls in _RESERVED_CLASSES:
        raise HTTPException(status_code=422, detail=f"'{body.cls}' is a managed scope, not an agent class.")
    namespaces = _resolve_namespaces(user, body.ns)
    try:
        compiled = compile_intent(body.intent)
    except IntentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    calls, params_available = await _recorded_calls(session, namespaces, body.cls, body.limit)
    if body.calls:
        ns = (namespaces or [""])[0]
        calls.extend(_sample_calls(body.calls, body.cls, ns))
        params_available = True
    if not calls:
        raise HTTPException(status_code=422, detail=f"no recorded traffic for class '{body.cls}' to replay")

    # Letter-prefixed: a Rego package segment may not start with a digit, and a raw hex scope starts
    # with one about 62% of the time — which presents as an intermittent "illegal number format"
    # parse error rather than anything that points at the package name.
    scope = "s" + uuid.uuid4().hex[:12]
    evaluate, load, unload, client = await _opa_evaluator(scope)
    try:
        await load(compiled.rego)
        # dry_run is sync; the OPA call is async, so the replay is driven here and the pure
        # accounting is reused rather than duplicated.
        # The OPA call is async and dry_run() is sync, so the replay is driven here and the pure
        # accounting is reused rather than duplicated. The closure hands back the pre-computed result
        # for each call in order.
        results = [await evaluate(compiled.rego, payload) for payload in calls]
        cursor = {"i": 0}

        def _replay(_rego: str, _payload: dict) -> dict:
            result = results[cursor["i"]]
            cursor["i"] += 1
            return result

        report = dry_run(compiled, calls, evaluator=_replay)
    finally:
        try:
            await unload()
        finally:
            await client.stop()

    log.info("nrvq.api.intent.dry_run", cls=body.cls, total=report.total,
             would_block=report.would_block, code="NRVQ-API-7111")
    out = report.as_dict()
    out["params_available"] = params_available
    return out


@router.post("/intents/drafts")
async def create_draft(
    body: DraftRequest,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Persist a NON-ENFORCING draft. Never writes to ``policies``; applying stays the gated flow."""
    require_admin(user)
    if body.cls in _RESERVED_CLASSES:
        raise HTTPException(status_code=422, detail=f"'{body.cls}' is a managed scope — draft a real agent class.")
    namespaces = _resolve_namespaces(user, body.ns)
    if namespaces is not None and body.ns not in namespaces:
        raise HTTPException(status_code=403, detail="namespace not permitted for this caller")
    try:
        compiled = compile_intent(body.intent)
    except IntentError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    draft_id = f"intent-{uuid.uuid4().hex[:16]}"
    session.add(
        IntentDraft(
            id=draft_id,
            namespace=body.ns,
            agent_class=body.cls,
            rego_source=compiled.rego,
            # `allow_tools` is the pre-existing column the Policy Catalog renders. The full intent
            # rides in `toggles` so the console can round-trip and re-edit it rather than being left
            # with generated Rego it cannot map back to the sentences that produced it.
            allow_tools={"rule_ids": list(compiled.rule_ids)},
            toggles={"intent": body.intent, "kind": "intent-v2"},
            priority=1,
            created_by=str(user.get("sub", "")),
            expires_at=datetime.now(UTC) + timedelta(days=_DRAFT_TTL_DAYS),
        )
    )
    await session.commit()
    log.info("nrvq.api.intent.draft_created", draft=draft_id, cls=body.cls,
             ns=body.ns, rules=len(compiled.rule_ids), code="NRVQ-API-7112")
    return {"draft_id": draft_id, "rule_ids": list(compiled.rule_ids), "enforcing": False}


def _mapping(value: object) -> dict:
    """The JSONB column as a mapping, whatever shape the row actually holds.

    `IntentDraft.toggles` / `.allow_tools` are typed `dict | None` and are ALSO written as lists by
    `threats.py` and `mitre.py`. Anything that is not a mapping yields an empty one, so a reader
    asking for a key gets the default instead of an AttributeError.
    """
    return value if isinstance(value, dict) else {}


@router.get("/intents/drafts")
async def list_drafts(
    ns: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
):
    """Pending intent drafts. Reads the dedicated table, never ``policies``."""
    namespaces = _resolve_namespaces(user, ns if ns is not None else "all")
    stmt = select(IntentDraft)
    if namespaces is not None:
        stmt = stmt.where(IntentDraft.namespace.in_(namespaces))
    stmt = stmt.order_by(desc(IntentDraft.created_at)).limit(limit)
    rows = (await session.execute(stmt)).scalars().all()
    return {
        "drafts": [
            {
                "draft_id": r.id,
                "namespace": r.namespace,
                "agent_class": r.agent_class,
                # `toggles` and `allow_tools` are typed `dict | None`, but THREE other producers
                # legitimately store a LIST in them: threats.py's intent generator (`enabled_keys()`),
                # its verb-promotion path (`verbs`), and mitre.py's control mapping (`usable` rule
                # ids). `threats.py` reads those back as `list(r["toggles"] or [])`, so both shapes
                # are real and long-standing.
                #
                # `(r.toggles or {}).get(...)` therefore raised AttributeError on any list-shaped row
                # — and because this is a LIST endpoint, one such row 500'd the whole drafts inbox for
                # every caller and every namespace. Creating a draft from the Attack Graph or from
                # MITRE permanently broke the inbox. Observed on AKS: a plain GET returned 500.
                #
                # Read defensively at the boundary rather than migrating the column: the list shape is
                # in use by shipped features and in existing rows, so narrowing it would be a breaking
                # change to fix a display default.
                "kind": _mapping(r.toggles).get("kind", "intent"),
                "rule_ids": _mapping(r.allow_tools).get("rule_ids", []),
                "would_block": r.would_block,
                "total": r.total,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "enforcing": False,
            }
            for r in rows
        ]
    }
