# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policy CRUD routes."""

from datetime import datetime, timedelta, timezone

import re
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace, require_admin, require_admin_or_service, require_target_cluster, scoped_namespace
from norviq.api.db.models import AuditLogEntry
from norviq.api.db.session import get_session
from norviq.api.routers.settings_router import assert_apply_allowed  # F-51: shared dry-run-only gate
from norviq.api.synthetic import is_synthetic_identity  # M3: exclude probe/test traffic from dry-run replay
from norviq.api.threat_intent import (  # COMP-GEN-02: accumulate remediation controls in the single overlay
    generate_remediation_overlay_rego, parse_remediation_controls, union_remediation_controls)
from norviq.config import settings

log = structlog.get_logger()
router = APIRouter()

# B-3 — reserved/managed scopes that DELETE must refuse (even via the raw API). Deleting any of these would
# silently move the fallback floor for a whole namespace: `__baseline__` (the per-ns default every class falls
# back to), the pack overlays (`__pack__`/`__pack_override__`/`__pack_weaken__`, owned by the packs router) and
# operator guardrails (`__guardrail__`). Unlike create — which intentionally ALLOWS `__guardrail__` (F-14) and
# only blocks the pack scopes — delete forbids the entire managed set, since a delete is destructive and there is
# no legitimate UI path to remove a managed scope (they are re-materialized from their own sources). The reserved
# `__cluster__` namespace (the cluster-wide baseline) is likewise undeletable.
_RESERVED_DELETE_CLASSES = ("__baseline__", "__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__")
_RESERVED_NAMESPACES = ("__cluster__",)
# POLICY-RESERVED-01: operator-authored reserved scopes an admin MAY remove via the explicit confirm-gated path.
# `__baseline__` and `__guardrail__` are authored through POST /policies (create ALLOWS them, F-14), so their absence
# of a revert path was a create/delete asymmetry — a high-priority `__baseline__` could shadow every class policy and
# never be removed. The pack overlays (`__pack__`/`__pack_override__`/`__pack_weaken__`) are EXCLUDED here: they are
# materialized/reverted by the packs router (`POST /policy-packs/{id}/disable`, `DELETE /policy-packs/override`), so a
# raw delete would desync that bookkeeping. `__cluster__` (the seeded cluster-wide baseline) is never deletable.
_OPERATOR_REVERTABLE_CLASSES = ("__baseline__", "__guardrail__")
# COMP-GEN-01 fix: the per-class compliance remediation overlay suffix. Applied compliance drafts land at
# "<real_class>__remediation__" (evaluator.py `_collect_candidates`/`_is_overlay`) — a DYNAMIC key, one per real
# class, so unlike the fixed names above it can't be a literal entry in `_RESERVED_DELETE_CLASSES` /
# `_OPERATOR_REVERTABLE_CLASSES`. It follows the `__guardrail__` precedent exactly: operator-authored via
# POST /policies (create does NOT block it, F-14 parity — see the create-path check below), reserved from a raw
# silent DELETE, but operator-REVERTABLE via the explicit `confirm_managed=true` admin-gated path — which deletes
# ONLY the overlay row, never the base `<real_class>` policy (a distinct loader key / DB row).
_REMEDIATION_OVERLAY_SUFFIX = "__remediation__"


def _is_remediation_overlay_class(agent_class: str) -> bool:
    """True for a per-class compliance remediation overlay key (COMP-GEN-01), e.g. "report-gen__remediation__" —
    never the base "report-gen" class itself. NOTE (known edge case, low-impact — not fixed here to keep this
    scoped): `__remediation__` is a RESERVED naming convention (mirrors `__pack__`/`__guardrail__`); a real
    agent_class that happens to be named with this suffix is treated as managed/reserved by the delete guard
    even though it is not actually an overlay. The evaluator's enforcement path (evaluator.py
    `_collect_candidates`) does not have this ambiguity — it tags overlay-ness via a provenance flag set at
    candidate construction, not by matching this suffix against a real class's own key. An admin can still
    delete a real class misnamed this way via `confirm_managed=true`."""
    return agent_class.endswith(_REMEDIATION_OVERLAY_SUFFIX) and agent_class != _REMEDIATION_OVERLAY_SUFFIX


def _reserved_scope_delete_error(namespace: str, agent_class: str) -> HTTPException | None:
    """Return a 422 for a delete that targets a reserved/managed scope, else None. Shared by the DELETE route so
    the guard lives in one place next to the reserved-scope set it enforces."""
    if (agent_class in _RESERVED_DELETE_CLASSES or namespace in _RESERVED_NAMESPACES
            or _is_remediation_overlay_class(agent_class)):
        return HTTPException(
            status_code=422,
            detail=f"'{namespace}/{agent_class}' is a managed scope and cannot be deleted — change a baseline via its "
                   "seed, sector packs via POST /api/v1/policy-packs/{id}/enable, and guardrails via their loader. "
                   "A compliance remediation overlay can be reverted via DELETE ...?confirm_managed=true (admin).",
        )
    return None


# C1: EXPLICIT allowlist of control-plane subs trusted to write/delete a policy OUTSIDE their own namespace.
# This must stay an allowlist, not a blanket "any non-apikey JWT" exemption — the sidecar's per-workload
# service JWT (webhook/injector.go `mintSidecarToken`, sub "norviq-sidecar") also satisfies "role=service,
# sub not apikey:*", and it is injected as a PLAIN ENV VAR into every workload pod (readable via
# `kubectl get pod -o yaml`), so treating "not an apikey" as "trusted for any namespace" let a sidecar token
# minted for namespace A POST/DELETE /policies for namespace B (cross-tenant policy tamper / enforcement
# kill). The sidecar is an enforcement PEP that only calls /evaluate — it has no legitimate reason to write
# policies at all, so it (and everything else not named here) is floored to its own `namespace` claim below,
# identically to a scoped apikey.
#
# Evidence for each entry (verified against HEAD, not assumed):
#   - "norviq-webhook": webhook/controller.go `bearerToken()` (~line 1043) mints {sub: "norviq-webhook",
#     role: "service", namespace: c.adminPolicyNamespace}. The controller watches AgentPolicy CRDs across
#     EVERY tenant namespace in the cluster and syncs each one via POST/DELETE /api/v1/policies for THAT
#     CRD's own namespace (controller.go ~line 1086 posts to "/api/v1/policies"; ~line 448/535 build a
#     per-object deletePath) — its own token's `namespace` claim is fixed to the admin/control namespace,
#     which is deliberately NOT the namespace it writes to. Genuinely cross-namespace by design; there is no
#     narrower floor to give it.
#
# Explicitly NOT allowlisted (verified they never call this router, so flooring them to their own namespace
# claim is safe and correct, not merely unused):
#   - "norviq-sidecar" (webhook/injector.go `mintSidecarToken`): the per-workload thin-proxy PEP; it only
#     calls /api/v1/evaluate. Its token DOES carry a namespace claim (its own pod's namespace), so flooring
#     it below is a correct no-op for its real traffic and a hard stop for a hijacked/leaked copy.
#   - "norviq-relay" / "norviq-fleet" (norviq/fleet_relay.py, norviq/fleet_puller.py, norviq/fleet/oidc_cc.py
#     `fleet_service_bearer`): the spoke<->hub fleet client. It only calls /api/v1/fleet/{heartbeat,rollup,
#     bundle,rollout} (scoped by `scoped_cluster`, a different guard) — never /api/v1/policies. Bundle
#     application on the spoke (`fleet_puller.py: FleetPolicyPuller.pull_once`) calls
#     `self._loader.create(...)` directly, in-process, bypassing this HTTP router and its auth entirely. Its
#     JWT also carries no `namespace` claim at all (only `cluster`), so if it ever DID reach this guard it
#     would fail-closed here rather than fail-open.
_TRUSTED_CROSS_NS_SUBS: frozenset[str] = frozenset({"norviq-webhook"})


# SECURITY (P1): the NrvqPolicy CRD caps a namespace policy's priority at 0-499 and reserves the
# clusterPriority band (500-1000) for admin-authored control-plane policies, but the generic
# POST /api/v1/policies never enforced that split — a namespace-scoped service-role API key (which passes
# require_admin_or_service and is floored to its own namespace, but is NOT an admin) could POST priority=800
# (200 OK) and shadow control-plane policy for its own namespace via the engine's highest-priority-wins
# precedence. Bound the band on the API too so the DB/OPA layer matches the CRD contract.
_CLUSTER_PRIORITY_FLOOR = 500  # first priority in the admin-only clusterPriority band (mirrors the CRD schema)


def _may_set_cluster_priority(user: dict) -> bool:
    """Whether a caller may write in the admin clusterPriority band (>= _CLUSTER_PRIORITY_FLOOR). Only a human
    admin, or the control-plane webhook controller — the one sub trusted to sync admin-authored clusterPriority
    CRDs (see _TRUSTED_CROSS_NS_SUBS) — qualifies. Every other principal, including a namespace-scoped
    service-role API key, is floored to the namespace band. Mirrors the _enforce_apikey_write_scope trust model
    so a scoped key cannot escalate priority any more than it can cross a namespace."""
    if str(user.get("role", "")).lower() == "admin":
        return True
    return str(user.get("sub") or "") in _TRUSTED_CROSS_NS_SUBS


def _enforce_priority_band(user: dict, priority: int) -> None:
    """SECURITY (P1): reject (422) a non-admin/non-control-plane write into the admin clusterPriority band so a
    namespace-scoped token cannot set priority >= _CLUSTER_PRIORITY_FLOOR and shadow control-plane policy. The
    legitimate namespace band (0-499) and the admin/controller cluster band are preserved. Rejected, not
    silently clamped, so the caller learns the write was refused (parity with the reserved-scope guards)."""
    if not _may_set_cluster_priority(user) and not (0 <= priority < _CLUSTER_PRIORITY_FLOOR):
        log.warning("nrvq.api.policy.priority_band_denied", priority=priority, actor=user.get("sub"),
                    actor_role=user.get("role"), code="NRVQ-API-7020")
        raise HTTPException(
            status_code=422,
            detail=f"priority {priority} is outside the namespace band (0-{_CLUSTER_PRIORITY_FLOOR - 1}); the "
                   f"clusterPriority band ({_CLUSTER_PRIORITY_FLOOR}-1000) is reserved for cluster administrators.",
        )


def _enforce_apikey_write_scope(user: dict, namespace: str) -> None:
    """A non-admin caller must not create/delete a policy OUTSIDE its own namespace (least-privilege).

    An admin issues an API key with a role AND a namespace claim (keys.py); scoping a `service`-role key to
    one tenant is an intentional least-privilege boundary, so a write/delete aimed at a different namespace
    is refused (403). A full admin (role 'admin') is unrestricted. Every OTHER principal — a scoped apikey
    (`sub` == 'apikey:<prefix>') AND every service JWT not on `_TRUSTED_CROSS_NS_SUBS` (including the
    per-workload sidecar token, see the allowlist comment above) — is floored to its own `namespace` claim;
    only the named control-plane subs get a cross-namespace exemption.
    """
    if str(user.get("role", "")).lower() == "admin":
        return
    sub = str(user.get("sub") or "")
    if sub in _TRUSTED_CROSS_NS_SUBS:
        return  # explicit control-plane allowlist — see _TRUSTED_CROSS_NS_SUBS for the evidence per entry
    claim = str(user.get("namespace") or "")
    if not claim or (namespace and namespace != claim):
        log.warning("nrvq.api.policy.write_scope_denied", requested=namespace, claim=claim, actor=sub,
                    code="NRVQ-API-7019")
        raise HTTPException(status_code=403, detail="Caller is not authorized to write policies for this namespace")


class PolicyCreate(BaseModel):
    """Policy create/update payload.

    M2: namespace/agent_class/policy_name/saved_by were previously unbounded free-text — a write-capable
    credential could submit an arbitrarily long string for any of them, held forever in memory + OPA + the
    DB (they are never truncated downstream). `max_length` bounds are a cheap DoS/storage-bloat floor; the
    limits are generous relative to any real k8s namespace/serviceaccount name (RFC 1123: <=63) or a
    human-authored policy name/actor label.
    """

    namespace: str = Field(max_length=128)
    agent_class: str = Field(max_length=128)
    rego_source: str
    enforcement_mode: str = "block"
    saved_by: str = Field(default="", max_length=128)
    priority: int = 100
    policy_name: str | None = Field(default=None, max_length=128)
    target: dict | None = None
    rules: list[str] | None = None


class RollbackRequest(BaseModel):
    """Rollback payload."""

    target_version: int


class ApplyRequest(BaseModel):
    """Policy apply payload."""

    target_type: str
    target_namespace: str
    target_name: str = ""
    target_kind: str = ""
    enforcement_mode: str = "block"


def _infer_target_type(ns: str, agent_class: str) -> str:
    """Classify a loader policy key into the UI's catalog tiers (class | namespace | workload)."""
    if ns == "__cluster__" or agent_class == "__baseline__" or agent_class.startswith("namespace:"):
        return "namespace"
    if ":" in agent_class:  # kind:name workload target, e.g. "deployment:checkout"
        return "workload"
    return "class"


async def _policy_match_counts(namespace: str | None) -> dict[tuple[str, str], int]:
    """B2: {(ns, class): governed-call count} from the audit log, in ONE grouped query, so a policy card can
    show real "matches" instead of a hardcoded 0. Acquires the session lazily + best-effort: if the DB is
    unavailable (or not initialized, e.g. a unit test with no DB) it returns an empty map — matches then falls
    back to 0 and the policy list still renders."""
    stmt = select(AuditLogEntry.namespace, AuditLogEntry.agent_class, func.count(AuditLogEntry.id)).group_by(
        AuditLogEntry.namespace, AuditLogEntry.agent_class
    )
    if namespace:
        stmt = stmt.where(AuditLogEntry.namespace == namespace)
    counts: dict[tuple[str, str], int] = {}
    try:
        provider = get_session()
        session = await provider.__anext__()
        try:
            for ns_v, cls_v, cnt in (await session.execute(stmt)).all():
                counts[(str(ns_v), str(cls_v))] = int(cnt)
        finally:
            await provider.aclose()
    except Exception as exc:  # noqa: BLE001 — matches is display-only; never fail the policy list on it
        log.warning("nrvq.api.policies.match_count_failed", error=str(exc), code="NRVQ-API-7012")
    return counts


@router.get("/policies")
async def list_policies(
    request: Request, namespace: str | None = Query(default=None), user: dict = Depends(get_current_user)
) -> list[dict]:
    """List policies loaded in memory. None/"all" => every namespace the caller may read (admin: all)."""
    namespace = read_namespace(user, namespace)  # None => all namespaces (admin); own ns for a tenant
    rows = []
    loader = request.app.state.loader
    match_map = await _policy_match_counts(namespace)  # B2: real governed-call counts (best-effort, no-DB-safe)
    for key, entry in loader._policies.items():
        ns, agent_class = key.split(":", 1)
        if namespace and ns != namespace:
            continue
        # FIX-2: surface the last-applied time so the Catalog card can reflect reality after an apply. Derived
        # from the latest in-memory version snapshot (present for anything applied this process lifetime); null
        # when unknown (e.g. warm-loaded on startup) — the card simply omits the timestamp then. No new column.
        versions = loader.get_versions(ns, agent_class)
        # C1: show the most recent of "last saved" (version) and "last applied" (apply event), so an apply
        # visibly re-stamps the card even when the rego content did not change.
        saved_at = versions[-1].saved_at if versions else None
        applied_at = loader.get_applied_at(ns, agent_class) if hasattr(loader, "get_applied_at") else None
        last_ts = max([t for t in (saved_at, applied_at) if t is not None], default=None)
        last_applied = last_ts.isoformat() if last_ts else None
        rows.append(
            {
                "namespace": ns,
                "agent_class": agent_class,
                "target_type": _infer_target_type(ns, agent_class),
                # M1: the current version is the LATEST version's number, not the count — with history
                # pruned (cap 10 / 90d) or partially rehydrated, len(versions) != the real version.
                "current_version": versions[-1].version if versions else 1,
                # M4: report the real enforcement_mode so the editor stops defaulting it to "audit" (which
                # silently rewrote every saved block policy to audit on the next Save).
                "enforcement_mode": str(entry.get("enforcement_mode", "block")),
                "rego_length": len(str(entry["rego"])),
                "priority": int(entry.get("priority", 100)),
                "last_applied": last_applied,
                "matches": match_map.get((ns, agent_class), 0),  # B2: real governed-call count
            }
        )
    log.info("nrvq.api.policies.listed", count=len(rows), code="NRVQ-API-7010")
    return rows


_LAYER_LABELS = {
    "__baseline__": "namespace baseline",
    "__pack__": "sector pack (overlay)",
    "__guardrail__": "tool-allowlist guardrail (overlay)",
    "__pack_override__": "pack override (overlay)",
}


@router.get("/policies/effective")
async def effective_policy(
    request: Request,
    namespace: str = Query("default"),
    agent_class: str = Query(...),
    user: dict = Depends(get_current_user),
) -> dict:
    """F-58: the EFFECTIVE policy stack governing a (namespace, agent_class) right now — the ordered candidate
    layers the evaluator ACTUALLY resolves. Strictly read-only/derived: it calls the same
    `evaluator._collect_candidates` enforcement uses, so it can never drift from real behaviour."""
    from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

    namespace = scoped_namespace(user, namespace) or "default"
    evaluator = request.app.state.evaluator
    event = ToolCallEvent(
        tool_name="__effective_probe__", tool_params={},
        agent_identity=AgentIdentity(
            spiffe_id=f"spiffe://norviq/ns/{namespace}/sa/{agent_class}", namespace=namespace, agent_class=agent_class),
        session_id="effective",
    )
    candidates = await evaluator._collect_candidates(event)
    layers = []
    for c in candidates:
        key = str(c["key"])
        ns, _, ac = key.partition(":")
        if ac == agent_class:
            label = "agent-class policy"
        elif ns == "__cluster__" and ac == "__baseline__":
            label = "cluster baseline (comprehensive)"
        elif _is_remediation_overlay_class(ac):
            # COMP-GEN-01: a per-class remediation overlay key is dynamic ("<class>__remediation__"), so it
            # can't be a literal _LAYER_LABELS entry — label it human-readably rather than showing the raw key.
            label = "compliance remediation (overlay)"
        else:
            label = _LAYER_LABELS.get(ac, ac)
        layers.append({
            "scope": key, "label": label, "priority": int(c.get("priority", 100)),
            # FIX-H6-2: use the provenance flag _collect_candidates tags at construction, not the key-suffix
            # heuristic — a real agent_class whose own key happens to end in a reserved suffix (e.g.
            # "...__remediation__") must show as its own base policy, never as an overlay.
            "overlay": bool(c.get("overlay", False)),
        })
    log.info("nrvq.api.policies.effective", namespace=namespace, agent_class=agent_class,
             layers=len(layers), code="NRVQ-API-7100")
    return {"namespace": namespace, "agent_class": agent_class, "layers": layers,
            "note": "overlay layers are tighten-only (can only make a decision stricter)"}


@router.get("/policies/{namespace}/{agent_class}")
async def get_policy(
    namespace: str, agent_class: str, request: Request, user: dict = Depends(get_current_user)
) -> dict:
    """Get one policy."""
    scoped_namespace(user, namespace)  # 403 if a non-admin reads another namespace's policy
    loader = request.app.state.loader
    rego = loader.get_current(namespace, agent_class)
    if rego is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    vers = loader.get_versions(namespace, agent_class)
    return {"namespace": namespace, "agent_class": agent_class, "rego_source": rego,
            "version": vers[-1].version if vers else 1}  # M1: real version number, not the count


@router.post("/policies")
async def create_policy(body: PolicyCreate, request: Request, user: dict = Depends(get_current_user), session: AsyncSession = Depends(get_session), _target: None = Depends(require_target_cluster)) -> dict:
    """Create or update a policy (admin, or the webhook controller's service identity)."""
    require_admin_or_service(user)
    _enforce_apikey_write_scope(user, body.namespace)  # a scoped API key may not write another namespace
    _enforce_priority_band(user, body.priority)  # P1: a scoped/non-admin caller may not set the admin clusterPriority band
    # H4: create loads straight into the read path (it ENFORCES on the next call), so a dry-run-only
    # namespace must reject it exactly like /apply does — else "Save" is a full apply the namespace claims
    # to forbid. (Dry-run + non-enforcing intent drafts stay allowed; they never touch this loader path.)
    await assert_apply_allowed(session, body.namespace)
    # Parity with delete: the `__cluster__` cluster-wide baseline is a managed scope (seeded by the loader, not the
    # generic policy endpoint) — a direct write here would move the whole-cluster fallback floor. Delete already
    # rejects it; create must too (no legitimate API caller POSTs to `__cluster__`).
    if body.namespace in _RESERVED_NAMESPACES:
        log.warning("nrvq.api.policy.reserved_scope", namespace=body.namespace, actor=user.get("sub"),
                    actor_role=user.get("role"), code="NRVQ-API-7016")
        raise HTTPException(
            status_code=422,
            detail=f"'{body.namespace}' is the managed cluster-baseline scope and cannot be written via this "
                   "endpoint — the cluster baseline is materialized by the loader/seed.",
        )
    validate_policy_create(body)
    agent_class = resolve_policy_key(body)
    # F-37: `__pack__` is a managed scope OWNED by the packs router (materialized from NamespacePack rows). A direct
    # write here is silently wiped the next time any pack is toggled (and reads as 0 coverage) — reject it and point
    # at the real enable path. (`__guardrail__` is intentionally operator-loaded via this endpoint, F-14.)
    # H5: include __pack_weaken__ — a direct create of it would bypass put_pack_override's OPA validation,
    # the tighten/weaken mutual-exclusion clearing, the loud weaken audit, and the admin-only gate (create
    # is reachable by the service role). (`__guardrail__` stays operator-loadable via this endpoint, F-14.)
    # COMP-GEN-01: a per-class remediation overlay (`<class>__remediation__`) is intentionally NOT blocked
    # here either — it follows the `__guardrail__` precedent (directly writable via this endpoint), which is
    # how the Policy Catalog's "Review & Apply" of a compliance draft persists it (see mitre.py
    # `_generate_remediation_draft`). It is still reserved from raw DELETE (see `_reserved_scope_delete_error`).
    if agent_class in ("__pack__", "__pack_override__", "__pack_weaken__"):
        log.warning("nrvq.api.policy.reserved_scope", namespace=body.namespace, agent_class=agent_class,
                    code="NRVQ-API-7016")
        raise HTTPException(
            status_code=422,
            detail=f"'{agent_class}' is a managed scope — enable a sector pack via POST /api/v1/policy-packs/{{id}}/enable "
                   "and customize it via PUT /api/v1/policy-packs/override, not the generic policy endpoint.",
        )
    loader = request.app.state.loader
    # M2: per-namespace hard cap on the COUNT of distinct policy scopes — mirrors the existing
    # `draft_cap_per_namespace` retention pattern (norviq/api/retention.py), applied to the policy catalog
    # instead of drafts. An UPDATE to an already-existing (namespace, agent_class) scope never grows the
    # count, so only a genuinely NEW scope is checked against the cap (DB-authoritative existence check —
    # holds across HA replicas even when this replica hasn't warmed the scope into memory yet). Duck-typed
    # (hasattr) like the evaluator hooks elsewhere in this codepath: the real PolicyLoader always implements
    # both methods, so this only ever no-ops for a minimal test double that doesn't.
    if hasattr(loader, "scope_exists") and not await loader.scope_exists(body.namespace, agent_class):
        cap = int(getattr(settings, "policy_scope_cap_per_namespace", 200))
        existing_count = await loader.count_namespace_scopes(body.namespace)
        if existing_count >= cap:
            log.warning("nrvq.api.policy.scope_cap_exceeded", namespace=body.namespace, agent_class=agent_class,
                        count=existing_count, cap=cap, actor=user.get("sub"), code="NRVQ-API-7120")
            raise HTTPException(
                status_code=429,
                detail=f"namespace '{body.namespace}' already has {existing_count} policy scopes (max {cap}) — "
                       "delete an unused scope before creating a new one.",
            )
    # COMP-GEN-02 (accumulate): the single "<class>__remediation__" overlay must hold the UNION of EVERY
    # applied compliance control, not just the last one. Apply is a full-replace UPSERT, so without this a
    # second applied control silently ERASED the first (false-coverage bug: the dashboard flipped the new
    # control to "enforced" while quietly reverting the previous one to "gap"). If the incoming rego is a
    # recognized compliance-remediation overlay (carries the COMP-GEN-02 manifest), merge its controls with
    # whatever the overlay already holds and re-materialize ONE combined rego. Any other rego (a manual
    # __guardrail__ load, a capability policy, arbitrary operator rego) does not parse to controls and is
    # left byte-identical — so this narrows strictly to the compliance-remediation flow.
    if _is_remediation_overlay_class(agent_class):
        incoming_controls = parse_remediation_controls(body.rego_source)
        if incoming_controls:
            base_class = agent_class[: -len(_REMEDIATION_OVERLAY_SUFFIX)]
            # COMP-GEN-02 (stale-read + read-modify-write race, live-reproduced): read the overlay's existing
            # controls DB-AUTHORITATIVELY (never the possibly-cold in-memory `_policies`, which on a peer/cold
            # replica is empty and made a concurrent/peer apply CLOBBER prior controls), and hold a Postgres
            # SESSION advisory lock keyed on (namespace, agent_class) across the read+merge+write so two
            # simultaneous applies to the SAME overlay serialize instead of racing (one silently dropping the
            # other's control). The lock is on a dedicated connection held for the whole critical section.
            async with loader._db_engine().connect() as _lk:
                await _lk.execute(text("SELECT pg_advisory_lock(hashtext(:k))"),
                                  {"k": f"nrvq:remediation:{body.namespace}:{agent_class}"})
                try:
                    existing = await loader.load_from_db(body.namespace, agent_class)
                    existing_rego = str(existing.get("rego", "") or "") if existing else ""
                    merged = union_remediation_controls(parse_remediation_controls(existing_rego), incoming_controls)
                    combined = generate_remediation_overlay_rego(base_class, merged)
                    validate_rego_source(combined, body.enforcement_mode)  # the merged rego re-clears the write gate
                    version = await loader.create(
                        body.namespace, agent_class, combined, saved_by=body.saved_by,
                        priority=body.priority, enforcement_mode=body.enforcement_mode, policy_name=body.policy_name)
                finally:
                    await _lk.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"),
                                      {"k": f"nrvq:remediation:{body.namespace}:{agent_class}"})
            log.info("nrvq.api.policy.remediation_accumulated", namespace=body.namespace, agent_class=agent_class,
                     controls=[c["control_id"] for c in merged], added=[c["control_id"] for c in incoming_controls],
                     version=version, actor=user.get("sub"), code="NRVQ-API-7123")
            return {"namespace": body.namespace, "agent_class": agent_class, "version": version,
                    "policy_name": body.policy_name, "priority": body.priority}
    version = await loader.create(
        body.namespace,
        agent_class,
        body.rego_source,
        saved_by=body.saved_by,
        priority=body.priority,
        enforcement_mode=body.enforcement_mode,
        policy_name=body.policy_name,
    )
    log.info(
        "nrvq.api.policy.created",
        namespace=body.namespace,
        agent_class=agent_class,
        version=version,
        priority=body.priority,
        policy_name=body.policy_name,
        actor=user.get("sub"),
        actor_role=user.get("role"),
        code="NRVQ-API-7011",
    )
    return {"namespace": body.namespace, "agent_class": agent_class, "version": version, "policy_name": body.policy_name, "priority": body.priority}


_DEFAULT_DECISION_RE = re.compile(r'\bdefault\s+decision\s*=\s*"(?:allow|block|escalate|audit)"')


def assert_decision_resolver(cleaned_rego: str) -> None:
    """A module MUST define a `decision` (the engine queries `data.<pkg>.decision`); a partial-set rule
    with no resolver leaves `decision` undefined and would silently ALLOW a fired block (P1-2). Accept the
    complete-rule form (`decision = "block"|"escalate" {`) OR partial sets accompanied by a resolver; when
    partial sets appear WITHOUT one, name that precisely so the guardrail/pack idiom stays authorable.
    `cleaned_rego` is comment-stripped source.

    FIX-3 (CRITICAL, silent-allow): a `decision = "block"|"escalate" { <condition> }` COMPLETE rule whose
    condition never matches the real input produces NO `decision` binding at all — OPA returns an empty
    result for that key, and the evaluator's `str(result.get("decision", "allow"))` (evaluator.py ~656/731)
    silently defaults to "allow", shadowing the cluster baseline at whatever priority the policy was pushed
    at. This is invisible in review because the rego LOOKS like a block policy. Every legitimate policy
    already declares `default decision = "..."` (comprehensive.rego, the sector packs, and every
    threat_intent.py template) so the resolver's output is always DEFINED — the author explicitly picks
    what "no rule matched" means for their policy. Requiring it here makes silent-allow structurally
    impossible for any admitted policy: a deliberate no-op "fake block" must now honestly spell out
    `default decision = "allow"` instead of relying on an absent binding. This check does NOT change the
    evaluator's runtime default (an absent `default decision` policy is rejected at write time instead —
    changing absent-at-runtime to fail-closed would break legitimate NARROW block policies whose whole
    point is to allow every non-matching tool).
    """
    if re.search(r'decision\s*=\s*"(block|escalate)"\s*\{', cleaned_rego):
        has_resolver = True
    elif re.search(r"\b(blocks|escalates|audits)\s*\[", cleaned_rego):
        raise HTTPException(
            status_code=422,
            detail="rego_source defines partial-set rules (blocks/escalates/audits) but no `decision` "
                   "resolver — append the canonical resolver so a fired rule becomes a decision, e.g.: "
                   '`block_fired { blocks[_] }` and `decision = "block" { block_fired }` (plus the '
                   "matching rule_id/reason lines; see comprehensive.rego RESOLVER-BEGIN..END), or author "
                   'a complete `decision = "block" { <condition> }` rule.',
        )
    else:
        raise HTTPException(status_code=422, detail="rego_source must include block or escalate decision")
    if has_resolver and not _DEFAULT_DECISION_RE.search(cleaned_rego):
        raise HTTPException(
            status_code=422,
            detail='rego_source must declare a `default decision = "allow"|"block"|"escalate"|"audit"` — '
                   "without one, a decision rule whose condition never matches real input produces no "
                   'binding and silently falls back to "allow" at evaluation time (a fired-block-turned-'
                   'silent-allow). Add e.g. `default decision = "allow"` at module scope; a policy that is '
                   'meant to always block should say so explicitly with `default decision = "block"`.',
        )


# S1: builtins that let a submitted policy escape the pure-decision sandbox. Each is a network/env/parser
# escape an attacker can drive purely through POST /policies/dry-run (or a policy create/pack-override) with
# NO redeploy required — the OPA compiler happily accepts them, so the reject has to happen HERE, before the
# rego ever reaches OPA:
#   http.send           - arbitrary outbound HTTP from inside the policy engine (SSRF: internal services,
#                          the cloud metadata endpoint, etc.)
#   opa.runtime         - dumps the OPA server's env vars / config (secret exfiltration)
#   net.*               - net.lookup_ip_addr / net.cidr_contains / net.cidr_expand / net.cidr_intersects /
#                          net.cidr_merge - network/DNS reconnaissance from inside the cluster
#   io.*                - io.jwt.decode/verify/encode (io.jwt) - token forging/inspection surface
#   rego.parse_module   - compiles rego AT EVAL TIME from attacker-controlled input - parser/sandbox escape
#   trace               - trace() - internal evaluation state disclosure
#   data.norviq.managed - FIX-1 (CRITICAL, cross-tenant read): OPA's shared managed server namespaces every
#                          pushed module under `data.norviq.managed.<sanitized-key>` (see
#                          `engine/opa_client.managed_package`/`rewrite_package`). At PUSH TIME the server
#                          REWRITES a submitted module's declared `package` line to its own computed
#                          `managed_package(f"{ns}:{class}")` — but it does NOT rewrite `data.` references
#                          left in the module BODY. The old own-package allowance below trusted the
#                          attacker-DECLARED `package` line: a tenant could declare `package
#                          norviq.managed.<victim-key>` (the victim's SERVER-COMPUTED package) as its own,
#                          pass the self-reference check, and read the victim's compiled policy — exfiltrated
#                          via the dry-run `reason` string. This ban is unconditional (checked before the
#                          own-package allowance, and before any self-reference logic runs) because no
#                          legitimate policy ever needs to reach into OPA's internal per-tenant namespace —
#                          every shipped/generated policy (comprehensive.rego, policies/sector/*.rego,
#                          threat_intent.py templates) only ever uses `input` + its own rules. Whitespace
#                          between the dots is tolerated (`data . norviq . managed`) since rego permits it.
_FORBIDDEN_REGO_TOKENS: frozenset[str] = frozenset({
    r"\bhttp\.send\b",
    r"\bopa\.runtime\b",
    r"\bnet\.[a-z_]+\b",
    r"\bio\.[a-z_]+\b",
    r"\brego\.parse_module\b",
    r"\btrace\s*\(",  # FIX-6: only the builtin CALL form — a bare identifier/var/rule named `trace` is legal rego
    r"\bdata\s*\.\s*norviq\s*\.\s*managed\b",  # FIX-1: no legit policy ever references OPA's internal per-tenant namespace
})


def _reject_forbidden_rego(dequoted: str) -> None:
    """S1/S12: reject a forbidden builtin (see `_FORBIDDEN_REGO_TOKENS`) or a `data.` reference OUTSIDE the
    module's own declared package (the cross-tenant/cross-package read exploited via
    `data.norviq.managed.<other-policy-key>`, which lets one namespace read another's compiled policy in the
    shared managed OPA server). `dequoted` must already be comment- AND string-literal-stripped (see
    `_strip_rego_comments` / `_strip_string_literals`) so a policy's own `reason`/comment text can mention
    these words freely — only actual rego references are rejected.
    """
    for pattern in _FORBIDDEN_REGO_TOKENS:
        if re.search(pattern, dequoted):
            raise HTTPException(
                status_code=422,
                detail="rego_source references a forbidden builtin/cross-package data (network/env access is "
                       "not permitted in policies)",
            )
    pkg_match = re.search(r"^\s*package\s+([A-Za-z0-9_.]+)", dequoted, flags=re.MULTILINE)
    own_pkg = pkg_match.group(1) if pkg_match else None
    for m in re.finditer(r"\bdata\.([A-Za-z0-9_.]*)", dequoted):
        ref = m.group(1)
        if own_pkg and (ref == own_pkg or ref.startswith(own_pkg + ".")):
            continue  # self-reference to the module's own declared package — legitimate
        raise HTTPException(
            status_code=422,
            detail="rego_source references a forbidden builtin/cross-package data (network/env access is "
                   "not permitted in policies)",
        )


def validate_rego_source(rego: str, enforcement_mode: str = "block") -> None:
    """Shared rego validation for every entry point that lets a caller submit rego: create, dry-run (S12 —
    dry-run previously skipped this entirely), and pack-override. Enforces the size/line/regex caps, the
    forbidden-builtin/cross-package reject (S1), and the decision-resolver shape check — in that order, so a
    submission is rejected by the cheapest check first."""
    if enforcement_mode not in {"block", "audit", "escalate"}:
        raise HTTPException(status_code=422, detail="invalid enforcement_mode")
    rego = rego or ""
    cleaned = _strip_rego_comments(rego)
    dequoted = _strip_string_literals(cleaned)
    if len(rego) > 65536:
        raise HTTPException(status_code=422, detail="rego_source exceeds max length")
    lines = [line for line in cleaned.splitlines() if line.strip()]
    if len(lines) > 500:
        raise HTTPException(status_code=422, detail="rego_source exceeds line limit")
    # Soft abuse heuristic (OPA uses linear-time RE2, so this is not a ReDoS guard). The shipped
    # comprehensive policy legitimately uses ~11 regex ops after the base64/PII/PCI detection rules,
    # so the cap must admit it with headroom.
    regex_ops = len(re.findall(r"\bregex\.[a-zA-Z0-9_]+\b", dequoted)) + len(re.findall(r"\bre_match\s*\(", dequoted))
    if regex_ops > 25:
        raise HTTPException(status_code=422, detail="too many regex operations")
    _reject_forbidden_rego(dequoted)  # S1: network/env/cross-package escape via a dangerous builtin or data ref
    assert_decision_resolver(cleaned)
    enforcement_bodies = re.findall(r'decision\s*=\s*"(?:block|escalate)"\s*\{([^}]*)\}', cleaned, flags=re.DOTALL)
    if enforcement_bodies and all(body.strip() == "false" for body in enforcement_bodies):
        raise HTTPException(status_code=422, detail="rego_source enforcement rule must be reachable")
    lowered = cleaned.lower()
    for required in ("decision", "rule_id", "reason"):
        if not re.search(rf"\b{required}\b", lowered):
            raise HTTPException(status_code=422, detail=f"rego_source must include {required}")


def validate_policy_create(body: PolicyCreate) -> None:
    """Validate policy payload for direct API writes (thin wrapper over `validate_rego_source`)."""
    validate_rego_source(body.rego_source or "", body.enforcement_mode)


def _strip_rego_comments(rego: str) -> str:
    lines = []
    for line in rego.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        lines.append(line)
    return "\n".join(lines)


def _strip_string_literals(rego: str) -> str:
    # Remove quoted strings so keyword scans do not match inside literals.
    return re.sub(r'"(?:\\.|[^"\\])*"', '""', rego)


def resolve_policy_key(body: PolicyCreate) -> str:
    """Resolve a stable loader key for namespace/workload policies."""
    if body.agent_class:
        return body.agent_class
    if body.policy_name:
        return body.policy_name
    target = body.target or {}
    target_kind = str(target.get("kind", "")).strip().lower()
    target_name = str(target.get("name", "")).strip()
    if target_kind and target_name:
        return f"{target_kind}:{target_name}"
    target_namespace = str(target.get("namespace", "")).strip()
    if target_namespace:
        return f"namespace:{target_namespace}"
    raise HTTPException(status_code=422, detail="agent_class or policy_name/target is required")


@router.delete("/policies/{namespace}/{agent_class}")
async def delete_policy(
    namespace: str, agent_class: str, request: Request, user: dict = Depends(get_current_user),
    confirm_managed: bool = Query(False), control_id: str | None = Query(None),
) -> dict:
    """Delete a policy from every layer (admin, or the webhook controller's service identity).

    POLICY-RESERVED-01: `confirm_managed=true` opts an ADMIN into removing an operator-authored reserved scope
    (`__baseline__`/`__guardrail__`) — the supported revert for the create/delete asymmetry (create permits them,
    delete previously refused all reserved scopes). Still refused with the flag: the `__cluster__` seeded baseline
    (never deletable) and the pack overlays (revert via the packs router). Without the flag the behavior is
    byte-identical to before.

    COMP-GEN-01: a per-class compliance remediation overlay (`<class>__remediation__`) follows the same
    `__guardrail__`-precedent revert path — `confirm_managed=true` + admin deletes ONLY the overlay row, never
    the base `<class>` policy (a distinct loader key / DB row), so an operator can undo an applied compliance
    control without touching the class's comprehensive policy."""
    require_admin_or_service(user)
    _enforce_apikey_write_scope(user, namespace)  # a scoped API key may not delete another namespace's policy
    if (confirm_managed and namespace not in _RESERVED_NAMESPACES
            and (agent_class in _OPERATOR_REVERTABLE_CLASSES or _is_remediation_overlay_class(agent_class))):
        # Explicit, admin-only revert of an operator-authored baseline/guardrail/remediation-overlay. NOT
        # require_admin_or_service: the webhook service identity and scoped API keys must never move a
        # namespace's fallback floor (or silently retract a compliance control).
        require_admin(user)
        log.warning("nrvq.api.policy.managed_scope_reverted", namespace=namespace, agent_class=agent_class,
                    actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7062")
    else:
        # B-3: refuse deletion of reserved/managed scopes (parity with the create/apply guards, which delete lacked —
        # a raw DELETE of `__baseline__`/`__pack__`/… would move the fallback floor for the whole namespace).
        reserved = _reserved_scope_delete_error(namespace, agent_class)
        if reserved is not None:
            hint = ""
            if confirm_managed and (agent_class in ("__pack__", "__pack_override__", "__pack_weaken__")):
                hint = " Revert sector-pack overlays via POST /api/v1/policy-packs/{id}/disable or DELETE /api/v1/policy-packs/override."
            elif confirm_managed and namespace in _RESERVED_NAMESPACES:
                hint = " The cluster-wide baseline is seeded and is never deletable via the API."
            log.warning("nrvq.api.policy.reserved_scope", namespace=namespace, agent_class=agent_class,
                        actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7017")
            raise HTTPException(status_code=reserved.status_code, detail=reserved.detail + hint) if hint else reserved
    loader = request.app.state.loader
    # COMP-GEN-02: per-control revert — `?control_id=<id>` removes ONE compliance control from the accumulated
    # overlay (re-materializing the union MINUS it) instead of deleting the whole overlay. Same admin +
    # confirm_managed gate as a full overlay delete (already enforced above). If it was the last control, fall
    # through to the normal full delete of the overlay key.
    if control_id and _is_remediation_overlay_class(agent_class):
        base_class = agent_class[: -len(_REMEDIATION_OVERLAY_SUFFIX)]
        # COMP-GEN-02 (stale-read over-delete, live-reproduced): read DB-AUTHORITATIVELY under the same advisory
        # lock as apply. Previously this read the possibly-cold in-memory `_policies`; on a cold/peer replica it
        # returned "" -> parse=[] -> remaining=[] -> the whole multi-control overlay was destroyed when the
        # operator asked to remove ONE control. DB-read + lock make the revert see the true control set and
        # serialize against a concurrent apply.
        _lock_k = f"nrvq:remediation:{namespace}:{agent_class}"
        async with loader._db_engine().connect() as _lk:
            await _lk.execute(text("SELECT pg_advisory_lock(hashtext(:k))"), {"k": _lock_k})
            try:
                existing = await loader.load_from_db(namespace, agent_class)
                existing_rego = str(existing.get("rego", "") or "") if existing else ""
                existing_priority = int(existing.get("priority", 1)) if existing else 1
                remaining = [c for c in parse_remediation_controls(existing_rego) if c["control_id"] != control_id]
                if remaining:
                    new_version = await loader.create(namespace, agent_class,
                                                      generate_remediation_overlay_rego(base_class, remaining),
                                                      saved_by=str(user.get("sub") or ""), priority=existing_priority,
                                                      enforcement_mode="block")
                else:
                    new_version = None  # last control removed -> fall through to a full delete of the overlay key
            finally:
                await _lk.execute(text("SELECT pg_advisory_unlock(hashtext(:k))"), {"k": _lock_k})
        if remaining:
            log.info("nrvq.api.policy.remediation_control_reverted", namespace=namespace, agent_class=agent_class,
                     removed=control_id, remaining=[c["control_id"] for c in remaining], actor=user.get("sub"),
                     actor_role=user.get("role"), code="NRVQ-API-7124")
            return {"deleted": True, "namespace": namespace, "agent_class": agent_class,
                    "removed_control": control_id, "remaining_controls": [c["control_id"] for c in remaining],
                    "version": new_version}
    # Capture the version being removed BEFORE the delete (get_versions is empty after) so the audit record names
    # exactly which version was destroyed.
    versions = loader.get_versions(namespace, agent_class)
    deleted_version = versions[-1].version if versions else None
    deleted = await loader.delete(namespace, agent_class)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy not found")
    # Audit every delete (actor, ns, class, version) with a code distinct from the match-count warning at :83.
    log.info("nrvq.api.policy.deleted", namespace=namespace, agent_class=agent_class, version=deleted_version,
             actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7018")
    return {"deleted": True, "namespace": namespace, "agent_class": agent_class, "version": deleted_version}


@router.get("/policies/{namespace}/{agent_class}/versions")
async def get_versions(
    namespace: str, agent_class: str, request: Request, user: dict = Depends(get_current_user)
) -> list[dict]:
    """Return policy version history, including each version's rego so the console can INSPECT a
    historical version read-only before restoring it (the rego already lives on the loader's
    PolicyVersion; it was previously dropped, which made the console's 'Load in Editor' show the
    current policy for every row — a lie). Bounded by the loader's in-memory cap (_MAX_VERSIONS = 10
    newest per scope; the DB retains more per policy_version_keep_count/keep_days = 20/90d), so
    returning the source per row is cheap."""
    scoped_namespace(user, namespace)  # 403 if a non-admin reads another namespace's versions
    versions = request.app.state.loader.get_versions(namespace, agent_class)
    return [
        {"version": v.version, "saved_by": v.saved_by, "saved_at": v.saved_at.isoformat(), "rego_source": v.rego_source}
        for v in versions
    ]


@router.post("/policies/{namespace}/{agent_class}/rollback")
async def rollback_policy(
    namespace: str,
    agent_class: str,
    body: RollbackRequest,
    request: Request,
    user: dict = Depends(get_current_user),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """Rollback policy to a previous version."""
    require_admin(user)
    # Parity with create/delete: rolling a reserved/managed scope (`__baseline__`/`__pack__`/… or the `__cluster__`
    # namespace) back to a prior version would move the fallback floor for the whole namespace out-of-band — the
    # managed scopes are re-materialized from their own sources, not version-rolled via this endpoint.
    reserved = _reserved_scope_delete_error(namespace, agent_class)
    if reserved is not None:
        log.warning("nrvq.api.policy.reserved_scope", namespace=namespace, agent_class=agent_class,
                    actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7017")
        raise reserved
    try:
        rego = await request.app.state.loader.rollback(namespace, agent_class, body.target_version)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    log.info("nrvq.api.policy.rolled_back", namespace=namespace, version=body.target_version,
             actor=user.get("sub"), actor_role=user.get("role"), code="NRVQ-API-7013")
    return {"rolled_back_to": body.target_version, "rego_length": len(rego)}


async def _validate_rego(evaluator, body: PolicyCreate) -> tuple[bool, list[str], dict | None]:
    """Compile + sample-evaluate the submitted rego via OPA; return (valid, errors, decision)."""
    errors: list[str] = []
    namespace = body.namespace or "default"
    agent_class = body.agent_class or "customer-support"
    sample_input = {
        "tool_name": "search_kb",
        "tool_params": {"query": "dry-run probe"},
        "agent": {
            "spiffe_id": f"spiffe://norviq/ns/{namespace}/sa/{agent_class}",
            "namespace": namespace,
            "agent_class": agent_class,
        },
        "trust_score": 0.8,
        "trust_category": "high",
        "session_id": "dry-run",
        "call_depth": 0,
    }
    decision: dict | None = None
    try:
        # Reuse the same OPA path real evaluation uses: this both compiles the rego and
        # confirms it yields a decision object (a syntax error makes opa exit non-zero → raises).
        # A distinct "dryrun:" key isolates the probe module so it never clobbers the live policy's
        # module in the shared OPA server (server mode).
        dry_key = f"dryrun:{namespace}:{agent_class}"
        decision = await evaluator._evaluate_opa(dry_key, namespace, agent_class, sample_input, body.rego_source)
        if decision.get("rule_id") == "evaluator_invalid_payload":
            errors.append("policy compiled but produced no valid decision object")
    except Exception as exc:
        # httpx timeouts stringify to "" — never surface a bare "opa evaluation failed: " (P1-2). Always
        # name the exception type and a fallback message so the console shows an actionable error.
        errors.append(f"opa evaluation failed: {type(exc).__name__}: {str(exc) or 'OPA request timed out'}")
    return (not errors), errors, decision


_DRYRUN_REPLAY_CAP = 500  # bound the replay so a busy namespace can't make dry-run unbounded


def _opa_input_from_record(rec: AuditLogEntry) -> dict:
    """Reconstruct the evaluator's OPA input from a stored audit record so the CANDIDATE rego can be
    replayed against the call it saw. tool_params come from the (optionally F-19-masked) payload — a
    class/tool-name-keyed policy replays exactly; a param-content rule under-fires on masked params
    (an honest limitation surfaced in the response)."""
    payload = rec.payload if isinstance(rec.payload, dict) else {}
    params = payload.get("masked_params") or payload.get("tool_params") or {}
    return {
        "tool_name": rec.tool_name,
        "tool_name_normalized": rec.tool_name,  # skeleton parity not reconstructable from the record; name is exact
        "tool_params": params if isinstance(params, dict) else {},
        "tool_params_normalized": params if isinstance(params, dict) else {},
        "agent": {
            "spiffe_id": rec.agent_id,
            "namespace": rec.namespace,
            "agent_class": rec.agent_class,
        },
        "trust_score": float(rec.trust_score or 0.0),
        "trust_category": "high" if (rec.trust_score or 0) >= 0.75 else "medium" if (rec.trust_score or 0) >= 0.5 else "low",
        "session_id": rec.session_id or "dry-run",
        "call_depth": 0,
    }


async def _replay_recent(evaluator, session, body: PolicyCreate, since) -> dict:
    """Replay the CANDIDATE rego against recent REAL traffic for the policy's scope and report what it
    would do — and crucially, how many currently-allowed calls it would NEWLY block (the decision-flip
    that tells an operator whether applying breaks legitimate traffic). Scoped to the target agent_class
    (a class-scoped policy can only flip its own class's calls); a class-less (namespace/workload) policy
    replays the whole namespace. Synthetic/red-team traffic is excluded — dry-run answers 'would this break
    REAL traffic'. The module is pushed to OPA once (digest-cached) then queried per record."""
    ns = body.namespace or "default"
    q = (
        select(AuditLogEntry)
        .where(AuditLogEntry.timestamp_utc >= since, AuditLogEntry.namespace == ns)
        # real traffic only: red-team is synthetic efficacy, not live traffic the policy must not break.
        .where(func.coalesce(AuditLogEntry.framework, "") != "redteam")
        .order_by(AuditLogEntry.timestamp_utc.desc())
        .limit(_DRYRUN_REPLAY_CAP + 1)
    )
    if body.agent_class:
        q = q.where(AuditLogEntry.agent_class == body.agent_class)
    rows = list((await session.scalars(q)).all())
    truncated = len(rows) > _DRYRUN_REPLAY_CAP
    rows = rows[:_DRYRUN_REPLAY_CAP]

    dry_key = f"dryrun:{ns}:{body.agent_class or '__all__'}"
    would_block = would_allow = would_escalate = newly_blocked = newly_allowed = 0
    flip_samples: list[dict] = []
    for rec in rows:
        # M3: the docstring promises synthetic traffic is excluded, but the query only drops framework=redteam.
        # Policy-tester / e2e / probe records are synthetic-but-not-redteam and would pollute the "would this
        # break REAL traffic" answer — filter them with the ONE shared classifier (mitre/redteam/retention use it).
        if is_synthetic_identity(rec.agent_class, getattr(rec, "agent_id", None)):
            continue
        try:
            dec = await evaluator._evaluate_opa(dry_key, ns, rec.agent_class, _opa_input_from_record(rec), body.rego_source)
        except Exception:
            continue  # a single bad record never sinks the whole simulation
        now = str(dec.get("decision", "allow"))
        was = str(rec.decision or "allow")
        if now == "block":
            would_block += 1
        elif now == "escalate":
            would_escalate += 1
        else:
            would_allow += 1
        # Decision flip vs what actually happened. was in {allow, audit(monitor)} but now blocked/escalated
        # = NEWLY restricted (the number that matters before applying).
        was_permissive = was in ("allow", "audit")
        now_restrictive = now in ("block", "escalate")
        if was_permissive and now_restrictive:
            newly_blocked += 1
            if len(flip_samples) < 8:
                flip_samples.append({"tool_name": rec.tool_name, "was": was, "now": now, "rule_id": str(dec.get("rule_id", ""))})
        elif was == "block" and now == "allow":
            newly_allowed += 1
    checked = len(rows)
    return {
        "total_records_checked": checked,
        "would_block": would_block,
        "would_allow": would_allow,
        "would_escalate": would_escalate,
        "newly_blocked": newly_blocked,
        "newly_allowed": newly_allowed,
        "newly_blocked_samples": flip_samples,
        "block_rate_pct": round((would_block / checked * 100) if checked else 0, 2),
        "truncated": truncated,
        "replay_cap": _DRYRUN_REPLAY_CAP,
    }


@router.post("/policies/dry-run")
async def dry_run_policy(
    body: PolicyCreate,
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """DRY-RUN: compile the submitted rego, then REPLAY it against recent real traffic for its scope and
    report what it would do — including the decision FLIPS (currently-allowed calls it would newly block).
    This replaces the old 'global historical block rate' (which reported what the LIVE policy already did,
    not what THIS candidate would do)."""
    # H7: dry-run REPLAYS the namespace's real 24h audit traffic — so it must be namespace-scoped like every
    # sibling read route, or a tenant scoped to ns A could replay ns B's tool names / rule_ids / decision
    # distribution via body.namespace. Admin = any ns; a tenant = own ns only.
    scoped_namespace(user, body.namespace or "default")
    # S12: dry-run COMPILES AND EXECUTES arbitrary submitted rego against the shared OPA server — that is a
    # write-class capability (it is not a passive read), so it needs the same role gate and namespace
    # write-scope guard `create_policy` requires, not just the read-scope check above. Without this a
    # namespace-unscoped viewer/read-only token could still probe http.send/opa.runtime/data.* through
    # dry-run even though it could never POST /policies. Mirrors create_policy's require_admin_or_service +
    # _enforce_apikey_write_scope exactly.
    require_admin_or_service(user)
    _enforce_apikey_write_scope(user, body.namespace or "default")
    # S1/S12: dry-run previously skipped validate_policy_create entirely — neither the size/line/regex caps
    # nor the forbidden-builtin/cross-package reject ran before the rego reached OPA. Run the SAME validation
    # create uses, BEFORE any compile/replay; its HTTPException(422) propagates to the client unmodified.
    validate_policy_create(body)
    evaluator = request.app.state.evaluator
    valid, errors, sample_decision = await _validate_rego(evaluator, body)
    since = datetime.now(timezone.utc) - timedelta(hours=24)

    if not valid:
        return {
            "valid": False, "errors": errors, "sample_decision": sample_decision,
            "total_records_checked": 0, "would_block": 0, "would_allow": 0, "would_escalate": 0,
            "newly_blocked": 0, "newly_allowed": 0, "newly_blocked_samples": [], "block_rate_pct": 0,
            "scope": {"namespace": body.namespace or "default", "agent_class": body.agent_class or None},
            "time_range": "last 24 hours",
            "recommendation": "Invalid rego — fix errors before deploying",
        }

    replay = await _replay_recent(evaluator, session, body, since)
    checked = replay["total_records_checked"]
    newly = replay["newly_blocked"]
    if checked == 0:
        recommendation = "No recent real traffic for this scope — cannot simulate impact; deploy with care."
    elif newly == 0:
        recommendation = "No currently-allowed traffic would be newly blocked — safe to deploy."
    else:
        pct = round(newly / checked * 100, 1)
        recommendation = f"Would NEWLY block {newly} of {checked} recent calls ({pct}%) — review the flips before deploying."
    log.info("nrvq.api.policy.dry_run", valid=valid, checked=checked, would_block=replay["would_block"],
             newly_blocked=newly, ns=body.namespace, cls=body.agent_class, code="NRVQ-API-7014")
    return {
        "valid": True,
        "errors": errors,
        "sample_decision": sample_decision,
        "scope": {"namespace": body.namespace or "default", "agent_class": body.agent_class or None},
        "time_range": "last 24 hours",
        "recommendation": recommendation,
        **replay,
    }


@router.post("/policies/{namespace}/{agent_class}/apply")
async def apply_policy(
    namespace: str,
    agent_class: str,
    body: ApplyRequest,
    request: Request,
    user: dict = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    _target: None = Depends(require_target_cluster),
) -> dict:
    """Apply a saved policy to a target scope."""
    require_admin(user)
    # F-42/H5: the create path guards reserved scopes (NRVQ-API-7016) but apply covered only 3 — __pack_weaken__
    # and __guardrail__ slipped through, and apply never checked the TARGET namespace. Reject every managed
    # class AND a reserved target namespace (apply could otherwise write into the managed __cluster__ scope
    # that create explicitly refuses).
    if agent_class in _RESERVED_DELETE_CLASSES or body.target_namespace in _RESERVED_NAMESPACES:
        log.warning("nrvq.api.policy.reserved_scope", namespace=namespace, agent_class=agent_class,
                    target_namespace=body.target_namespace, actor=user.get("sub"), code="NRVQ-API-7016")
        raise HTTPException(
            status_code=422,
            detail=f"'{agent_class}' / '{body.target_namespace}' is a managed scope and cannot be applied via this "
                   "endpoint — change a baseline via its seed and sector packs via POST /api/v1/policy-packs/{id}/enable.",
        )
    # F-51: high-assurance namespaces can be set dry-run-only — the API rejects applies (server-enforced, admin too).
    await assert_apply_allowed(session, body.target_namespace)
    loader = request.app.state.loader
    rego = loader.get_current(namespace, agent_class)
    if not rego:
        raise HTTPException(status_code=404, detail="Policy not found. Save it first.")
    # Part C FIX: actually load the policy into the read path + persist it at the target so it ENFORCES (the old
    # path wrote the evaluator's unread dict and never persisted the target — a 200 that didn't enforce). This
    # routes apply through the same read-path/cache-invalidation create() uses; idempotent for the same-namespace
    # UI flow (re-affirm, no version bump), and it now genuinely enforces cross-target too.
    result = await loader.apply_to_target(
        namespace,
        agent_class,
        body.target_namespace,
        agent_class,
        saved_by=str(user.get("sub") or ""),
        enforcement_mode=body.enforcement_mode or "block",
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Policy not found. Save it first.")
    applied_version, _created = result
    # C1/HA: apply_to_target() now re-stamps applied_at itself on every code path (persisted via DB NOW() for
    # a new/mode-changed apply, in-memory fast-path for a true no-op reaffirm) — calling mark_applied() again
    # here would overwrite that with a fresh datetime.now() and silently discard the cross-replica-converged
    # DB value apply_to_target just hydrated, reintroducing the per-replica drift this fix closes.
    # FIX A: echoing body.enforcement_mode here is a 200 that can lie — apply_to_target's same-rego branch only
    # persists the caller's mode when it actually differs from what's stored (see NRVQ-REG-5019). Re-read the
    # TARGET entry so the response always reflects what's actually in the DB/read-path, not what was requested.
    persisted_entry = loader.get_entry(body.target_namespace, agent_class)
    persisted_mode = str((persisted_entry or {}).get("enforcement_mode") or body.enforcement_mode or "block")
    log.info(
        "nrvq.api.policy.applied",
        namespace=namespace,
        agent_class=agent_class,
        target_type=body.target_type,
        target_namespace=body.target_namespace,
        mode=persisted_mode,
        actor=user.get("sub"),
        actor_role=user.get("role"),
        code="NRVQ-API-7015",
    )
    return {
        "applied": True,
        "policy": f"{namespace}/{agent_class}",
        "target_type": body.target_type,
        "target_namespace": body.target_namespace,
        "target_name": body.target_name,
        "enforcement_mode": persisted_mode,
        "version": applied_version,  # C1: the version now enforcing on the target (the success panel shows it)
    }
