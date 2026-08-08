# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""JWT auth helpers for API endpoints.

Dual-mode: validates OIDC RS256/ES256 access tokens against the IdP's JWKS
(``oidc_enabled``) ALONGSIDE legacy shared-secret HS256 (``legacy_hs256_enabled``). The two paths
are mutually exclusive and each pins a single-algorithm allowlist, so an attacker cannot downgrade
an RS256 token to HS256-with-the-public-key (alg-confusion). Group->role/namespace mapping is
applied to validated OIDC claims so all consumers (HTTP deps + the WebSocket path) see the same
normalized ``role``/``namespace``/``sub`` shape.
"""

from time import perf_counter

import jwt
import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError as JWTError

from norviq.api.jwks import get_jwks_client
from norviq.api.session_revocation import is_revoked, token_hash
from norviq.config import settings
from norviq.telemetry.metrics import record_path_phase

log = structlog.get_logger()
security = HTTPBearer(auto_error=False)

# Bound the bearer credential BEFORE any crypto. The Authorization header is NOT covered by the
# request-body 413 limit, so an attacker could feed jwt.decode a multi-megabyte "token" as a cheap DoS
# probe. 8 KiB is far above any legitimate HS256 session token (~200 B), API key, or OIDC RS256 token
# (with group claims, ~1-4 KiB); anything larger is rejected as invalid up front.
_MAX_BEARER_LEN = 8192

# Role strength for deterministic group-mapping precedence (admin wins). Flip here for least-privilege.
_ROLE_RANK = {"admin": 3, "service": 2, "viewer": 1}

# The ONLY routes a must_change=True token may reach (exact paths, matched by equality — see
# get_current_user). These are the concrete mounted paths (routers are included under `/api/v1`):
# clear the flag (change-password), exit the session (logout), or read one's own identity (me, the
# console's session-restore path). Exact match — never a suffix test — so a crafted path that merely
# *ends* with one of these (e.g. `/api/v1/policies/x/auth/logout`) can't slip the lockdown.
_MUST_CHANGE_ALLOWED_PATHS = frozenset(
    {"/api/v1/auth/change-password", "/api/v1/auth/logout", "/api/v1/me"}
)


async def _validate_token(token: str) -> dict:
    """Validate a token (OIDC or legacy HS256) and return normalized claims. Raises JWTError."""
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "")
    if settings.oidc_enabled and alg in {"RS256", "ES256"}:
        return await _validate_oidc(token, header)
    if settings.legacy_hs256_enabled and alg == "HS256":
        # Require an `exp` claim (matching the OIDC branch above). Without this, PyJWT verifies
        # exp only when present and never *requires* it, so a validly-signed HS256 token minted with no
        # exp is immortal AND defeats logout (revocation TTL falls back to ~1s at auth_login.py). Every
        # legitimate mint sets exp (token_mint.mint_admin_token / mint_session_token), so this rejects
        # only forged/no-exp tokens (JWTError -> 401).
        claims = dict(
            jwt.decode(
                token,
                settings.api_secret_key,
                algorithms=["HS256"],
                options={"require": ["exp"]},
            )
        )
        log.info("nrvq.auth.legacy_hs256", sub=claims.get("sub"), code="NRVQ-AUTH-14005")
        return claims
    raise JWTError(f"unsupported or disabled token alg: {alg!r}")


async def _validate_oidc(token: str, header: dict) -> dict:
    """Validate an RS256/ES256 OIDC token against the JWKS and apply group mapping."""
    kid = header.get("kid")
    if not kid:
        raise JWTError("OIDC token missing kid")
    key = await get_jwks_client().get_key(kid)
    try:
        # PyJWT's `decode` wants an actual key object, not a raw JWK dict (jose accepted the dict
        # directly) — wrap it. `PyJWK` infers the algorithm from the JWK's `kty`/`crv` (RSA -> RS256,
        # EC P-256 -> ES256) when the JWK has no explicit `alg`, matching this deployment's supported set,
        # and PyJWT then requires the token's header `alg` to equal that inferred algorithm — a strictly
        # tighter alg-confusion guard than jose's plain allowlist check.
        signing_key = jwt.PyJWK(key)
    except JWTError as exc:
        log.warning("nrvq.auth.oidc_rejected", error=str(exc), code="NRVQ-AUTH-14001")
        raise JWTError(f"invalid JWKS key: {exc}") from exc
    try:
        claims = dict(
            jwt.decode(
                token,
                signing_key,
                algorithms=["RS256", "ES256"],
                issuer=settings.oidc_issuer,
                audience=settings.oidc_audience,
                options={"require": ["exp"], "verify_aud": True, "verify_iss": True},
            )
        )
    except JWTError as exc:
        log.warning("nrvq.auth.oidc_rejected", error=str(exc), code="NRVQ-AUTH-14001")
        raise
    claims = _apply_group_mapping(claims)
    log.info("nrvq.auth.oidc_validated", sub=claims.get("sub"), role=claims.get("role"), code="NRVQ-AUTH-14000")
    return claims


def _apply_group_mapping(claims: dict) -> dict:
    """Map IdP groups -> Norviq (role, namespace, cluster). Admin wins; conflicting non-admin fails closed.

    `cluster` is the multi-cluster fleet dimension: "*" = all clusters (admins), a cluster id,
    or "" (single-cluster — the default, which existing single-cluster endpoints simply ignore).
    """
    groups = claims.get(settings.oidc_group_claim, []) or []
    if isinstance(groups, str):
        groups = [groups]
    matched = [settings.oidc_group_mappings[g] for g in groups if g in settings.oidc_group_mappings]
    if not matched:
        # Least-privilege floor: authenticated but unmapped -> viewer, no namespace, no cluster.
        claims["role"], claims["namespace"], claims["cluster"] = "viewer", "", ""
        return claims
    role = max((m.get("role", "viewer") for m in matched), key=lambda r: _ROLE_RANK.get(r, 0))
    if role == "admin":
        claims["role"], claims["namespace"], claims["cluster"] = "admin", "", "*"
        return claims
    namespaces = {m["namespace"] for m in matched if m.get("namespace")}
    if len(namespaces) > 1:
        log.warning("nrvq.auth.oidc_rejected", reason="conflicting_namespaces",
                    namespaces=sorted(namespaces), code="NRVQ-AUTH-14001")
        raise JWTError("conflicting namespace mappings")
    clusters = {m["cluster"] for m in matched if m.get("cluster")}
    if len(clusters) > 1:
        log.warning("nrvq.auth.oidc_rejected", reason="conflicting_clusters",
                    clusters=sorted(clusters), code="NRVQ-AUTH-14001")
        raise JWTError("conflicting cluster mappings")
    claims["role"] = role
    claims["namespace"] = next(iter(namespaces), "")
    claims["cluster"] = next(iter(clusters), "")
    return claims


async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security), request: Request = None  # type: ignore[assignment]
) -> dict:
    """Time the auth dependency, then delegate to `_authenticate`.

    A wrapper rather than a timer inside the body: that body has several return paths (JWT, OIDC, API key)
    and raises 401/403 on others, so timing it inline would mean keeping half a dozen call sites in sync and
    a new branch would silently stop being measured. `finally` covers every path, including the raises —
    which matters, because a slow REJECTION is exactly as bad for a caller as a slow acceptance.

    Why this is measured at all: the API's HTTP layer is ~35% of what a caller waits for one enforcement
    decision, and auth runs on every request (JWT verify, plus a Redis session-revocation check). None of it
    was attributed. The signature is unchanged so `Depends(get_current_user)` resolves exactly as before.
    """
    _t0 = perf_counter()
    try:
        return await _authenticate(creds, request)
    finally:
        record_path_phase("api", "auth", (perf_counter() - _t0) * 1000.0)


async def _authenticate(
    creds: HTTPAuthorizationCredentials | None, request: Request | None
) -> dict:
    """Validate the bearer token (OIDC or HS256) and return claims.

    Additive: a credential that is not a valid JWT but is a Norviq API key (``nrvq_`` prefix)
    is resolved against the issued-key store as a scoped principal. JWT validation is tried first, so
    nothing about existing token auth changes. (`request` is FastAPI-injected when used as a dependency;
    direct callers may omit it — it only supplies the Redis cache for api-key auth throttling.)
    """
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
    if len(creds.credentials) > _MAX_BEARER_LEN:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    try:
        claims = await _validate_token(creds.credentials)
    except JWTError as exc:
        if creds.credentials.startswith("nrvq_"):
            from norviq.api.api_keys import authenticate_api_key

            cache = getattr(getattr(request, "app", None), "state", None)
            cache = getattr(cache, "cache", None) if cache is not None else None
            principal = await authenticate_api_key(creds.credentials, cache=cache)
            if principal is not None:
                return principal
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc
    # A signature-valid JWT that was logged out is dead — reject it server-side. Applies
    # uniformly to any JWT-validated credential (HS256 session + OIDC); API keys have their own
    # lifecycle (DELETE /keys). Cache is None-safe (direct callers / tests) — the in-process mirror
    # still applies via is_revoked.
    cache = getattr(getattr(request, "app", None), "state", None)
    cache = getattr(cache, "cache", None) if cache is not None else None
    if await is_revoked(cache, creds.credentials):
        log.info(
            "nrvq.auth.revoked_token_rejected",
            sub=claims.get("sub"),
            token_hash_prefix=token_hash(creds.credentials)[:12],
            code="NRVQ-AUTH-14016",
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session has been logged out")
    # A token minted with must_change=True (the seeded default admin, or any account after an
    # `admin_reset` — i.e. still on a KNOWN/default password) is fail-closed here: block everything
    # except the small set of routes needed to actually clear the flag (change-password) or exit the
    # session (logout — also reachable directly, this is defense in depth) or read one's own identity
    # (me, used by the console's session-restore path). `request` is only absent for direct/non-HTTP
    # callers (tests, internal use) — nothing to gate there.
    if claims.get("must_change") and request is not None:
        path = request.url.path
        allowed = path in _MUST_CHANGE_ALLOWED_PATHS
        if not allowed:
            log.info(
                "nrvq.auth.must_change_blocked",
                sub=claims.get("sub"),
                path=path,
                code="NRVQ-AUTH-14018",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Password change required",
            )
    return claims


def require_admin(user: dict) -> None:
    """Require admin role in token claims."""
    role = str(user.get("role", "")).lower()
    if role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")


def require_admin_or_service(user: dict) -> None:
    """Allow a human admin OR a machine 'service' identity (e.g. the webhook CRD controller).

    The webhook controller mints a short-lived service-role JWT to sync NrvqPolicy CRDs to the API;
    least-privilege — only the controller's create/delete policy endpoints accept the service role,
    everything else (rollback/apply/manual writes) stays admin-only via require_admin.
    """
    role = str(user.get("role", "")).lower()
    if role not in {"admin", "service"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin or service role required")


async def require_target_cluster(request: Request) -> None:
    """SERVER backstop for the cluster mutation guard. A cluster-scoped WRITE must only affect the
    cluster this API actually serves. The console sends the operator's intended target on the
    ``X-Nrvq-Target-Cluster`` header; if it is present and does not match this deployment's served cluster id, the
    write is refused (409) — a mutation aimed at another cluster must never silently land on this one, regardless of
    what label the UI shows. An absent/empty header means local intent (the default), so the SDK/sidecar hot path and
    every existing client are unaffected. This is the server half of the guard; the UI (NRVQ-UI-4601) is the first
    line."""
    target = (request.headers.get("X-Nrvq-Target-Cluster") or "").strip()
    served = settings.fleet_cluster_id or "local"
    if target and target != served:
        log.warning("nrvq.api.target_cluster_mismatch", target=target[:64], served=served, code="NRVQ-API-7460")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"target cluster '{target}' does not match this deployment's served cluster '{served}' — "
                   "this API only mutates its own cluster; open the target cluster's own console to change it",
        )


def scoped_namespace(user: dict, requested: str | None) -> str | None:
    """Restrict a non-admin caller to its own namespace claim.

    Admins may read any namespace (or all, when requested is None). Non-admin tokens may only read
    the namespace in their claim — a request for a different namespace is 403. This stops a token
    scoped to one tenant from reading another tenant's audit/agent/policy data via the query param.
    """
    role = str(user.get("role", "")).lower()
    if role == "admin":
        return requested
    claim_ns = str(user.get("namespace", "") or "")
    # A non-admin HUMAN with NO namespace claim (the viewer/unmapped least-privilege floor) has no
    # namespace scope, so it gets no tenant data — without this guard it would fall through to
    # `claim_ns or requested` and reach ANY requested namespace (a cross-tenant read hole). Machine
    # principals (role=service: the webhook controller, fleet relay) stay trusted with an empty claim.
    if role != "service" and not claim_ns:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No namespace scope")
    if requested and claim_ns and requested != claim_ns:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this namespace")
    return claim_ns or requested


def attested_namespace(user: dict, requested: str | None = None) -> str:
    """Namespace derived from the caller's OWN credential-claimed SPIFFE ID. ``""`` when not derivable.

    Closes the residual that ``scoped_namespace`` deliberately leaves open. There, a MACHINE principal
    (``role=service``) with an EMPTY namespace claim is trusted to evaluate any namespace the request
    BODY names — the hot path needs that latitude, and the alternative at the time was breaking every
    sidecar. The consequence is that an unbound service token could evaluate as any tenant.

    The durable closure is to take the namespace from something the caller cannot choose. It already
    exists: ``spiffe_id`` is one of ``_BOUND_IDENTITY_FIELDS``, so for a machine principal it is resolved
    from the credential and (under ``auth_require_bound_agent_identity``) REQUIRED — and a Norviq SVID
    encodes the namespace as ``spiffe://norviq/ns/<ns>/sa/<sa>``. So the workload's attested identity
    names its own namespace, and no new attestation channel is needed.

    Read strictly from ``user`` (the validated claims), NEVER from ``agent_identity``: after
    ``scoped_identity`` the identity's ``spiffe_id`` falls back to the body's value when the credential
    doesn't claim one, and deriving the namespace from a body-supplied SVID would just reintroduce the
    same hole one level down.

    Uses the engine's STRICT parser, which pins the trust domain and the exact 4-segment shape. The
    looser scan in ``routers/agents.py`` (find "ns" anywhere in the path) is fine for display scoping but
    would accept ``spiffe://evil/ns/victim/sa/x`` — not something to base an authorization decision on.

    Raises 403 when the SVID's namespace contradicts an explicit request, or a namespace claim on the
    same token. Both are spoof-or-misissue, so they are loud rather than silently corrected.
    """
    if str(user.get("role", "")).lower() != "service":
        # Humans are already tenant-pinned by scoped_namespace and carry no workload SVID; admin keeps
        # its cross-namespace latitude (console what-if / red-team simulate).
        return ""
    claimed_svid = str(user.get("spiffe_id", "") or "")
    if not claimed_svid:
        return ""
    # Local import: keeps the auth module free of an engine-layer dependency at import time (parts of
    # norviq.engine import norviq.api.db), matching the deferred-import pattern used elsewhere.
    from norviq.engine.identity import _parse_norviq_spiffe_id

    parsed = _parse_norviq_spiffe_id(claimed_svid)
    if not parsed:
        return ""  # a foreign or malformed SVID attests nothing; leave scoped_namespace in charge
    attested = parsed[0]
    claim_ns = str(user.get("namespace", "") or "")
    if claim_ns and claim_ns != attested:
        # The credential disagrees with itself. Picking either value silently would be a guess about
        # which half to trust, so refuse and make the misissued token visible.
        log.warning(
            "nrvq.auth.attested_namespace_conflicts_with_claim",
            sub=user.get("sub"), claim=claim_ns, attested=attested, code="NRVQ-AUTH-14022",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Credential namespace claim conflicts with its attested identity",
        )
    asked = str(requested or "")
    if asked and asked != attested:
        log.warning(
            "nrvq.auth.attested_namespace_denied",
            sub=user.get("sub"), attested=attested, requested=asked, code="NRVQ-AUTH-14023",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized for this namespace",
        )
    return attested


# The identity fields that SELECT ENFORCEMENT and must therefore come from the credential, never from
# the request body. `agent_class` picks the Rego program (evaluator._collect_candidates:
# f"{namespace}:{agent_class}"), `spiffe_id` keys the trust score + the agent_frozen: kill-switch +
# the per-agent rate limit, and `workload` pulls in the f"{namespace}:deployment:{workload}" tier.
_BOUND_IDENTITY_FIELDS = ("agent_class", "spiffe_id", "workload")
# What the strict ratchet demands of a MACHINE principal. Per-field on purpose: a token bound on
# agent_class but not spiffe_id would otherwise satisfy an "is it bound at all?" test while leaving the
# kill-switch evadable. `workload` stays OPTIONAL rather than required: the injector mints it now
# (mintSidecarToken, webhook/injector.go) but only when the pod has a resolvable owner, so a bare pod
# or a CRD-managed workload legitimately has no claim — requiring one would fail those closed for a
# tier that simply does not apply to them.
_REQUIRED_BOUND_FIELDS = ("agent_class", "spiffe_id")

# ...but `spiffe_id` is only MINTABLE in mock mode, so demanding it unconditionally made the ratchet
# unsatisfiable — a trap rather than a posture.
#
# The webhook binds that claim only when it can predict the SVID byte-for-byte, i.e. the mock resolver
# (`webhook/injector.go::mintSidecarToken`; `injector_identity_binding_test.go` asserts it is ABSENT under
# workload-api, because a SPIRE-issued id has a trust domain the webhook does not control and a guess
# would 403 every call). So on a workload-api install, `auth_require_bound_agent_identity=true` would
# have rejected EVERY sidecar evaluation on the hot path — the one flag whose whole purpose is to be
# turned on, and it could not be.
#
# Requiring only what the deployment can actually issue keeps the ratchet meaningful where it bites
# (agent_class still selects the Rego program, so an unbound credential is still refused) without
# demanding a claim that cannot exist. Note what this does NOT do: with no spiffe_id claim,
# `attested_namespace` has nothing to derive from, so a workload-api token with no namespace claim keeps
# the pre-existing body-supplied behaviour. Closing THAT needs the peer's real SVID read from the
# internal mTLS client certificate — nginx already verifies it and forwards X-Nrvq-Client-Verify /
# X-Nrvq-Client-Subject — which is a separate change, not this one.
def _required_bound_fields() -> tuple[str, ...]:
    """The bound-identity fields a machine principal must carry, for THIS deployment's SPIFFE mode.

    workload-api mode drops `spiffe_id` from the REQUIRED set, and that is not a preference — the
    injector cannot mint the claim because a SPIRE-issued SVID's trust domain is not ours to predict
    (webhook/injector.go only binds it in "mock" mode, where the id is deterministic). Minting a guess
    would 403 every tool call.

    But the relaxation has a consequence the hardened posture does not advertise: with no spiffe_id
    claim, scoped_identity's binding loop skips the field, so the BODY's spiffe_id passes through — and
    spiffe_id is the key for the trust score, the per-agent rate limit and the agent_frozen: admin
    kill-switch. An operator who deploys SPIRE + auth_require_bound_agent_identity=true believes
    identity is attested end to end; for the SPIFFE id specifically it is not.

    What is done about it, since the claim genuinely cannot be minted:
      * `_reject_cross_namespace_spiffe` below still pins a body-supplied SVID to the caller's OWN
        namespace claim, so the hole is bounded to intra-namespace rather than cross-tenant;
      * `warn_if_identity_binding_is_partial` says so once, loudly, at startup, instead of letting the
        posture read as complete.
    """
    if str(getattr(settings, "spiffe_mode", "mock")).lower() == "workload-api":
        return tuple(f for f in _REQUIRED_BOUND_FIELDS if f != "spiffe_id")
    return _REQUIRED_BOUND_FIELDS


def warn_if_identity_binding_is_partial() -> bool:
    """Say once, at startup, when the strict posture cannot actually bind spiffe_id. Returns True then."""
    mode = str(getattr(settings, "spiffe_mode", "mock")).lower()
    strict = bool(getattr(settings, "auth_require_bound_agent_identity", False))
    if mode == "workload-api" and strict:
        log.warning(
            "nrvq.auth.identity_binding_partial",
            detail="spiffe_mode=workload-api: the sidecar token carries NO spiffe_id claim (a SPIRE "
                   "SVID is not predictable at injection), so a service credential's SPIFFE id comes "
                   "from the request body. It is pinned to the token's own namespace, but WITHIN that "
                   "namespace the trust score, per-agent rate limit and the agent_frozen kill-switch "
                   "are keyed on a value the caller supplies. Treat the admin freeze as advisory here, "
                   "and bind identity at the transport instead (internal mTLS).",
            code="NRVQ-AUTH-14022",
        )
        return True
    return False


def _reject_cross_namespace_spiffe(user: dict, identity: dict) -> None:
    """Pin a body-supplied SPIFFE id to the caller's OWN namespace claim.

    Only reachable when the credential has no spiffe_id claim to bind against (workload-api mode). The
    id still is not attested, but it can no longer name ANOTHER tenant's agent — which is what turned a
    missing claim into cross-tenant freeze evasion. Uses the engine's strict parser, the same one
    attested_namespace uses, so `spiffe://evil/ns/victim/sa/x` does not qualify as a namespace claim.
    """
    if str(user.get("role", "")).lower() != "service":
        return
    claimed_ns = str(user.get("namespace", "") or "")
    body_id = str(identity.get("spiffe_id", "") or "")
    if not claimed_ns or not body_id:
        return
    from norviq.engine.identity import _parse_norviq_spiffe_id

    parsed = _parse_norviq_spiffe_id(body_id)
    if parsed is None:
        return
    svid_ns, _sa = parsed
    if svid_ns != claimed_ns:
        log.warning(
            "nrvq.auth.spiffe_namespace_mismatch",
            sub=user.get("sub"), claim_namespace=claimed_ns, requested=body_id,
            code="NRVQ-AUTH-14023",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SPIFFE id names a different namespace than this credential",
        )
# Fields that only ADD a policy candidate. For these, "unclaimed" resolves to empty (drop the tier)
# rather than to the body's value — clearing an additive tier can only ever be more restrictive.
_ADDITIVE_TIER_FIELDS = ("workload",)


def scoped_identity(user: dict, agent_identity: dict | None) -> dict:
    """Return ``agent_identity`` with every credential-claimed field FORCED to the claim.

    Companion to ``scoped_namespace``: ``namespace`` is not the only authorization-relevant field in an
    ``agent_identity``. Each of ``_BOUND_IDENTITY_FIELDS`` selects what gets enforced, so all of them are
    resolved from the caller's credential rather than trusted from the body.

    **The claim is authoritative, not merely validated.** Checking "body matches claim" is not enough,
    because dropping a field is as powerful as substituting one: an omitted/empty ``agent_class`` skips
    the class program while ``__baseline__`` and ``__cluster__:__baseline__`` REMAIN candidates
    (evaluator._collect_candidates), so the caller silently falls back to the looser baseline, loses its
    tighten-only ``__remediation__`` overlay, and gets a neutral scope-drift trust signal instead of a
    penalised one. An omitted ``workload`` likewise drops a workload-tier policy written for it. So a
    claimed field is written back over whatever the body said (or didn't say).

    An explicit MISMATCH is still a loud 403 (``NRVQ-AUTH-14019``) rather than a silent correction — it is
    an attempted spoof and operators should see it. A merely absent value is corrected silently, since
    legitimate clients routinely omit optional fields.

    * ``admin`` — unrestricted (console what-if / red-team simulation evaluate as other identities, the
      same latitude admin already has across namespaces).
    * claim ABSENT for a field — that field stays unbound (nothing to resolve it against).
    * ``auth_require_bound_agent_identity`` — the ratchet, applied to MACHINE principals (``role=service``)
      only: they must carry every field in ``_REQUIRED_BOUND_FIELDS``. Human sessions have no agent
      identity to bind and are already tenant-pinned by ``scoped_namespace``, so holding them to it would
      only break the console's Policy Tester / Attack Graph simulate for non-admins.
    """
    identity = dict(agent_identity or {})
    role = str(user.get("role", "")).lower()
    if role == "admin":
        return identity
    bound: list[str] = []
    for field in _BOUND_IDENTITY_FIELDS:
        claim = str(user.get(field, "") or "")
        if not claim:
            continue
        bound.append(field)
        asked = str(identity.get(field) or "")
        if asked and asked != claim:
            log.warning(
                "nrvq.auth.identity_binding_denied",
                sub=user.get("sub"),
                field=field,
                claim=claim,
                requested=asked,
                code="NRVQ-AUTH-14019",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Not authorized for this {field}",
            )
        # Claim wins — including when the body omitted the field or sent it empty.
        identity[field] = claim
    # A provisioned (bound) credential may not self-select an ADDITIVE policy tier it was not issued for.
    # `workload` only ever ADDS the f"{namespace}:deployment:{workload}" candidate, so clearing it is
    # always the safe direction (the tier simply doesn't apply) — unlike agent_class, where clearing would
    # DOWNGRADE to the baseline. Without this a bound sidecar could name any deployment and pull in that
    # tier's program.
    #
    # This used to read "no issuer mints a workload claim today", and that was the whole reason the
    # workload tier never applied to real traffic: the sidecar sent a workload and this discarded it on
    # arrival, so a policy targeting a Deployment saved, synced, reported Active and decided nothing.
    # The injector is the issuer now (mintSidecarToken), and the value is not the sidecar's to choose —
    # it is derived at admission from the pod's OWNER reference, so a bound token grants exactly the tier
    # its pod is entitled to. The clearing below still applies to any credential without the claim.
    if bound:
        for field in _ADDITIVE_TIER_FIELDS:
            if field not in bound and identity.get(field):
                log.info(
                    "nrvq.auth.identity_tier_dropped",
                    sub=user.get("sub"),
                    field=field,
                    requested=str(identity.get(field)),
                    code="NRVQ-AUTH-14021",
                )
                identity[field] = ""
    # With no spiffe_id claim to bind against (workload-api mode), at least stop the body naming
    # another tenant's agent — the difference between an unattested id and a cross-tenant one.
    if "spiffe_id" not in bound:
        _reject_cross_namespace_spiffe(user, identity)
    if role == "service":
        missing = [f for f in _required_bound_fields() if f not in bound]
        if missing and settings.auth_require_bound_agent_identity:
            log.warning(
                "nrvq.auth.identity_unbound_denied",
                sub=user.get("sub"),
                missing=",".join(missing),
                code="NRVQ-AUTH-14020",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Credential is not bound to an agent identity",
            )
    return identity


def read_namespace(user: dict, requested: str | None) -> str | None:
    """Namespace filter for cross-namespace READ endpoints (Audit / Agents / MITRE / Coverage / …).

    The console's "All namespaces" scope sends ``namespace=all`` (or omits it). This treats "all" the
    same as an unscoped read: an ADMIN gets ``None`` (no namespace filter — every namespace), while a
    scoped tenant is still pinned to its own namespace and a no-scope viewer still 403s. Tenant isolation
    is preserved by delegating to ``scoped_namespace`` — "all" never lets a viewer read another tenant.
    A ``None`` return means "no WHERE namespace filter"; callers MUST guard the filter with ``if ns:``.
    """
    role = str(user.get("role", "")).lower()
    claim = str(user.get("namespace", "") or "")
    if requested == "all" or requested is None:
        # Unrestricted read only for principals that may see every namespace.
        if role == "admin" or claim == "*" or (role == "service" and not claim):
            return None
        if not claim:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No namespace scope")
        return claim  # a scoped tenant's "all" is its own namespace, never cross-tenant
    return scoped_namespace(user, requested)


def scoped_cluster(user: dict, requested: str | None) -> str | None:
    """Restrict a non-admin caller to its own cluster claim (multi-cluster fleet).

    Admin (or cluster claim "*") may read any cluster (or all, when requested is None). Other tokens may
    only read the cluster in their claim — a request for a different cluster is 403. This stops one
    cluster's service/viewer token from reading or writing another cluster's fleet rollups.
    """
    role = str(user.get("role", "")).lower()
    claim = str(user.get("cluster", "") or "")
    if role == "admin" or claim == "*":
        return requested
    if requested and claim and requested != claim:
        log.warning("nrvq.fleet.cluster_scope_denied", requested=requested, claim=claim, code="NRVQ-FLT-15009")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this cluster")
    return claim or requested


async def decode_token(token: str, cache=None) -> dict:
    """Decode a token outside the HTTP dependency (e.g. websocket query param). Raises JWTError.

    Also rejects logged-out tokens (`cache` is keyword-with-default — existing positional
    callers are unaffected; the in-process revocation mirror is consulted even when cache is None).
    """
    claims = await _validate_token(token)
    if await is_revoked(cache, token):
        log.info(
            "nrvq.auth.revoked_token_rejected",
            sub=claims.get("sub"),
            token_hash_prefix=token_hash(token)[:12],
            code="NRVQ-AUTH-14016",
        )
        raise JWTError("token has been logged out")
    return claims
