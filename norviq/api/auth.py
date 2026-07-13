# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""JWT auth helpers for API endpoints.

Dual-mode (IDENTITY epic A1): validates OIDC RS256/ES256 access tokens against the IdP's JWKS
(``oidc_enabled``) ALONGSIDE legacy shared-secret HS256 (``legacy_hs256_enabled``). The two paths
are mutually exclusive and each pins a single-algorithm allowlist, so an attacker cannot downgrade
an RS256 token to HS256-with-the-public-key (alg-confusion). Group->role/namespace mapping (A2) is
applied to validated OIDC claims so all consumers (HTTP deps + the WebSocket path) see the same
normalized ``role``/``namespace``/``sub`` shape.
"""

import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from norviq.api.jwks import get_jwks_client
from norviq.api.session_revocation import is_revoked, token_hash
from norviq.config import settings

log = structlog.get_logger()
security = HTTPBearer(auto_error=False)

# Role strength for deterministic group-mapping precedence (admin wins). Flip here for least-privilege.
_ROLE_RANK = {"admin": 3, "service": 2, "viewer": 1}


async def _validate_token(token: str) -> dict:
    """Validate a token (OIDC or legacy HS256) and return normalized claims. Raises JWTError."""
    header = jwt.get_unverified_header(token)
    alg = header.get("alg", "")
    if settings.oidc_enabled and alg in {"RS256", "ES256"}:
        return await _validate_oidc(token, header)
    if settings.legacy_hs256_enabled and alg == "HS256":
        claims = dict(jwt.decode(token, settings.api_secret_key, algorithms=["HS256"]))
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
        claims = dict(
            jwt.decode(
                token,
                key,
                algorithms=["RS256", "ES256"],
                issuer=settings.oidc_issuer,
                audience=settings.oidc_audience,
                options={"require_exp": True, "verify_aud": True, "verify_iss": True},
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

    `cluster` is the multi-cluster fleet dimension (F045): "*" = all clusters (admins), a cluster id,
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
    """Validate the bearer token (OIDC or HS256) and return claims.

    Additive (F046): a credential that is not a valid JWT but is a Norviq API key (``nrvq_`` prefix)
    is resolved against the issued-key store as a scoped principal. JWT validation is tried first, so
    nothing about existing token auth changes. (`request` is FastAPI-injected when used as a dependency;
    direct callers may omit it — it only supplies the Redis cache for F-03 api-key auth throttling.)
    """
    if not creds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing token")
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
    # AUTH-01: a signature-valid JWT that was logged out is dead — reject it server-side. Applies
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
    # H1: a token minted with must_change=True (the seeded default admin, or any account after an
    # `admin_reset` — i.e. still on a KNOWN/default password) was previously honored by every endpoint.
    # Fail-closed here: block everything except the small set of routes needed to actually clear the
    # flag (change-password) or exit the session (logout — also reachable directly, this is defense in
    # depth) or read one's own identity (me, used by the console's session-restore path). `request` is
    # only absent for direct/non-HTTP callers (tests, internal use) — nothing to gate there.
    if claims.get("must_change") and request is not None:
        path = request.url.path
        allowed = path.endswith(("/auth/change-password", "/auth/logout", "/me"))
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
    """R2 (P1) SERVER backstop for the F-69 cluster mutation guard. A cluster-scoped WRITE must only affect the
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
    # F-06: a non-admin HUMAN with NO namespace claim (the viewer/unmapped least-privilege floor) previously
    # fell through to `claim_ns or requested` and reached ANY requested namespace — a cross-tenant read hole on
    # every scoped route. A floor user has no namespace scope, so it gets no tenant data. Machine principals
    # (role=service: the webhook controller, fleet relay) stay trusted with an empty claim.
    if role != "service" and not claim_ns:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No namespace scope")
    if requested and claim_ns and requested != claim_ns:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized for this namespace")
    return claim_ns or requested


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
    """Restrict a non-admin caller to its own cluster claim (multi-cluster fleet, F045).

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

    AUTH-01: also rejects logged-out tokens (`cache` is keyword-with-default — existing positional
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
