# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""HIGH-1: HTTP-level rate limiting (pure ASGI middleware).

``settings.evaluator_rate_limit_per_window`` (norviq/engine/evaluator.py) is an OPA POLICY decision made
INSIDE an already-authenticated ``/evaluate`` call — it says nothing about the HTTP layer in front of it.
Before this module, nothing bounded the request RATE the API would accept: ``/auth/login``, ``/evaluate``,
``/policies/dry-run``, and ``/redteam/*`` could all be flooded without limit (DoS on the API pods / the DB
pool / the OPA sidecar).

Design:
  * Redis-backed fixed-window counter (INCR + conditional EXPIRE) via the existing, already-public
    ``RedisCache.incr_call_count`` — one Redis round trip per request, shared correctly across every HA
    API replica (an in-process counter would let an attacker spread load across replicas to bypass it).
  * Keyed per-identity when the request carries a bearer JWT: the ``sub`` claim is read with an
    UNVERIFIED decode (no signature check, no JWKS round trip) purely to pick a bucket — this middleware
    is a DoS throttle, not an authorization boundary; every route it protects still runs its own full
    ``get_current_user`` signature verification before doing anything. Keeping it unverified is what
    keeps this middleware cheap enough to sit in front of the hot ``/evaluate`` path. Requests with no
    bearer token (or a malformed one) fall back to a per-client-IP bucket.
  * Route-class ceilings (config.py, all NRVQ_HTTP_RATE_LIMIT_* overridable): /evaluate gets a HIGH
    ceiling (it is the hot enforcement path and must never be the bottleneck); /auth/login (pre-auth,
    always IP-keyed), /policies/dry-run, and /redteam/* get much stricter ceilings; everything else gets
    a moderate default.
  * FAIL-OPEN on any Redis error (availability > strictness — a Redis blip must never take the API down).
  * /healthz, /readyz, /metrics are always excluded — k8s probes and the Prometheus scrape must never 429.

REPORT-AUDEXPORT-01 precedent (see body_limit.py): this MUST be pure ASGI, not ``BaseHTTPMiddleware`` —
the latter breaks ``StreamingResponse`` (the audit-export bug). A 429 short-circuit is easy to do safely
in pure ASGI (send our own response, never touch ``receive``/the body); the pass-through path leaves
``receive``/``send`` completely untouched.
"""

from __future__ import annotations

import json
import time

import jwt
import structlog

from norviq.config import settings

log = structlog.get_logger()

# (path_prefix, route_class) — checked in order, first match wins. Prefixes are matched against the
# ASGI scope path, which already excludes any mount-level prefix (FastAPI routers are mounted under
# "/api/v1" in main.py, so these are the FULL request paths).
_ROUTE_RULES: tuple[tuple[str, str], ...] = (
    ("/api/v1/evaluate", "evaluate"),
    ("/api/v1/auth/login", "auth_login"),
    ("/api/v1/policies/dry-run", "dry_run"),
    ("/api/v1/redteam", "redteam"),
)


def _route_class(path: str) -> str:
    """Classify a request path into a rate-limit route class (falls back to "default")."""
    for prefix, cls in _ROUTE_RULES:
        if path == prefix or path.startswith(prefix + "/") or path.startswith(prefix + "?"):
            return cls
    return "default"


def _limit_for(route_class: str) -> int:
    """The configured per-window ceiling for a route class."""
    return {
        "evaluate": settings.http_rate_limit_evaluate_per_window,
        "auth_login": settings.http_rate_limit_auth_login_per_window,
        "dry_run": settings.http_rate_limit_dry_run_per_window,
        "redteam": settings.http_rate_limit_redteam_per_window,
    }.get(route_class, settings.http_rate_limit_default_per_window)


def _client_ip(scope) -> str:
    """Best-effort caller IP: honor X-Forwarded-For (ingress/proxy) first, else the raw ASGI client."""
    for name, value in scope.get("headers") or ():
        if name == b"x-forwarded-for":
            # Left-most entry is the original client (standard XFF convention).
            return value.decode(errors="replace").split(",")[0].strip()
    client = scope.get("client")
    return client[0] if client else "unknown"


def _unverified_sub(scope) -> str | None:
    """Best-effort JWT `sub` claim for bucket keying. Deliberately UNVERIFIED — see module docstring."""
    for name, value in scope.get("headers") or ():
        if name != b"authorization":
            continue
        raw = value.decode(errors="replace")
        if not raw.lower().startswith("bearer "):
            return None
        token = raw[7:].strip()
        try:
            # Deliberately unverified (see module docstring): no signature/JWKS check, just a base64
            # claims peek to pick a rate-limit bucket. `verify_signature: False` is PyJWT's equivalent
            # of jose's `get_unverified_claims` (both skip signature AND every other claim check).
            claims = jwt.decode(token, options={"verify_signature": False})
        except Exception:  # noqa: BLE001 - malformed/garbage token -> fall back to IP keying
            return None
        sub = claims.get("sub")
        return str(sub) if sub else None
    return None


def _too_many_requests_body(route_class: str) -> bytes:
    return json.dumps({"detail": f"Rate limit exceeded for {route_class}"}).encode()


class RateLimitMiddleware:
    """Redis-backed, per-identity/IP HTTP rate limiter. Fail-open on Redis errors. Pure ASGI."""

    def __init__(self, app) -> None:
        self.app = app
        self._last_fail_open_log = 0.0

    async def __call__(self, scope, receive, send) -> None:
        if scope.get("type") != "http" or not settings.http_rate_limit_enabled:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if any(path == p or path.startswith(p) for p in settings.http_rate_limit_exclude_paths):
            await self.app(scope, receive, send)
            return

        cache = getattr(getattr(scope.get("app"), "state", None), "cache", None)
        if cache is None:
            # Cache not wired yet (e.g. very early in startup) — fail open.
            await self.app(scope, receive, send)
            return

        route_class = _route_class(path)
        if route_class == "auth_login":
            # Pre-auth route: always IP-keyed regardless of any (unauthenticated) bearer present.
            identity = f"ip:{_client_ip(scope)}"
        else:
            sub = _unverified_sub(scope)
            identity = f"id:{sub}" if sub else f"ip:{_client_ip(scope)}"

        limit = _limit_for(route_class)
        window_s = settings.http_rate_limit_window_s
        bucket_key = f"http:{route_class}:{identity}"

        try:
            count = await cache.incr_call_count(bucket_key, window_s=window_s)
        except Exception as exc:  # noqa: BLE001 - Redis down/unreachable: availability > strictness
            now = time.monotonic()
            if now - self._last_fail_open_log > 30:
                log.warning(
                    "nrvq.api.rate_limit.fail_open", error=str(exc), route_class=route_class,
                    code="NRVQ-API-7080",
                )
                self._last_fail_open_log = now
            await self.app(scope, receive, send)
            return

        if count > limit:
            log.warning(
                "nrvq.api.rate_limit.exceeded", route_class=route_class, identity=identity,
                count=count, limit=limit, code="NRVQ-API-7081",
            )
            body = _too_many_requests_body(route_class)
            await send({
                "type": "http.response.start",
                "status": 429,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"retry-after", str(window_s).encode()),
                ],
            })
            await send({"type": "http.response.body", "body": body})
            return

        await self.app(scope, receive, send)
