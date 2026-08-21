# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""HTTP-level rate limiting (pure ASGI middleware).

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

Following the body_limit.py precedent: this MUST be pure ASGI, not ``BaseHTTPMiddleware`` —
the latter breaks ``StreamingResponse`` (the audit-export bug). A 429 short-circuit is easy to do safely
in pure ASGI (send our own response, never touch ``receive``/the body); the pass-through path leaves
``receive``/``send`` completely untouched.
"""

from __future__ import annotations

from time import perf_counter

import ipaddress
import json
import time
from functools import lru_cache

import jwt
import structlog

from norviq.telemetry.metrics import record_path_phase
from norviq.config import settings

log = structlog.get_logger()

# (path_prefix, route_class) — checked in order, first match wins. Prefixes are matched against the
# ASGI scope path, which already excludes any mount-level prefix (FastAPI routers are mounted under
# "/api/v1" in main.py, so these are the FULL request paths).
_ROUTE_RULES: tuple[tuple[str, str], ...] = (
    ("/api/v1/evaluate", "evaluate"),
    ("/api/v1/auth/login", "auth_login"),
    ("/api/v1/policies/dry-run", "dry_run"),
    # ONLY the expensive WRITES. `redteam` is sized at 15/60s because starting a suite fans out to
    # every agent class x every attack in the catalog — a genuine DoS surface that deserves a tight
    # ceiling. Classifying the whole `/api/v1/redteam` prefix put the READS in that same bucket, and
    # the console's landing page calls `/redteam/results/latest` on every boot (Dashboard.tsx, and
    # Compliance.tsx does it too). Measured over one e2e run: 116 hits on results/latest against 20
    # actual Red Team page mounts — 83% of them from Overview.
    #
    # So roughly fifteen visits to the OVERVIEW page in a minute started 429-ing a real operator's
    # console, on a guard that exists to stop them hammering the suite runner. Reads now fall through
    # to `default` (300/60s); the ceiling on the thing actually worth protecting is unchanged.
    ("/api/v1/redteam/suite", "redteam"),
    ("/api/v1/redteam/run", "redteam"),
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


def _peer_ip(scope) -> str:
    """The real TCP peer address — the only value a caller cannot forge."""
    client = scope.get("client")
    return client[0] if client else "unknown"


@lru_cache(maxsize=8)
def _trusted_networks(cidrs: tuple[str, ...]) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Parse the trusted-proxy CIDRs ONCE per distinct config value.

    Off the hot path (every request would otherwise re-parse), and it gives a malformed entry one LOUD
    log instead of a silent per-request skip: a CIDR that doesn't parse is dropped, which can only ever
    NARROW trust (the peer then fails the check and we fall back to its unforgeable address).
    """
    nets = []
    for raw in cidrs:
        try:
            nets.append(ipaddress.ip_network(raw.strip(), strict=False))
        except ValueError:
            log.error(
                "nrvq.api.rate_limit.bad_trusted_cidr",
                cidr=raw,
                detail="ignored — XFF from peers in this range will NOT be trusted",
                code="NRVQ-API-7131",
            )
    return tuple(nets)


def _peer_is_trusted(peer: str) -> bool:
    """Is the TCP peer one of the reverse proxies we're willing to believe an XFF header from?"""
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        # Not an IP at all (e.g. a unix-socket peer, or TestClient's "testclient") — never trusted.
        return False
    return any(addr in net for net in _trusted_networks(tuple(settings.http_rate_limit_trusted_proxy_cidrs)))


def _normalize_ip(raw: str) -> str:
    """Return a canonical bare IP for use as a bucket key, or "" when it isn't one.

    Guards three ways an XFF entry splits one caller across many buckets (each a free throttle reset):
    a ``host:port`` suffix with a rotating source port, the bracketed ``[v6]:port`` form, and
    non-canonical IPv6 spellings of the same address. A non-IP string is rejected outright so it can
    never become a bucket key (or a log field).
    """
    value = raw.strip()
    if value.startswith("["):  # [2001:db8::1] or [2001:db8::1]:41022
        value = value[1:].split("]", 1)[0]
    elif value.count(":") == 1:  # host:port — never split a bare IPv6, which has multiple colons
        value = value.split(":", 1)[0]
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return ""


def _client_ip(scope) -> str:
    """Caller IP for rate-limit bucketing, derived only from data we actually trust.

    ``X-Forwarded-For`` is client-WRITABLE, so its left-most entry is whatever the caller typed. Keying a
    throttle on that means an attacker rotates the header and every request lands in a fresh bucket — the
    ceiling is never reached (throttle bypass, worst on the pre-auth ``/auth/login`` route, which is
    always IP-keyed). But ignoring XFF outright is not the answer either: behind a proxy every caller
    would then share the proxy's single bucket, so one abuser throttles everyone (self-DoS).

    So the header is believed only when BOTH hold:

    * the TCP **peer** is a trusted proxy (``http_rate_limit_trusted_proxy_cidrs``, default loopback —
      exactly the in-pod nginx the chart runs in front of the API). This is the load-bearing check: a pod
      hitting the API's plaintext port directly is not loopback, so its XFF is ignored and it cannot
      reach the forgeable path at all; and
    * the chain is at least ``http_rate_limit_trusted_proxy_hops`` long, in which case the Nth entry
      FROM THE RIGHT is used — the address our outermost trusted proxy observed, which the caller cannot
      control by prepending entries.

    Anything else falls back to the unforgeable TCP peer.
    """
    peer = _peer_ip(scope)
    hops = int(settings.http_rate_limit_trusted_proxy_hops or 0)
    if hops <= 0 or not _peer_is_trusted(peer):
        return peer
    # RFC 7239 treats repeated headers as equivalent to one comma-joined chain; join ALL of them so a
    # proxy that ADDS its own header line can't leave the attacker's line first (returning on the first
    # header would hand the attacker the value).
    chain = b",".join(v for n, v in (scope.get("headers") or ()) if n == b"x-forwarded-for")
    if not chain:
        return peer
    parts = [p.strip() for p in chain.decode(errors="replace").split(",") if p.strip()]
    if len(parts) < hops:
        return peer  # didn't traverse the expected chain — don't trust a short/forged one
    return _normalize_ip(parts[-hops]) or peer


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
            # NOT an authorization decision: the only claim used is `sub`, to pick a rate-limit
            # bucket, and every route this middleware fronts still runs the full signature check in
            # `get_current_user` before doing anything. The worst a forged `sub` buys is a DIFFERENT
            # throttle bucket, never access. The directive must be the line immediately above the
            # finding — semgrep does not scan back through a comment block for it.
            # nosemgrep: python.jwt.security.unverified-jwt-decode.unverified-jwt-decode
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

        # Timed because this middleware runs a Redis INCR on EVERY request, including the enforcement hot
        # path, and the API's HTTP layer measured ~35% of what a caller waits with none of it attributed.
        # Only the limiter's own decision is timed — `self.app(...)` downstream is deliberately outside it,
        # or this would just re-measure the whole request.
        _rl_t0 = perf_counter()
        try:
            count = await cache.incr_call_count(bucket_key, window_s=window_s)
            record_path_phase("api", "ratelimit", (perf_counter() - _rl_t0) * 1000.0)
        except Exception as exc:  # noqa: BLE001 - Redis down/unreachable: availability > strictness
            # Recorded on the fail-open arm too: a Redis timeout here is SLOW, so excluding it would hide
            # the worst case behind the label that looks healthy.
            record_path_phase("api", "ratelimit", (perf_counter() - _rl_t0) * 1000.0)
            now = time.monotonic()
            if now - self._last_fail_open_log > 30:
                log.warning(
                    "nrvq.api.rate_limit.fail_open", error=str(exc), route_class=route_class,
                    code="NRVQ-API-7133",
                )
                self._last_fail_open_log = now
            await self.app(scope, receive, send)
            return

        if count > limit:
            log.warning(
                "nrvq.api.rate_limit.exceeded", route_class=route_class, identity=identity,
                count=count, limit=limit, code="NRVQ-API-7134",
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
