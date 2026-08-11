# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Forewarning for the 30-day sidecar credential cliff (C2-020).

Both credentials the webhook injects are 30-day and are baked into an immutable pod spec: the service
JWT (`iat` -> `exp` measured at exactly 720h on a live pod) and the mTLS client cert
(`webhook/injector.go`, `NotAfter: now.Add(30*24*time.Hour)`). Nothing renews either — there is no
rotation loop in the webhook and nothing in the sidecar re-reads a credential — so a pod that keeps
running for thirty days ends up holding two expired ones.

What happens then is CORRECT and must not be "fixed": the API answers 401, `remote_evaluator.py` sees a
4xx, and a 4xx overrides `sdk_fallback_mode` to fail CLOSED, because a refused credential silently
becoming a governance bypass would be far worse. That behaviour is deliberate and tested.

The defect is that it arrives with no warning. Every injected pod stops being able to make a tool call,
on a timer, and the first signal anyone gets is the outage itself — at which point `/system-health`
does diagnose it correctly (`engine_rejected_request`, "typically an expired or wrong sidecar token",
remediation "restart affected pods"). Diagnosing an outage in progress is not the same as preventing it.

So: observe expiry where the API already decodes the token, and surface it as a WARNING days before
the cliff. Nothing here can block a request or fail one — every function is best-effort and swallows
its own errors, because this is a reporting convenience bolted onto the authentication path and an
auth path that fails because a reporting write failed would be a much worse bug than the one it warns
about.

Rotation, when it happens, is pod replacement — proven live: a replacement pod gets a new token with a
later `iat` and an unchanged identity. So the fix an operator takes from this warning is to roll the
affected Deployments, which is the same remediation `/system-health` already prints.
"""

from __future__ import annotations

import time

import structlog

log = structlog.get_logger()

# How far ahead to warn. Long enough that a team on a weekly release cadence sees it with a cycle to
# spare, short enough that the warning is not permanently lit for a fleet on healthy 30-day rotation.
WARN_WITHIN_S = 7 * 24 * 3600

_KEY_PREFIX = "sidecar_exp"


def _key(namespace: str, workload: str) -> str:
    return f"{_KEY_PREFIX}:{namespace or '-'}:{workload or '-'}"


async def observe(cache, claims: dict) -> None:
    """Record that this caller's credential expires soon. Best-effort, never raises.

    Called from the authentication path, so the cost discipline matters:

    * SERVICE tokens only. A human session is short-lived by design and its expiry is not an
      infrastructure event — warning about it would bury the signal in noise.
    * Nothing is written until the credential is inside the warning window, so the steady state for a
      healthy fleet is ZERO writes on the hot path.
    * `nx=True` bounds it to one write per (namespace, workload) even inside the window, instead of one
      per request — a busy workload in its final week could otherwise turn this into a write per
      evaluate call.
    * The TTL is the credential's own remaining lifetime, so the record cannot outlive the thing it
      describes and no cleanup job is needed.

    The `nx` guard means a rotated credential does not immediately overwrite the older record. That is
    deliberate and safe in the direction that matters: the stale value is always the EARLIER expiry, so
    the warning appears early and clears when the old key times out. Warning too early is a nuisance;
    warning too late is the bug.
    """
    if cache is None:
        return
    try:
        if str(claims.get("role", "")).lower() != "service":
            return
        exp = int(claims.get("exp") or 0)
        if exp <= 0:
            return
        remaining = exp - int(time.time())
        if remaining <= 0 or remaining > WARN_WITHIN_S:
            return
        key = _key(str(claims.get("namespace") or ""), str(claims.get("workload") or ""))
        await cache._client().set(key, str(exp), ex=max(1, remaining), nx=True)
    except Exception as exc:  # noqa: BLE001 — a reporting write must never fail authentication
        log.debug("nrvq.api.sidecar_expiry.observe_failed", error=str(exc), code="NRVQ-API-7120")


async def expiring_soon(cache, namespace: str | None = None) -> list[dict]:
    """The recorded credentials inside the warning window, newest-expiring last. Best-effort -> [].

    Returns `[]` rather than raising on any failure, so an unreadable Redis degrades this to "no
    warning" instead of taking down the health page an operator opens during an incident. That is the
    right direction here and only here: absence of a warning is the status quo the product shipped
    with, whereas a 500 on /system-health removes the surface that reports every OTHER outage.
    """
    if cache is None:
        return []
    out: list[dict] = []
    try:
        client = cache._client()
        now = int(time.time())
        async for raw in client.scan_iter(match=f"{_KEY_PREFIX}:*", count=200):
            key = raw.decode() if isinstance(raw, (bytes, bytearray)) else str(raw)
            parts = key.split(":")
            if len(parts) < 3:
                continue
            ns, workload = parts[1], ":".join(parts[2:])
            if namespace and ns != namespace:
                continue
            value = await client.get(key)
            if value is None:
                continue
            exp = int(value.decode() if isinstance(value, (bytes, bytearray)) else value)
            out.append({
                "namespace": "" if ns == "-" else ns,
                "workload": "" if workload == "-" else workload,
                "expires_at": exp,
                "days_left": max(0, round((exp - now) / 86400, 1)),
            })
    except Exception as exc:  # noqa: BLE001 — see the docstring; degrade to "no warning"
        log.warning("nrvq.api.sidecar_expiry.read_failed", error=str(exc), code="NRVQ-API-7121")
        return []
    out.sort(key=lambda r: r["expires_at"])
    return out


def issue_for(rows: list[dict]) -> dict | None:
    """Render the warning band for /system-health, or None when there is nothing to say."""
    if not rows:
        return None
    soonest = rows[0]
    names = ", ".join(f"{r['workload'] or '?'} ({r['namespace'] or '?'})" for r in rows[:5])
    if len(rows) > 5:
        names += f", and {len(rows) - 5} more"
    return {
        "id": "sidecar_credential_expiring",
        # WARNING, not critical: nothing is broken yet, and that is the entire point of this entry.
        # Raising it as critical would train operators to ignore the band that DOES mean an outage.
        "severity": "warning",
        "title": "Injected sidecar credentials expire soon",
        "detail": (
            f"{len(rows)} injected workload(s) hold a credential expiring within "
            f"{WARN_WITHIN_S // 86400} days — soonest in {soonest['days_left']} day(s): {names}. "
            "Nothing renews these in place: the token and client certificate are 30-day and are fixed "
            "in the pod spec at admission. When one expires the engine refuses that sidecar's calls "
            "and they fail CLOSED, so the workload's tool calls stop."
        ),
        "remediation": (
            "Roll the affected Deployments before the date above — replacement is how these rotate, "
            "and a new pod is admitted with freshly minted credentials."
        ),
        "affected_calls": len(rows),
        "namespaces": sorted({r["namespace"] for r in rows if r["namespace"]}),
        "last_seen": None,
        "window_minutes": None,
        "expiring": rows[:20],
    }
