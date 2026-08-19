# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Forewarning for expiring service credentials — the 30-day sidecar cliff (C2-020), and service keys.

TWO KINDS, and conflating them is what this module got wrong first time round. It captured every
`role=service` principal and described all of them as injected sidecars, but `role=service` also covers
the webhook controller, the fleet relay and every operator-minted service key (`auth.py`: "principals
(role=service: the webhook controller, fleet relay) stay trusted with an empty claim"). The `workload`
claim is what the injector actually mints and is OPTIONAL for everything else, so those principals were
recorded under an empty workload and rendered as "? (norviq)" — a red, permanent band naming no
workload, telling the operator to roll a Deployment that did not exist. Observed live on a kind install
where NO pod in that namespace had an injected sidecar at all.

So the kind is decided by the `workload` claim, the subject is always recorded (workload, else `sub`),
and each kind gets its own band because their remediations have nothing in common.

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

# v2. The v1 prefix keyed on (namespace, WORKLOAD) and captured every `role=service` principal, but
# `workload` is an optional claim that only the injector mints — so the webhook controller, the fleet
# relay and every operator-minted service key landed under an empty workload and rendered as "? (ns)":
# a red banner naming nothing, telling the operator to roll a Deployment that does not exist. The v1
# keys are deliberately NOT read any more; each carries the credential's own remaining lifetime as its
# TTL, so they age out on their own and a stale unnameable row disappears from the banner immediately.
_KEY_PREFIX = "cred_exp"
_LEGACY_KEY_PREFIX = "sidecar_exp"

#: An injected sidecar credential, identified by the `workload` claim the injector mints
#: (`webhook/injector.go`). Rotates by pod replacement.
KIND_SIDECAR = "sidecar"
#: Any other `role=service` principal — the webhook controller, the fleet relay, an operator-minted
#: service key. Rotates by minting a replacement and updating whatever consumes it.
KIND_SERVICE_KEY = "service_key"


def _key(kind: str, namespace: str, subject: str) -> str:
    return f"{_KEY_PREFIX}:{kind}:{namespace or '-'}:{subject or '-'}"


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
        # SHORT-LIVED CREDENTIALS ARE NOT "EXPIRING SOON" — they are short-lived on purpose, and
        # something re-mints them. The webhook controller signs itself a ONE-HOUR service JWT and
        # re-mints it at 60s-to-expiry (`webhook/controller.go`, `bearerToken`), so it is ALWAYS inside
        # a 7-day window: on a fresh install this warning appeared immediately, marked the whole system
        # `degraded`, and could never clear. Measured on a clean AKS install.
        #
        # A credential whose ENTIRE lifetime is shorter than the warning window was born inside it, so
        # "expires within 7 days" carries no information about it. Lifetime, not remaining time, is what
        # separates the two: a 30-day sidecar credential still warns at day 23; a 1-hour token never
        # does. No `iat` means the lifetime is unknowable, and there the safe direction is to warn —
        # missing a real expiry is worse than one extra band.
        issued = int(claims.get("iat") or 0)
        if issued > 0 and (exp - issued) <= WARN_WITHIN_S:
            return
        # WHICH KIND of service credential this is decides the entire warning: its title, what it says
        # will break, and what the operator should do. `workload` is the injector's own claim, so its
        # presence — not `role=service` — is what makes something an injected sidecar.
        workload = str(claims.get("workload") or "")
        if workload:
            kind, subject = KIND_SIDECAR, workload
        else:
            kind, subject = KIND_SERVICE_KEY, str(claims.get("sub") or "")
        if not subject:
            # Nothing to name means nothing to act on, and a warning an operator cannot resolve trains
            # them to ignore the band. Both minting paths set `sub`, so this is a degenerate token.
            log.debug("nrvq.api.sidecar_expiry.unnameable_credential", code="NRVQ-API-7122")
            return
        key = _key(kind, str(claims.get("namespace") or ""), subject)
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
            if len(parts) < 4:
                continue
            kind, ns, subject = parts[1], parts[2], ":".join(parts[3:])
            if kind not in (KIND_SIDECAR, KIND_SERVICE_KEY):
                continue
            if namespace and ns != namespace:
                continue
            value = await client.get(key)
            if value is None:
                continue
            exp = int(value.decode() if isinstance(value, (bytes, bytearray)) else value)
            out.append({
                "kind": kind,
                "namespace": "" if ns == "-" else ns,
                "subject": "" if subject == "-" else subject,
                # Kept so an older console still renders a name rather than an empty cell; for a
                # service key this is the key's own subject, which IS what an operator acts on.
                "workload": "" if subject == "-" else subject,
                "expires_at": exp,
                "days_left": max(0, round((exp - now) / 86400, 1)),
            })
    except Exception as exc:  # noqa: BLE001 — see the docstring; degrade to "no warning"
        log.warning("nrvq.api.sidecar_expiry.read_failed", error=str(exc), code="NRVQ-API-7121")
        return []
    out.sort(key=lambda r: r["expires_at"])
    return out


def issue_for(rows: list[dict]) -> dict | None:
    """The warning band for /system-health, or None when there is nothing to say.

    Returns the SOONEST-expiring kind. `issues_for` returns one band per kind and is what the route
    uses; this is kept because a single band was the shipped shape and returning two from a function
    named `issue_for` would be a silent contract change for any other caller.
    """
    bands = issues_for(rows)
    return bands[0] if bands else None


def issues_for(rows: list[dict]) -> list[dict]:
    """One band per kind of expiring credential, soonest first.

    Split because the two kinds share nothing an operator acts on. An injected sidecar's credential is
    baked into an immutable pod spec and rotates by pod replacement; a service key is a row an operator
    minted and rotates by minting another and updating whatever presents it. One band saying "roll the
    affected Deployments" over a mixed list is wrong for half of it — and was wrong for ALL of it here,
    because the only row this install ever produced was a service principal with no workload at all.
    """
    if not rows:
        return []
    out: list[dict] = []
    for kind in (KIND_SIDECAR, KIND_SERVICE_KEY):
        group = [r for r in rows if r.get("kind", KIND_SIDECAR) == kind]
        if group:
            out.append(_band(kind, group))
    out.sort(key=lambda b: b["expiring"][0]["expires_at"])
    return out


def _band(kind: str, rows: list[dict]) -> dict:
    soonest = rows[0]
    names = ", ".join(
        f"{r.get('subject') or r.get('workload') or '?'} ({r['namespace'] or '?'})" for r in rows[:5]
    )
    if len(rows) > 5:
        names += f", and {len(rows) - 5} more"
    days = WARN_WITHIN_S // 86400
    if kind == KIND_SIDECAR:
        ident, title = "sidecar_credential_expiring", "Injected sidecar credentials expire soon"
        detail = (
            f"{len(rows)} injected workload(s) hold a credential expiring within {days} days — soonest "
            f"in {soonest['days_left']} day(s): {names}. Nothing renews these in place: the token and "
            "client certificate are 30-day and are fixed in the pod spec at admission. When one expires "
            "the engine refuses that sidecar's calls and they fail CLOSED, so the workload's tool calls "
            "stop."
        )
        remediation = (
            "Roll the affected Deployments before the date above — replacement is how these rotate, "
            "and a new pod is admitted with freshly minted credentials."
        )
    else:
        ident, title = "service_key_expiring", "Service keys expire soon"
        detail = (
            f"{len(rows)} service credential(s) expire within {days} days — soonest in "
            f"{soonest['days_left']} day(s): {names}. These are not injected sidecars: they are keys an "
            "operator minted (an MCP proxy, the fleet relay, a CI caller). When one expires the API "
            "answers 401 and the caller fails CLOSED, so whatever presents it stops working."
        )
        remediation = (
            "Mint a replacement key with the same role and namespace, update whatever presents it, then "
            "revoke the old one. Rolling a Deployment does NOT rotate these."
        )
    return {
        "id": ident,
        # WARNING, not critical: nothing is broken yet, and that is the entire point of this entry.
        # Raising it as critical would train operators to ignore the band that DOES mean an outage.
        "severity": "warning",
        "title": title,
        "detail": detail,
        "remediation": remediation,
        "affected_calls": len(rows),
        "namespaces": sorted({r["namespace"] for r in rows if r["namespace"]}),
        "last_seen": None,
        "window_minutes": None,
        "expiring": rows[:20],
    }
