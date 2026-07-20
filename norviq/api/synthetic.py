# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Classify synthetic / test / probe / eval agent identities so the Asset & Attack graphs (and the Compliance
"affected agent-classes" join) can exclude them by default.

The graphs would otherwise be dominated by scattered probe/eval SVIDs minted by the red-team / e2e / eval /
policy-tester / scorer harnesses — NOT a real runtime concept (they exist only on seeded / test clusters).
Default-hide them, with a "N test/probe hidden — Show" toggle. This is the ONE shared classifier used by
``/asset-graph``, ``/attack-paths`` AND the Compliance affected-agent-class join — never fork a second copy.

Source of truth, in order:
  1. An explicit marker on the node — the harness SHOULD mint a probe SVID with ``norviq.io/synthetic=true``
     (preferred; survives any future renaming of the test identities).
  2. A SPIFFE / agent-class NAMING convention the seeded test identities use — matched ANCHORED on the class
     name (the ``/sa/<class>`` SVID segment), not a loose substring, so a real product class can never collide.

Real agents (customer-support, deploy-bot, report-runner, hr-chatbot, billing-assistant, payments, pipeline, …)
never match, so excluding synthetics never drops a real node/edge or a real affected-agent-class chip.
"""

from __future__ import annotations

import re

# Class-name PREFIXES that mark a seeded probe / test / eval identity (matched against the class name, anchored
# at its start — e.g. "evtrace-1783266533" matches "evtrace-"). Kept specific so real product classes (nouns
# like "customer-support", "billing-assistant") never collide.
SYNTHETIC_CLASS_PREFIXES: tuple[str, ...] = (
    "allowlist-probe",   # intent-allowlist e2e probes
    "e2e-intent",        # attack-graph intent e2e
    "probe-",            # generic probes
    "evtrace-",          # /evaluate trace harness
    "effecttest",        # effect-proof harness
    "smoke-",            # smoke tests
    "canary-",           # canary checks
    "wave1e2e", "wave2e2e", "wave3e2e",  # wave e2e specs (also covered by the regex below)
)

# EXACT class names that are console/eval test identities (no real product class uses these).
SYNTHETIC_CLASS_EXACT: frozenset[str] = frozenset({"policy-tester", "scorer"})

# ``wave<N>e2e...`` pattern (the e2e specs mint classes like "wave4e2e-<ts>").
_SYNTHETIC_RE = re.compile(r"^wave\d+e2e", re.IGNORECASE)


def _class_from_spiffe(spiffe_id: str | None) -> str | None:
    """Extract the ``<class>`` from ``spiffe://.../sa/<class>`` (defensive)."""
    if not spiffe_id:
        return None
    parts = spiffe_id.split("/")
    if "sa" in parts:
        idx = parts.index("sa")
        if idx + 1 < len(parts) and parts[idx + 1]:
            return parts[idx + 1]
    return None


def is_synthetic_identity(
    agent_class: str | None,
    spiffe_id: str | None = None,
    properties: dict | None = None,
) -> bool:
    """Return True for a synthetic/test/probe/eval identity that should be hidden from the graphs by default."""
    props = properties or {}
    # (1) explicit marker wins — the harness can set this when it mints a probe SVID.
    if props.get("synthetic") is True:
        return True
    if str(props.get("norviq.io/synthetic", "")).strip().lower() == "true":
        return True
    # (2) naming fallback — anchored on the CLASS name (from agent_class, else parsed from the SVID).
    cls = (agent_class or _class_from_spiffe(spiffe_id) or "").strip().lower()
    if not cls:
        return False
    if cls in SYNTHETIC_CLASS_EXACT:
        return True
    if cls.startswith(SYNTHETIC_CLASS_PREFIXES):
        return True
    if _SYNTHETIC_RE.match(cls):
        return True
    return False


# SQL mirror for audit_log rows. The Overview KPIs (/audit/stats) count REAL traffic only — they drop
# red-team-framework rows AND synthetic/probe identities. To let the Audit Log offer a "Real traffic only"
# filter that reconciles EXACTLY with that headline (instead of the two surfaces silently disagreeing over
# synthetic rows), expose the SAME exclusion as a SQL predicate. Kept HERE, next to the one classifier, so
# the Python and the SQL never drift. For audit rows the props-marker path never applies (no properties
# column), so agent_class alone is authoritative — identical to what is_synthetic_identity checks in stats.
def audit_row_is_non_real(model):
    """SQLAlchemy predicate: True when an audit_log row is NON-real traffic (red-team source OR a
    synthetic/test/probe agent-class). ``~audit_row_is_non_real(M)`` is the real-traffic-only filter."""
    from sqlalchemy import func, or_

    cls = func.lower(func.coalesce(model.agent_class, ""))
    conds = [model.framework == "redteam", cls.in_(tuple(SYNTHETIC_CLASS_EXACT))]
    conds += [cls.like(f"{p}%") for p in SYNTHETIC_CLASS_PREFIXES]  # class-name prefixes (already lowercase)
    conds.append(cls.op("~")("^wave[0-9]+e2e"))  # mirrors _SYNTHETIC_RE (Postgres POSIX regex on the lowered class)
    return or_(*conds)
