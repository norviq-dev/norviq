# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The ONE classifier for traffic the product generated about itself, and for test/probe identities.

Every consumer imports it from here: the real-traffic filters (audit stats, volume, top-blocked, the
Audit Log's "Real traffic only", the live tail, MITRE/compliance evidence, coverage efficacy, /tools,
intent proposals, dry-run replay, system-health liveness), the Agents roster, the Asset and Attack
graphs, the red-team target picker, and the engine's per-identity writers (agent registry, trust
cache, trust history, behavioural profile, asset graph). Never fork a second copy.

There are two halves, and they mean different things:

  * ``is_synthetic_framework`` -- the CALL was fabricated (a red-team run, an Attack Graph Simulate,
    a probe). Its identity may be a real agent's SVID, or a made-up ``sa/<class>`` one that no
    workload uses, and nothing in the identity says which. So the engine writes NO per-identity state
    for it: writing it to a real SVID poisons that agent's trust, and writing it to a made-up SVID
    invents an agent. The audit row still records the call, with the framework as its marker.
  * ``is_synthetic_identity`` -- the IDENTITY is a test identity (the Policy Tester's
    ``sa/policy-tester-<rand>``, e2e classes, eval scorers). State written under it is isolated to
    it, so it may register; every surface hides it by default behind a "N hidden -- Show" toggle.

``is_non_real_traffic`` is either of them, and ``audit_row_is_non_real`` is its SQL twin.

Identity source of truth, in order:
  1. An explicit marker on the node -- ``norviq.io/synthetic=true`` (preferred; survives renaming).
  2. A naming convention, matched ANCHORED at the start of the agent class AND of the SVID's
     ``/sa/<name>`` segment. Both are checked because the Policy Tester runs under the class the
     operator is testing (a real one) and marks itself only in the service-account segment.

Real agents (customer-support, deploy-bot, report-runner, hr-chatbot, billing-assistant, payments, pipeline, ...)
never match, so excluding synthetics never drops a real node/edge or a real affected-agent-class chip.
"""

from __future__ import annotations

import re

# Class-name PREFIXES that mark a seeded probe / test / eval identity (matched against the class name, anchored
# at its start — e.g. "evtrace-1783266533" matches "evtrace-"). Kept specific so real product classes (nouns
# like "customer-support", "billing-assistant") never collide.
SYNTHETIC_CLASS_PREFIXES: tuple[str, ...] = (
    "allowlist-probe",   # intent-allowlist e2e probes
    "e2e-",              # all e2e-spec throwaway classes (e2e-intent-*, e2e-probe, e2e-123, e2e-bot, …).
                         # Was "e2e-intent" alone, which missed siblings minted by other e2e specs and
                         # leaked them into the Asset/Attack graphs. No real product class starts "e2e-".
    "policy-tester-",    # Policy Tester's per-session ephemeral identity (policy-tester-<rand>); the bare
                         # "policy-tester" is in SYNTHETIC_CLASS_EXACT below, this covers the disposable form.
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


# Framework tags the product's own fabricated traffic carries. One set for the engine and the API: they
# used to disagree (the engine also knew red-team/policy-tester/probe, the API only "redteam") and the
# Attack Graph's Simulate tag was in neither, so Simulate calls counted as real traffic everywhere.
SYNTHETIC_FRAMEWORKS: frozenset[str] = frozenset({
    "redteam",        # console Red Team suite + `norviq redteam run` (norviq/redteam/attacks.py)
    "red-team",       # spelling variant accepted from raw /evaluate callers
    "policy-tester",  # Policy Tester (it also marks its SVID; see SYNTHETIC_CLASS_PREFIXES)
    "probe",          # hand-made probes
    "attack-graph",   # Attack Graph Simulate + the path engine's step checks
})


def is_synthetic_framework(framework: str | None) -> bool:
    """True when the call itself was fabricated by the product (see the module docstring)."""
    return str(framework or "").strip().lower() in SYNTHETIC_FRAMEWORKS


def _class_from_spiffe(spiffe_id: str | None) -> str | None:
    """Extract the ``<name>`` from ``spiffe://.../sa/<name>`` (defensive)."""
    if not spiffe_id:
        return None
    parts = spiffe_id.split("/")
    if "sa" in parts:
        idx = parts.index("sa")
        if idx + 1 < len(parts) and parts[idx + 1]:
            return parts[idx + 1]
    return None


def _is_synthetic_name(name: str | None) -> bool:
    cls = (name or "").strip().lower()
    if not cls:
        return False
    if cls in SYNTHETIC_CLASS_EXACT:
        return True
    if cls.startswith(SYNTHETIC_CLASS_PREFIXES):
        return True
    return bool(_SYNTHETIC_RE.match(cls))


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
    # (2) naming convention, on the class AND on the SVID's service-account segment. The SVID used to be
    # read only when the class was empty, so a Policy Tester session (real class, `sa/policy-tester-<rand>`)
    # counted as real traffic and listed as a real agent.
    return _is_synthetic_name(agent_class) or _is_synthetic_name(_class_from_spiffe(spiffe_id))


def is_non_real_traffic(
    framework: str | None,
    agent_class: str | None,
    spiffe_id: str | None = None,
) -> bool:
    """True when a call must not count as real traffic: a fabricated call OR a test identity.
    ``audit_row_is_non_real`` below is the SQL twin of exactly this function."""
    return is_synthetic_framework(framework) or is_synthetic_identity(agent_class, spiffe_id)


def is_non_real_row(row) -> bool:
    """``is_non_real_traffic`` over an audit_log row (ORM object or anything with the same attributes)."""
    return is_non_real_traffic(
        getattr(row, "framework", None), getattr(row, "agent_class", None), getattr(row, "agent_id", None)
    )


# --- the SQL twins ---------------------------------------------------------------------------------
#
# Each predicate below is ONE regular expression per column, matched with SQLAlchemy's
# ``regexp_match``. That compiles to Postgres' ``~`` in production and to ``REGEXP`` on SQLite, where
# SQLAlchemy's driver registers Python's ``re.search`` for it, so the suite can run the same SQL against
# real rows and compare every answer with the Python functions above. The old twin used Postgres-only
# ``~`` and two-argument ``substring()``, and it could only be checked by reading its text. Running it
# showed where it disagreed with Python: ``trim()`` strips spaces only, so a tab or newline around a
# tag or class made a row synthetic in Python and real in SQL.
#
# The patterns keep to what Postgres' regex flavour and Python's ``re`` read the same way: ``^ $``,
# ``(?:a|b)``, ``* + {n,}``, ``[...]`` and ``\s``. Case is matched with explicit ``[xX]`` classes, not
# ``lower()``, because the SVID's ``sa`` marker is case-sensitive in ``_class_from_spiffe`` while the
# name after it is not. Only ASCII letters are folded: the names are all ASCII, and Python's ``lower()``
# maps a handful of non-ASCII letters (the Kelvin sign) onto ASCII ones, which the SQL does not follow.

_SAFE_NAME = re.compile(r"[a-z0-9-]+")
for _name in (*SYNTHETIC_FRAMEWORKS, *SYNTHETIC_CLASS_EXACT, *SYNTHETIC_CLASS_PREFIXES):
    # Embedded in the patterns without escaping, so they must stay plain. A "-" outside a bracket is a
    # literal in both regex flavours. A raise, not an assert, so `python -O` cannot skip the check.
    if not _SAFE_NAME.fullmatch(_name):
        raise ValueError(f"synthetic name {_name!r} needs escaping before it can go in the SQL twin")


def _ci(name: str) -> str:
    """``name`` as a pattern that matches it in any ASCII case."""
    return "".join(f"[{c}{c.upper()}]" if c.isalpha() else c for c in name)


def _alt(names) -> str:
    return "(?:" + "|".join(_ci(n) for n in sorted(names)) + ")"


# A whole tag, with any whitespace around it: `str(framework).strip().lower() in SYNTHETIC_FRAMEWORKS`.
_FRAMEWORK_PATTERN = rf"^\s*{_alt(SYNTHETIC_FRAMEWORKS)}\s*$"
# What `_is_synthetic_name` accepts once the name has been stripped: an exact name, a prefix, or the
# wave<N>e2e form. `{end}` is what must follow an exact name: the end of the value, or of the segment.
_NAME_BODY = (
    r"(?:{exact}\s*{end}|{prefixes}|" + _ci("wave") + r"[0-9]+" + _ci("e2e") + ")"
).format(exact=_alt(SYNTHETIC_CLASS_EXACT), prefixes=_alt(SYNTHETIC_CLASS_PREFIXES), end="{end}")
_CLASS_PATTERN = r"^\s*" + _NAME_BODY.format(end="$")
# `_class_from_spiffe`: the segment after the FIRST segment that is exactly "sa" (case-sensitive), when
# that segment is not empty. `_NOT_SA` is any segment other than "sa": empty, one character, three or
# more, or two characters that are not "sa".
_NOT_SA = r"(?:[^/]?|[^/]{3,}|[^s/][^/]|s[^a/])"
_SVID_PATTERN = rf"^(?:{_NOT_SA}/)*sa/\s*" + _NAME_BODY.format(end="(?:/|$)")


def _matches(column, pattern: str):
    from sqlalchemy import func

    # COALESCE so a NULL column is "" (real), never a NULL that turns NOT(...) into NULL and drops the row.
    return func.coalesce(column, "").regexp_match(pattern)


def audit_row_is_fabricated(model):
    """SQLAlchemy twin of ``is_synthetic_framework`` for an audit_log row. Used on its own where the
    identity is already fixed (one agent's drill-down), so only the fabricated-call half applies."""
    return _matches(model.framework, _FRAMEWORK_PATTERN)


def identity_is_synthetic_sql(agent_class_column, spiffe_column):
    """SQLAlchemy twin of ``is_synthetic_identity`` over a class column and a SPIFFE-id column, for tables
    that have no marker properties (audit_log, agent_registry)."""
    from sqlalchemy import or_

    return or_(_matches(agent_class_column, _CLASS_PATTERN), _matches(spiffe_column, _SVID_PATTERN))


def registry_row_is_synthetic(model):
    """``is_synthetic_identity`` for an agent_registry row: the filter for agent lists that hide test
    identities by default."""
    return identity_is_synthetic_sql(model.agent_class, model.spiffe_id)


# SQL mirror for audit_log rows: the twin of ``is_non_real_traffic``, kept HERE next to it so the Python
# and the SQL never drift. For audit rows the props-marker path never applies (no properties column).
def audit_row_is_non_real(model):
    """SQLAlchemy predicate: True when an audit_log row is NON-real traffic (a synthetic framework, OR a
    synthetic class, OR a synthetic SVID service-account segment). ``~audit_row_is_non_real(M)`` is the
    real-traffic-only filter."""
    from sqlalchemy import or_

    return or_(audit_row_is_fabricated(model), identity_is_synthetic_sql(model.agent_class, model.agent_id))
