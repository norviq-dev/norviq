# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The tool registry: what tools exist, and how well we know it.

This is a READ-ONLY PROJECTION. It owns no table and writes nothing — every row comes from a store that
already exists, and the endpoint's whole job is to say where each name came from.

WHY THIS EXISTS. The Visual Policy Builder had no idea what tools existed, so it inferred a "known tool"
set from recent audit traffic UNIONed with `ALL_CAPABILITY_FRAGMENTS` — substrings like "post", "http",
"delete", which are matching fragments, not identifiers. The same union fed the suggestion dropdown AND
the "no agent has called X yet" warning, so the console offered names that cannot exist and then
suppressed its own warning for exactly those names. Meanwhile Gate A had been parsing real tool
definitions off every `tools/list` and persisting them — schema and all — where nothing read them.

PROVENANCE IS THE POINT, not a column. The bug above is what happens when sources of different strength
are unioned and the union is treated as an existence oracle, so this endpoint returns tiers side by side
and NEVER merges them:

  * ``mcp_declared`` — read from a definition the server actually published and an operator approved.
    Carries a JSON Schema. This is the strong tier.
  * ``observed``     — a name seen in real traffic. Proves the name exists; says nothing about its shape.

A caller that flattens these back into one set has reintroduced the bug.

AN ORACLE, NEVER A GATE. Deny-by-default REQUIRES authoring a rule for a tool nobody has called yet — an
allowlist you can only write after the fact is not a preventive control. So nothing here restricts what
an operator may type. It exists to make the console honest about what it knows, not to shrink what it
will accept.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Literal

import structlog
from fastapi import APIRouter, Depends, Query
from sqlalchemy import distinct, select
from sqlalchemy.ext.asyncio import AsyncSession

from norviq.api.auth import get_current_user, read_namespace
from norviq.api.db.models import AuditLogEntry, McpToolPin
from norviq.api.db.session import get_session
from norviq.api.routers.mcp import _status_of
from norviq.api.synthetic import audit_row_is_non_real  # the ONE shared synthetic/probe classifier (do not fork)
from norviq.config import settings
from norviq.engine.confusables import skeleton

log = structlog.get_logger()
router = APIRouter()

SOURCE_DECLARED = "mcp_declared"
SOURCE_OBSERVED = "observed"

# Mirrors norviq/mcp/scanner.py's ordering. Duplicated rather than imported for the same reason mcp.py
# duplicates the pin verdicts: importing the MCP data plane into the control-plane image for one dict is
# a worse trade than restating five strings.
_SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_RANGE_HOURS = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30, "90d": 24 * 90}


def _severity_at_least(severity: str, threshold: str) -> bool:
    """True when `severity` meets or exceeds `threshold` on the scanner's scale."""
    return _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER.get(threshold, 99)


def _description_is_withheld(scan_severity: str) -> bool:
    """Whether Gate A would have stripped or stubbed this tool's description before the model saw it.

    Re-DERIVED rather than read, because the firewall's action (strip / sanitize / pass) is not persisted
    — `mcp_tool_pins` keeps only `scan_severity` and `findings`. Getting this wrong is not cosmetic:
    `approved_canonical` holds the PRE-sanitize text (the CatalogEntry is built at firewall.py:563-571
    from the original dict; the rewrite at :589-590 acts on a copy), so echoing a description the scanner
    condemned would render, in the operator's console, the exact injection text the firewall withheld from
    the model. The scanner's own thresholds are the only correct source for that judgement.
    """
    return _severity_at_least(scan_severity, settings.mcp_scan_sanitize_severity) or _severity_at_least(
        scan_severity, settings.mcp_scan_strip_severity
    )


def _parse_canonical(canonical: str) -> dict | None:
    """Decode a stored canonical definition, or None if it cannot be read.

    UNPARSEABLE INPUT IS THE NORMAL CASE, not an error path. `canonical_definition` (mcp/pins.py:74-82)
    serialises with `sort_keys=True` and the proxy stores `[:_CANONICAL_MAX]` — a bare 8 KiB slice with no
    marker and no JSON repair (mcp/firewall.py:570). Alphabetically `description` sorts BEFORE
    `inputSchema`, so a server with a verbose (or deliberately padded) description pushes the schema
    wholly past the cap. A truncated definition is therefore invalid JSON *and* may be missing the one
    field we came for. Both outcomes degrade to `schema_available: false` rather than raising.
    """
    if not canonical:
        return None
    try:
        parsed = json.loads(canonical)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _declared_row(row: McpToolPin) -> dict:
    """One `mcp_declared` entry.

    Reads `approved_canonical`, never `last_canonical`. The distinction is the entire reason the pins
    table exists: `last_canonical` is whatever the server is serving RIGHT NOW, which on a drifted or
    hostile server is attacker-controlled and unreviewed. Seeding a policy-authoring picker from it would
    let a server that changed its own definition steer which arguments an operator thinks exist. The
    approved copy is the one a human blessed.
    """
    definition = _parse_canonical(row.approved_canonical)
    schema = definition.get("inputSchema") if definition else None
    if not isinstance(schema, dict):
        schema = None

    withheld = _description_is_withheld(row.scan_severity or "none")
    description = None if withheld or definition is None else definition.get("description")
    if not isinstance(description, str):
        description = None

    return {
        "name": row.tool_name,
        # Computed SERVER-side and shipped, never recomputed in the browser: ui/src/lib/skeleton.ts
        # ports neither the cross-script confusables table nor Cf/Cc stripping, so a browser-derived
        # skeleton disagrees with `input.tool_name_normalized` and bakes an unmatchable literal into rego.
        "name_skeleton": skeleton(row.tool_name),
        "source": SOURCE_DECLARED,
        "namespace": row.namespace,
        "server_id": row.server_id,
        "pin_status": _status_of(row),
        "scan_severity": row.scan_severity,
        "description": description,
        "description_withheld": withheld,
        "input_schema": schema,
        "schema_available": schema is not None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
    }


def _observed_row(namespace: str, tool_name: str) -> dict:
    """One `observed` entry: the name existed in real traffic, and that is all this tier claims."""
    return {
        "name": tool_name,
        "name_skeleton": skeleton(tool_name),
        "source": SOURCE_OBSERVED,
        "namespace": namespace,
        "server_id": None,
        "pin_status": None,
        "scan_severity": None,
        "description": None,
        "description_withheld": False,
        "input_schema": None,
        "schema_available": False,
        "last_seen_at": None,
    }


@router.get("/tools")
async def list_tools(
    namespace: str | None = Query(default=None),
    range: Literal["24h", "7d", "30d", "90d"] = Query(default="30d"),
    session: AsyncSession = Depends(get_session),
    user: dict = Depends(get_current_user),
) -> list[dict]:
    """Every tool the caller may see, each tagged with how we know about it.

    An EMPTY LIST IS A NORMAL ANSWER and callers must treat it as one. `mcp_tool_pins` is populated only
    when MCP injection is on (helm ships `webhook.injection.mcp.enabled: false`) AND a pod is annotated
    AND its server actually serves a `tools/list`; on top of that, HTTP-transport proxies never report at
    all. A console that renders "no tools exist" from an empty registry would be wrong far more often
    than it was right — hence the `observed` tier, and hence nothing here gates authoring.
    """
    ns = read_namespace(user, namespace)

    pin_stmt = select(McpToolPin)
    if ns:  # `read_namespace` returns None for "every readable namespace" — the guard is mandatory
        pin_stmt = pin_stmt.where(McpToolPin.namespace == ns)
    pins = (await session.scalars(pin_stmt.order_by(McpToolPin.server_id, McpToolPin.tool_name))).all()

    rows = [_declared_row(p) for p in pins]
    # Keyed on (NAMESPACE, name), never on the bare name. `read_namespace` returns None for the
    # console's default "All namespaces" scope, so `pins` then spans every tenant — and a name-only
    # set would suppress the observed row for `payments/run_query` because SOME OTHER namespace pinned
    # a `run_query`. The operator authoring policy for `payments` would read a tool that is unpinned,
    # unscanned and of unknown shape there as declared-and-approved: precisely the flattening this
    # module's docstring calls "reintroducing the bug". Declared in one namespace and merely observed
    # in another is TWO facts, and they belong in their two tiers.
    declared_keys = {(p.namespace, p.tool_name.lower()) for p in pins}

    # Observed tier. `audit_row_is_non_real` is the SQL twin of `is_synthetic_identity` and exists exactly
    # so this exclusion does not have to be re-expressed (or forgotten): without it, red-team and probe
    # traffic would register as evidence that a tool is real, which is the opposite of what this tier
    # claims. Overview/Compliance already reconcile against the same predicate.
    since = datetime.now(timezone.utc) - timedelta(hours=_RANGE_HOURS[range])
    seen_stmt = (
        select(distinct(AuditLogEntry.tool_name), AuditLogEntry.namespace)
        .where(AuditLogEntry.timestamp_utc >= since)
        .where(~audit_row_is_non_real(AuditLogEntry))
    )
    if ns:
        seen_stmt = seen_stmt.where(AuditLogEntry.namespace == ns)
    for tool_name, row_ns in (await session.execute(seen_stmt)).all():
        name = str(tool_name or "")
        # A declared tool that has also been called stays in the strong tier — it is the same tool IN
        # THAT NAMESPACE, and emitting it twice would invite a caller to count it twice. The same name
        # in a namespace with no pin is a DIFFERENT fact and keeps its observed row.
        if not name or (str(row_ns or ""), name.lower()) in declared_keys:
            continue
        rows.append(_observed_row(str(row_ns or ""), name))

    log.debug(
        "nrvq.api.tools.list",
        # Counted off `pins`/`rows`, not off a de-duplicated name set: `rows` holds one entry PER PIN,
        # so two servers declaring one name made `len(rows) - len(names)` over-report the observed tier.
        declared=len(pins),
        observed=len(rows) - len(pins),
        code="NRVQ-API-7040",
    )
    return rows
