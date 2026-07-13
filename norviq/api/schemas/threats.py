# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Response/request schemas for the Attack Graph (feat/attack-graph).

The enriched ``ThreatPath`` is the design-handoff kill-chain shape the console renders (ranked list +
d3 canvas + inspector). It is derived server-side from the asset-graph snapshot + real audit decision
history (see routers/threats.py) — every field is real data, no mock."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ReachAsset(BaseModel):
    """One asset in a path's blast radius. ``s=1`` marks a sensitive (data / high-sensitivity) asset."""

    n: str
    s: int = 0


class ThreatStep(BaseModel):
    """One hop of a kill-chain, joined to its asset-graph edge's real 24h decision counts."""

    from_: str = Field(alias="from")
    to: str
    verb: str  # "calls" (→ tool) | "reaches" (→ data)
    dec: str  # "allow" | "mixed" | "block" | "would_block" — from the edge's real decision history
    kind: str  # "agent" | "tool" | "data" — the target node kind
    deny: int = 0
    allow: int = 0
    would_block: int = 0  # Monitor-mode would-block count on this hop (logged, not enforced)
    # CAP-2: the ACTUAL data operation this hop performs (read/write/delete/send) + its risk, from the
    # source-capability registry — so a destructive hop reads differently from a read hop instead of a
    # generic "reaches". Populated only when the operation resolves against a known source type; None
    # otherwise (unknown source / generic tool name), so the UI falls back to the plain relationship word.
    op: str | None = None
    op_risk: str | None = None  # low | medium | high | critical
    # Classification lifecycle: where the op came from ("learned" = admin-promoted, "registry" = the
    # name/token classifier); and for a still-UNCLASSIFIED tool hop, the observation evidence so the UI
    # can show "observing · {verb} n/m" instead of nothing.
    op_src: str | None = None
    inferred_verb: str | None = None
    inferred_count: int = 0
    observed_calls: int = 0

    model_config = {"populate_by_name": True}


class ThreatPath(BaseModel):
    """The enriched kill-chain the Attack Graph renders."""

    id: str
    sev: str  # critical | high | medium | low
    src: str
    tgt: str
    ns: str
    cls: str
    mitre: str
    hops: int
    trust: float
    blast: int
    status: str  # exploitable | blocked | unsimulated
    tool: str  # chokepoint tool
    reach: list[ReachAsset] = []
    steps: list[ThreatStep] = []
    verdict: str = ""
    fix: str = ""
    # An intent/capability policy is APPLIED for this class whose allowlist would deny the chokepoint tool.
    # The `status` above is derived from historical audit, so it can still read "exploitable" right after a
    # defense is applied (no new traffic yet) — this flag says "you have a defense here; Simulate to confirm".
    governed_by: str = ""  # "" | "intent" | "capability"


class ThreatPathsResponse(BaseModel):
    paths: list[ThreatPath] = []
    namespaces: list[str] = []
    # A1: number of paths hidden because their source agent is synthetic/probe (drives the "N hidden — Show" chip).
    synthetic_hidden: int = 0


class IntentToggles(BaseModel):
    readonly: bool = False
    scope: bool = False
    rate: bool = False
    egress: bool = False


class IntentCoverageRequest(BaseModel):
    ns: str = "all"
    cls: str
    intent: IntentToggles = IntentToggles()
    allow_tools: list[str] = []


class IntentCoverageResponse(BaseModel):
    rego: str
    covered: list[str] = []  # path ids the generated policy DENIES
    residual: list[str] = []  # path ids still exploitable
    covered_count: int = 0
    total: int = 0


class IntentDraftRequest(BaseModel):
    ns: str = "default"
    cls: str
    intent: IntentToggles = IntentToggles()
    allow_tools: list[str] = []
    path_ids: list[str] = []


class IntentSuggestTool(BaseModel):
    """One tool an agent of the class actually calls — a candidate for the intended allowlist."""

    name: str
    allow: int = 0  # real 24h allow decisions on this agent→tool edge
    block: int = 0  # real 24h block decisions
    tag: str = "normal"  # "egress" | "chokepoint" | "normal"
    target: str | None = None  # the data/target node this tool reaches on a class attack path, if any
    in_attack_path: bool = False
    # The tool's inferred OPERATION (read/write/delete/send) + risk, so the operator sees WHAT each tool
    # does when choosing what to allow — resolved even for cloud/opensource tools (aws_s3_delete, …).
    op: str | None = None
    op_risk: str | None = None  # low | medium | high | critical
    # Where the op came from: "learned" = an admin PROMOTED the verb (tool_verb_overrides),
    # "registry" = the name/token classifier. None when op is None (observation phase).
    op_src: str | None = None
    # OBSERVATION-phase evidence for a still-unclassified tool: total evidenced calls + the verb the
    # params suggest most often. Drives the "observing · inferred {verb} · Promote" affordance.
    observed_calls: int = 0
    inferred_verb: str | None = None
    inferred_count: int = 0


class IntentSuggestResponse(BaseModel):
    ns: list[str] = []
    cls: str
    tools: list[IntentSuggestTool] = []


class IntentDraftResponse(BaseModel):
    draft_id: str
    policy: str  # "{ns}/{cls}"
    ns: str
    cls: str
    deeplink: str
    priority: int = 1  # == the comprehensive baseline priority for the ns (tighten-only tie-break)
    enforcement: str = "draft"  # NEVER "enforce" — a draft never enforces on its own
    valid: bool = True
    errors: list[str] = []
    would_block: int = 0
    would_allow: int = 0
    covered_count: int = 0
    total: int = 0


class IntentDraftSummary(BaseModel):
    draft_id: str
    ns: str
    cls: str
    # COMP-GEN-01 fix: for a compliance-remediation draft, `cls` (== agent_class) is the compound
    # persistence overlay key ("<class>__remediation__"); `affected_class` carries the real class the
    # draft affects, for UI display. NULL for non-remediation drafts (where `cls` already is the real class).
    affected_class: str | None = None
    enabled: list[str] = []
    allow_tools: list[str] = []
    covered_count: int = 0
    total: int = 0
    created_by: str = ""
    created_at: str = ""
    # F2: compliance-draft provenance (None for Attack-Graph intent drafts).
    source_framework: str | None = None
    source_control_id: str | None = None
    source_control_name: str | None = None
    # Part B: TTL — when this non-enforcing draft auto-expires (ISO; "" = never).
    expires_at: str = ""


class IntentDraftPage(BaseModel):
    """Part B (B6): a BOUNDED page of drafts + the total count, so the Policy Catalog never renders the whole
    list at once ("N more · view all")."""

    drafts: list[IntentDraftSummary] = []
    total: int = 0          # total real (non-expired) drafts matching the scope
    returned: int = 0       # how many are in this page
    offset: int = 0
    limit: int = 0
