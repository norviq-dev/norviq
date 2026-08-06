// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Visual Policy Builder — Phase 2 spike (round B). The MVP "linear rule rail" sheet: scope (agent
// class) + an editable list of rules (decision, rule_id, reason, OR-of-AND condition rows) + defaults,
// compiled LIVE (client-side, no round trip) via builderCompile.ts into a read-only rego preview with a
// budget meter and inline compile errors. Dry-run replays the compiled rego against real traffic before
// Save & enforce is allowed — recompiling the graph invalidates a prior dry-run (staleness is tracked by
// exact rego-string identity, the same doctrine the raw editor in PolicyCatalog.tsx uses).
//
// No free-form rego ever reaches this component — every field is enum/string/number, so a malicious or
// careless graph can never inject rego syntax (see builderCompile.ts's header comment for the full
// argument). Visual language borrows the PolicyCatalog sheet kit (`sheet-overlay`/`sheet-kit`,
// `section-label`, `field-row`, `KitButton`) so this reads as part of the same product, not a bolt-on.

import "../../lib/monaco"; // Bundle Monaco locally — must precede <Editor> (see lib/monaco.ts)
import "./BuilderSteps.css"; // Numbered-step left pane (UX redesign) — layout only, see file header.
import Editor from "@monaco-editor/react";
import { registerRego } from "../../lib/monaco-rego";
import { ProvenanceBadge } from "../common/ProvenanceBadge";
import { InlineDisabledReason } from "../common/InlineDisabledReason";
// The console's ONE lookalike DETECTOR (IntentModal / RuleCard / NearMissCard / Intents all use it).
// A second detector keyed differently is the defect, not the fix: two surfaces would disagree about
// whether the same observed name is trustworthy, and the quiet one would be this — the surface with
// the Save button. See `BuilderLookalikeNote` below for why this sheet cannot also reuse the shared
// LookalikeNote's *sentence* (a different compiler runs underneath it).
import { lookalikeOf, type Lookalike } from "../../lib/predicateSentence";
import { ConditionPicker, type PickerGroup, type PickerOption } from "./ConditionPicker";
import { ScopeCell } from "./ScopeCell";
import { AlertCircle, Check, FlaskConical, Maximize2, Minimize2, Plus, Trash2, X } from "lucide-react";
import { Fragment, useEffect, useMemo, useRef, useState, type CSSProperties, type ReactNode } from "react";
import {
  apiSend,
  dryRunPolicy,
  fetchAllAgents,
  fetchClusterInfo,
  fetchTools,
  type DryRunReplay,
  type ToolRegistryEntry
} from "../../api/client";
import {
  COLLECTION_FIELD_EXPR,
  NUMERIC_FIELD_EXPR,
  PARAM_PATH_PREFIX,
  SCALAR_FIELD_EXPR,
  compileGraph,
  constraintCostsRegexOp,
  describeFact,
  factCostsRegexOp,
  loaderKeyFor,
  scopeIdentifier,
  type BuilderError
} from "../../lib/builderCompile";
import { schemaPaths, type SchemaPath } from "../../lib/toolSchema";
import type {
  BuilderAllowlistRefinements,
  BuilderParamConstraint,
  BuilderCondition,
  BuilderConditionNot,
  BuilderDecision,
  BuilderDefaults,
  BuilderDetector,
  BuilderGrantFact,
  BuilderGraph,
  BuilderKeywordTarget,
  BuilderMode,
  BuilderRule,
  BuilderScope,
  BuilderCollectionFactField,
  BuilderNumericFactField
} from "../../lib/builderGraph";
import { CAPABILITY_SOURCE_ORDER, CAPABILITY_SOURCES, verbsForSource, type CapabilityVerb } from "../../lib/capabilitySources";
import { ApplyResultPanel, type ApplyResult } from "../common/ApplyResultPanel";
import { KitButton } from "../common/KitButton";

/**
 * The lookalike marking for THIS sheet — same detector, same words for the name, different
 * consequence, because a different compiler runs underneath it.
 *
 * The shared `LookalikeNote` ends on: "The engine matches this allowlist evasion-normalised, so the
 * rule grants the look-alike AND the plain-ASCII tool of the same shape." That is true where it
 * ships — IntentModal / Intents compile SERVER-side through `norviq/api/threat_intent.py`, whose
 * `skeleton()` folds Cyrillic е to Latin e, so `allow_skeletons` holds the ASCII prototype and both
 * names match it. Its own header comment cites that file.
 *
 * The Visual Builder does not go through it. This sheet compiles in the BROWSER (`compileGraph`) and
 * saves that rego verbatim (`rego_source: compiled.rego`), and `ui/src/lib/skeleton.ts` documents a
 * deliberate gap: it implements NFKD + mark-strip + lowercase and NOT the cross-script confusables
 * table, so it does not fold Cyrillic at all. Measured emission for the tool `sеnd_email` (U+0435):
 *
 *     allow_names     := {"sеnd_email"}      <- Cyrillic, unfolded
 *     allow_skeletons := {"sеnd_email"}      <- Cyrillic, unfolded
 *     in_allowlist { allow_names[lower(input.tool_name)] }
 *     in_allowlist { allow_skeletons[input.tool_name_normalized] }
 *
 * The engine always sends `input.tool_name_normalized = skeleton(tool_name)` with the PYTHON
 * skeleton, i.e. the folded `send_email`, which equals neither entry. So a call to the plain-ASCII
 * `send_email` matches NOTHING here and stays denied by the allowlist's `intent_default_deny`; this
 * grant covers the look-alike alone. Rendering the shared note's sentence on this row told the
 * operator their allow had widened to two names when it had not — a claim about the policy they were
 * about to save that the file they were about to save contradicts.
 *
 * So: `lookalikeOf` (the one detector) and its `masked`/`codepoints` vocabulary are reused verbatim,
 * as is LookalikeNote's visual treatment; only the consequence sentence is this sheet's own. Delete
 * this component and go back to the shared one the moment `ui/src/lib/skeleton.ts` gains the
 * confusables table — at that point both compilers agree and one sentence is true of both.
 */
function BuilderLookalikeNote({
  lookalikes,
  trailer,
  "data-testid": testId
}: {
  lookalikes: Lookalike[];
  /** The consequence sentence. Differs between "already granted" and "offered, not yet added". */
  trailer: ReactNode;
  "data-testid"?: string;
}) {
  if (lookalikes.length === 0) return null;
  return (
    <div
      data-testid={testId ?? "builder-lookalike-note"}
      style={{
        marginTop: 5,
        padding: "7px 9px",
        borderRadius: 8,
        border: "1px solid #ff3b5c30",
        background: "#ff3b5c12",
        fontSize: 12,
        lineHeight: 1.5,
        color: "var(--text-secondary)"
      }}
    >
      <span className="pill" style={{ background: "#ff3b5c15", color: "#ff3b5c", borderColor: "#ff3b5c30", marginRight: 7 }}>
        Lookalike name
      </span>
      {lookalikes.map((l) => (
        <span key={l.value} style={{ display: "block", marginTop: 5 }}>
          <code className="mono" style={{ fontSize: 12 }}>
            {l.masked}
          </code>{" "}
          carries {l.codepoints.join(", ")} where an ASCII letter appears to be.
        </span>
      ))}
      <span style={{ display: "block", marginTop: 5 }}>{trailer}</span>
    </div>
  );
}

// --- Intent Allowlist mode (Phase 2c) --------------------------------------------------------------
const REFINEMENT_KEYS: (keyof BuilderAllowlistRefinements)[] = ["readonly", "egress", "scope", "rate"];
const REFINEMENT_LABEL: Record<keyof BuilderAllowlistRefinements, string> = {
  readonly: "Read-only",
  egress: "No external egress",
  scope: "Namespace-scoped",
  rate: "Rate-limit (advisory)"
};
const EMPTY_REFINEMENTS: BuilderAllowlistRefinements = { readonly: false, egress: false, scope: false, rate: false };

// --- Per-tool parameter constraints (Phase 2d) -----------------------------------------------------
// The refinements above are class-wide booleans; these scope ONE tool by its arguments, which is the
// difference between "may call execute_sql" (what a framework tool-binding already says) and "may read
// users and orders, never payments, capped at 100 rows".
type ConstraintKind = BuilderParamConstraint["kind"];
const CONSTRAINT_KINDS: ConstraintKind[] = [
  "matches",
  "notMatches",
  "oneOf",
  "noneOf",
  "maxNumber",
  "required",
  "forbidden",
  "hostIn"
];
/** Verb shown between the parameter name and its value, so each row reads as a sentence:
 *  `query` · must match · ^\s*select\b */
const CONSTRAINT_VERB: Record<ConstraintKind, string> = {
  matches: "must match",
  notMatches: "must NOT match",
  oneOf: "must be one of",
  noneOf: "must not be any of",
  maxNumber: "at most",
  required: "must be present",
  forbidden: "must be absent",
  hostIn: "host must be one of"
};
/** Concrete, copy-pasteable examples — an operator who has never written one of these should be able to
 *  see what it is for without leaving the sheet. */
const CONSTRAINT_HINT: Record<ConstraintKind, string> = {
  matches: "e.g. (?i)^\\s*select\\b — only read statements",
  notMatches: "e.g. (?i)(card_number|ssn) — never these columns",
  oneOf: "e.g. users, orders — the only tables it may touch",
  noneOf: "e.g. payments — tables it may never touch",
  maxNumber: "e.g. 100 — cap rows returned",
  required: "the call must supply this parameter",
  forbidden: "e.g. force — refuse a forced delete",
  hostIn: "e.g. api.internal.example.com — the only egress target"
};
const CONSTRAINT_PLACEHOLDER: Record<ConstraintKind, string> = {
  matches: "regular expression",
  notMatches: "regular expression",
  oneOf: "comma-separated values",
  noneOf: "comma-separated values",
  maxNumber: "number",
  required: "",
  forbidden: "",
  hostIn: "comma-separated hosts"
};
// --- Scoping FACTS on a grant -----------------------------------------------------------------------
//
// WHY THIS EXISTS, and it is the difference between a security control and a restatement of the agent
// framework's tool binding. The constraints above address `input.tool_params[<field>]` — ONE named
// argument. That plus a list of tool names is exactly what LangChain/LangGraph already give you by
// binding a tool set: "this bot may call send_email". It is a capability list, not an intent.
//
// The facts below are what the ENGINE derived about the whole call, so they can say the things a
// per-field rule structurally cannot: it must not CARRY a credential (wherever in the payload it
// hides), it may only REACH these recipients or hosts (extracted from every parameter, so moving the
// URL to a differently-named field does not dodge it), it may only TOUCH these SQL tables.
//
// Every one is a SET operation, so none of them spends the server's 25-regex-op budget.
//
// DERIVED FROM THE FIELD REGISTRY, not restated here. `COLLECTION_FIELD_EXPR` / `NUMERIC_FIELD_EXPR`
// in builderCompile.ts are the addressable-field registry (itself mirroring schema.py). An earlier
// version of this listed five hand-picked options, which meant six addressable fields —
// sql_statements, param_values, destinations.urls, destinations.schemes, call_depth, trust_score —
// simply could not be reached from the UI, and any field added to the registry later would silently
// fail to appear. That is the same defect shape as every fail-open in this feature: two lists that
// must agree about one thing, and only one of them maintained.
//
// Labels are OVERRIDES over a generated default, so a new registry field shows up immediately with a
// readable-enough name and can be given nicer wording later — it can never be missing.
//
// THE SCALAR KIND, and why it arrived late. `param_paths.<dotted.path>` addresses ONE argument at any
// depth — the only primitive that can reach `filters.ids[0]` — and until now it had no editor anywhere
// in the product, reachable solely through the /intents handoff. The reason was recorded honestly a few
// hundred lines below: `scalarFact`'s default is `field: "param_paths."` with an empty value, which does
// not compile, and a control that starts invalid and asks the operator to guess a dotted path from
// memory is worse than no control. What changed is not the compiler — it always supported this — but
// that `GET /api/v1/tools` now supplies the tool's declared argument tree, so the control has something
// real to offer.
type FactFieldKind = "collection" | "numeric" | "scalar";
type FactFieldSpec = { field: string; kind: FactFieldKind };

const FACT_FIELDS: FactFieldSpec[] = [
  ...Object.keys(COLLECTION_FIELD_EXPR).map((field) => ({ field, kind: "collection" as const })),
  ...Object.keys(NUMERIC_FIELD_EXPR).map((field) => ({ field, kind: "numeric" as const })),
  ...Object.keys(SCALAR_FIELD_EXPR).map((field) => ({ field, kind: "scalar" as const }))
];

/** Ops offered per field kind, in the order an operator is most likely to want them. */
const FACT_OPS_BY_KIND: Record<FactFieldKind, string[]> = {
  collection: ["noneOf", "subsetOf", "anyOf", "maxCount"],
  numeric: ["max", "min"],
  scalar: ["equals", "in", "matches", "notMatches"]
};

/**
 * Ops offered for one field, narrowed by what the field can actually do.
 *
 * Keyed by kind AND field because kind alone over-offers. `matches`/`notMatches` are the only ops that
 * spend the server's 25-regex-op budget, so a field with a small closed vocabulary (pin_status, verb,
 * direction) should steer to set membership, which is free. This is advisory narrowing of the ORDER and
 * the SET on offer — never a restriction on what the compiler accepts.
 */
function factOpsFor(kind: FactFieldKind, field: string): string[] {
  const base = FACT_OPS_BY_KIND[kind];
  if (kind !== "scalar") return base;
  // Closed-vocabulary scalars: a regex over "pinned"/"drift"/"quarantined" costs budget to express what
  // `in` says for free, and invites a pattern that silently matches more than intended.
  if (CLOSED_VOCAB_SCALARS.has(field)) return ["equals", "in"];
  return base;
}

const CLOSED_VOCAB_SCALARS = new Set(["verb", "tool_kind", "direction", "mcp.pin_status", "mcp.scan_severity"]);

/**
 * The actual values each closed-vocabulary scalar can hold, transcribed from the engine.
 *
 * `factOpsFor` already narrowed these fields to `equals`/`in` on the grounds that they have a small
 * fixed vocabulary — but the VALUE stayed a free-text box, so the narrowing only removed the regex
 * footgun and left the typo one. `drifted` instead of `drift`, `critical ` with a space, `Pinned`
 * capitalised: each compiles to valid rego, passes the validator, and then matches nothing forever.
 * A rule that silently never fires is the worst outcome for a security control, because it looks
 * identical to one that fires and finds nothing.
 *
 * Sources, so a drift here is findable: pin_status from norviq/mcp/pins.py's PIN_* constants,
 * scan_severity from firewall.py's _SEVERITY_ORDER plus the "unknown" a tool with no catalog entry
 * now reports, direction from firewall.py's `"answer" if surface == "answer" else "call"`, verb from
 * evaluator.py's _PROMOTION_RANK.
 */
export const SCALAR_ENUM_VALUES: Record<string, readonly string[]> = {
  "mcp.pin_status": ["pinned", "first_seen", "drift", "quarantined", "unknown"],
  // "unknown" is a real value, not a placeholder: a tool Gate A never scanned reports it, and it is
  // deliberately OUTSIDE the severity ladder so it matches no allow list by accident.
  "mcp.scan_severity": ["none", "low", "medium", "high", "critical", "unknown"],
  direction: ["call", "answer"],
  verb: ["unknown", "read", "write", "send", "delete"],
  // Only two, and that is the engine's real answer — `_tool_kind` returns "sql" or "other", nothing
  // else. Offering a richer-looking set here (read/write/exec/network) would be inventing a vocabulary
  // the evaluator never emits, so every one of those rules would match nothing.
  tool_kind: ["sql", "other"]
};

const FACT_OP_VERB: Record<string, string> = {
  noneOf: "must not include",
  subsetOf: "must be within",
  anyOf: "must include one of",
  maxCount: "at most (count)",
  max: "at most",
  min: "at least",
  equals: "is exactly",
  in: "is one of",
  matches: "matches regex",
  notMatches: "does NOT match regex"
};

/** Friendly names where we have them; anything else falls back to a humanised field path. */
const FACT_FIELD_LABEL: Record<string, string> = {
  data_classes: "data it carries",
  sql_tables: "SQL tables",
  sql_statements: "SQL statements",
  param_values: "any parameter value",
  "destinations.emails": "recipient addresses",
  "destinations.urls": "destination URLs",
  "destinations.hosts": "destination hosts",
  "destinations.schemes": "URL schemes",
  param_bytes: "payload size (bytes)",
  call_depth: "call depth",
  trust_score: "agent trust score",
  verb: "operation verb",
  tool_kind: "tool kind",
  sql_normalized: "normalised SQL",
  direction: "plane (call / answer)",
  "mcp.server": "MCP server",
  "mcp.pin_status": "MCP pin status",
  "mcp.scan_severity": "MCP scan severity"
};
/**
 * Does this clause describe the WHOLE CALL, or one named argument?
 *
 * Both live in the facts array — `param_paths.<path>` is stored as a fact because that is how the
 * compiler emits it — so which array it is in cannot be the answer. The field can: a `param_paths.`
 * prefix means the clause addresses one declared argument; anything else the engine derived from the
 * call as a whole.
 */
function isWholeCallFact(f: BuilderGrantFact): boolean {
  const field = f.type === "not" ? (f.inner as { field?: string }).field : (f as { field?: string }).field;
  return !field?.startsWith(PARAM_PATH_PREFIX);
}

function factFieldLabel(field: string): string {
  // A `param_paths.<path>` field is not in the registry — the path is whatever the tool's own arguments
  // are — so it labels itself: `param_paths.filters.customer` reads as "argument filters.customer".
  if (field.startsWith(PARAM_PATH_PREFIX)) return `argument ${field.slice(PARAM_PATH_PREFIX.length)}`;
  return FACT_FIELD_LABEL[field] ?? field.replace(/[._]/g, " ");
}

const FACT_FIELD_HINT: Record<string, string> = {
  data_classes: "secret, pci, pii — matched wherever in the payload it sits, not just one argument",
  "destinations.emails": "every address found anywhere in the call, so it cannot be moved to another field",
  "destinations.hosts": "every URL host found anywhere in the call",
  sql_tables: "the tables the SQL actually touches",
  param_bytes: "a volume guard, e.g. 65536"
};

function blankFact(field: string, kind: FactFieldKind, op: string): BuilderGrantFact {
  if (kind === "numeric") {
    return { type: "numericFact", field: field as BuilderNumericFactField, op: op as "max" | "min", value: 0 };
  }
  if (kind === "scalar") {
    const scalarOp = op as "equals" | "in" | "matches" | "notMatches";
    // `in` carries a LIST, everything else a single value. Emitting the wrong one produces a condition
    // the validator rejects, so the shape is chosen here rather than patched up at render time.
    return scalarOp === "in"
      ? { type: "scalarFact", field, op: scalarOp, values: [] }
      : { type: "scalarFact", field, op: scalarOp, value: "" };
  }
  const collectionOp = op as "subsetOf" | "noneOf" | "anyOf" | "maxCount";
  if (collectionOp === "maxCount") {
    return { type: "collectionFact", field: field as BuilderCollectionFactField, op: collectionOp, count: 1 };
  }
  return { type: "collectionFact", field: field as BuilderCollectionFactField, op: collectionOp, values: [] };
}

/**
 * Change a fact's OPERATOR while keeping the value the operator already typed.
 *
 * Rebuilding blank on every op change threw away a list someone had just entered merely because they
 * switched "must not include" to "must be within" — two ops over the same values, where only the MEANING
 * differs. Round-tripping through the text form carries the value wherever the shapes agree and degrades
 * predictably where they do not (a value list becoming a count has nothing sensible to carry).
 */
function retypedFact(f: BuilderGrantFact, kind: FactFieldKind, nextOp: string): BuilderGrantFact {
  if (f.type === "not") return f;
  return withFactValue(blankFact(f.field, kind, nextOp), factValueText(f));
}

function factKindOfSpec(f: BuilderGrantFact): FactFieldKind {
  if (f.type === "numericFact") return "numeric";
  if (f.type === "scalarFact") return "scalar";
  return "collection";
}

function factValueText(f: BuilderGrantFact): string {
  if (f.type === "numericFact") return String(f.value ?? "");
  if (f.type === "scalarFact") return f.op === "in" ? (f.values ?? []).join(", ") : (f.value ?? "");
  if (f.type === "collectionFact") {
    return f.op === "maxCount" ? String(f.count ?? "") : (f.values ?? []).join(", ");
  }
  return "";
}

function withFactValue(f: BuilderGrantFact, text: string): BuilderGrantFact {
  if (f.type === "numericFact") return { ...f, value: Number(text) || 0 };
  if (f.type === "scalarFact") {
    return f.op === "in"
      ? { ...f, values: text.split(",").map((v) => v.trim()).filter(Boolean) }
      : { ...f, value: text };
  }
  if (f.type === "collectionFact") {
    if (f.op === "maxCount") return { ...f, count: Number(text) || 0 };
    return { ...f, values: text.split(",").map((v) => v.trim()).filter(Boolean) };
  }
  return f;
}

function blankConstraint(kind: ConstraintKind): BuilderParamConstraint {
  switch (kind) {
    case "matches":
    case "notMatches":
      return { kind, field: "", pattern: "" };
    case "oneOf":
    case "noneOf":
      return { kind, field: "", values: [] };
    case "maxNumber":
      return { kind, field: "", max: 0 };
    case "hostIn":
      return { kind, field: "", hosts: [] };
    default:
      return { kind, field: "" };
  }
}
/** Render a constraint's value side as editable text. Lists round-trip through a comma-separated string
 *  so the operator types what they read. */
function constraintValueText(c: BuilderParamConstraint): string {
  switch (c.kind) {
    case "matches":
    case "notMatches":
      return c.pattern;
    case "oneOf":
    case "noneOf":
      return c.values.join(", ");
    case "hostIn":
      return c.hosts.join(", ");
    case "maxNumber":
      return String(c.max);
    default:
      return "";
  }
}
function withConstraintValue(c: BuilderParamConstraint, text: string): BuilderParamConstraint {
  const list = () =>
    text
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s !== "");
  switch (c.kind) {
    case "matches":
    case "notMatches":
      return { ...c, pattern: text };
    case "oneOf":
    case "noneOf":
      return { ...c, values: list() };
    case "hostIn":
      return { ...c, hosts: list() };
    case "maxNumber": {
      const n = Number(text);
      return { ...c, max: Number.isFinite(n) ? n : Number.NaN };
    }
    default:
      return c;
  }
}
// Step ② mode chooser (UX redesign) — one-line explanation under each option so the difference between
// the two modes is legible without docs. Display-only; BuilderMode's wire values are unchanged.
/** One heading for the scope panel's three kinds of clause.
 *
 *  Per-argument constraints and whole-call facts were rendered as one undifferentiated list, so an
 *  operator could not tell which clauses address a NAMED argument (and therefore fail when the caller
 *  simply omits it) from those the engine derives about the call as a whole. They read identically and
 *  behave differently — the design's ARGUMENT / WHOLE CALL / NEGATED split is the fix. */
/**
 * The ARGUMENT heading's hint — ONE constant, because the panel deliberately prints ONE heading over
 * TWO clause storages (per-field `constraints` and `param_paths.<arg>` `facts`) and the two call sites
 * held byte-identical string literals that could drift apart without anything noticing.
 *
 * THIS SENTENCE IS A SECURITY CLAIM, so it says only what the compiler enforces. Both storages now
 * make the omission promise good — a constraint through `_present(f)`, a `param_paths` fact through
 * `paramPathGuards`' derivability conjunct — and `builderIntentGrants.test.ts` pins both against real
 * opa. It used to be true of the constraint rows and FALSE of the fact rows printed under the same
 * heading in the same panel: `param_paths.columns notMatches …` with `columns` omitted evaluated ALLOW.
 *
 * The second clause exists because the two storages still READ a supplied value differently, and the
 * merged heading hides that. A constraint walks the whole value, so a nested or list-shaped argument is
 * inspected. A `param_paths` clause names ONE derived key, and `{"columns": ["a"]}` derives
 * `columns[0]`, not `columns` — so the line fails rather than matching. Fail-closed either way, but an
 * operator who is not told will read a passing dry-run as "my pattern did not match" when the truth is
 * "the engine never gave this line a value to read".
 */
const ARGUMENT_SCOPE_HINT =
  "Addresses one named parameter. A call that omits it fails this line — and a param_paths. clause " +
  "fails it too when the argument arrives nested or as a list, because the engine derives a different " +
  "path for those.";

function ScopeSection({ label, hint }: { label: string; hint: string }) {
  return (
    // Addressable so a test can assert WHICH clauses sit under which heading by DOM order rather than
    // by hunting for copy in a textContent blob — the grouping is the guarantee, and it should not
    // break every time a label is reworded.
    //
    // A RULE ABOVE THE HEADING, not just a bolder word. ARGUMENT and WHOLE CALL are the two halves
    // this panel exists to distinguish, and at 10.5px in --text-secondary the heading weighed the
    // same as the clause text under it — so the section boundary was invisible and the whole editor
    // read as one undifferentiated list.
    <div
      data-testid={`builder-scope-section-${label.toLowerCase().replace(/\s+/g, "-")}`}
      style={{ marginTop: 16, marginBottom: 6, paddingTop: 10, borderTop: "1px solid var(--border)" }}
    >
      <div
        style={{
          fontSize: 11,
          fontWeight: 700,
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: "var(--text-primary)"
        }}
      >
        {label}
      </div>
      <div style={{ fontSize: 11, lineHeight: 1.5, color: "var(--text-muted)", marginTop: 3 }}>{hint}</div>
    </div>
  );
}

/**
 * One authored condition, as a discrete card.
 *
 * The rows were bare flex containers separated by an 8px margin on a single flat surface, so five
 * conditions read as one run-on paragraph of controls — the operator could not see where a clause
 * began or ended, only a field of uniform text. A clause is the unit of meaning here (each one is a
 * line that must hold), so it gets the boundary.
 *
 * Inset rather than raised: the editor already sits on --bg-elevated, so a DARKER surface reads as
 * "contained by" instead of competing with the panel it lives in.
 */
const CLAUSE_CARD: CSSProperties = {
  display: "flex",
  gap: 7,
  alignItems: "center",
  flexWrap: "wrap",
  marginTop: 7,
  padding: "8px 9px",
  borderRadius: 8,
  border: "1px solid var(--border)",
  background: "var(--bg-void)"
};

/**
 * The left-hand cell naming what a clause addresses.
 *
 * A LABEL, styled as one. It previously rendered at the same 11.5px mono as the value the operator
 * types, so "data it carries" and the secret they were entering carried equal weight and neither
 * read as the subject of the sentence.
 */
const CLAUSE_LABEL: CSSProperties = {
  width: 124,
  flex: "none",
  fontSize: 11,
  fontWeight: 600,
  color: "var(--text-secondary)"
};

const MODE_DESCRIPTION: Record<BuilderMode, string> = {
  rules: "Add blocks on top of what's already allowed. Everything not matched keeps its current outcome.",
  allowlist: "Deny everything for this scope except the tools you list."
};
// "Allowlist (deny by default)" describes the MECHANISM. It was "Intent allowlist", which collided with
// the /intents screen: after the handoff this mode IS an intent editor, so one concept carried the same
// name in two places — the confusion this repo already paid to remove once by cutting the canvas.
// The two surfaces do different jobs (that screen DISCOVERS and VALIDATES from recorded traffic; this
// one AUTHORS and EDITS), so the fix is the naming, not the architecture.
const MODE_LABEL: Record<BuilderMode, string> = {
  rules: "Tighten-only rules",
  allowlist: "Allowlist (deny by default)"
};

// Exported for reuse by this file's own ConditionChip/RuleCard below and by tests. (Previously also
// shared with a second, drag-and-drop visual builder — cut in the Phase 2f consolidation: the
// form-based Visual Builder is now the ONLY visual builder, so this vocabulary has a single consumer.)
export const DETECTORS: BuilderDetector[] = ["sql_injection", "shell_injection", "prompt_injection", "pii", "destructive_tool"];
export const DECISIONS: BuilderDecision[] = ["block", "escalate", "audit"];
// Policy tiers (Phase 3) — mirrors BuilderScope["kind"]. Order is the tier picker's own display order.
export const SCOPE_TIERS: BuilderScope["kind"][] = ["class", "namespace", "workload"];
export const SCOPE_TIER_LABEL: Record<BuilderScope["kind"], string> = {
  class: "Agent class",
  namespace: "Namespace",
  workload: "Workload"
};

/**
 * The priority POSTed for each tier.
 *
 * The builder used to send no `priority` at all, so every tier landed on the server default of 100 —
 * including the Namespace tier, which the console itself renders under a "Catch-all fallback · lowest
 * priority" heading (PolicyCatalog's PRIORITY map: workload highest, class medium, namespace lowest).
 * The Resolution hierarchy made the contradiction visible: it states "highest-priority-wins, top to
 * bottom" and then listed a priority-100 namespace policy BELOW the priority-1 namespace baseline.
 *
 * Enforcement was never wrong — `_collect_candidates` orders the tiers structurally, so a class policy
 * still beat a namespace policy at equal priority (verified on a live cluster). This aligns the number
 * with the model the UI already displays, so the table an operator reads to reason about precedence is
 * self-consistent.
 *
 * Values sit inside the 0–499 band documented for namespace-scoped authors, keep the relative order
 * workload > class > namespace, and 50 for the namespace tier matches the cookbook's own
 * observe-first namespace baseline recipe.
 */
export const SCOPE_TIER_PRIORITY: Record<BuilderScope["kind"], number> = {
  workload: 200,
  class: 100,
  namespace: 50
};
// Step ① tier cards (UX redesign) — one-line description + example shown on each selectable card, so
// the difference between the three tiers is legible without docs. Display-only; the wire semantics
// (BuilderScope["kind"]) are unchanged.
export const SCOPE_TIER_DESCRIPTION: Record<BuilderScope["kind"], string> = {
  class: "Every agent of one class, across the namespace.",
  namespace: "Every agent in one namespace, whatever its class.",
  workload: "One Deployment's agents only."
};
export const SCOPE_TIER_EXAMPLE: Record<BuilderScope["kind"], string> = {
  class: "e.g. report-gen",
  namespace: "e.g. default",
  workload: "e.g. checkout"
};
export const KEYWORD_TARGETS: BuilderKeywordTarget[] = ["tool", "params", "both"];
// The condition-type dropdown's own options — deliberately excludes "not" (Phase 2b): NOT is a toggle
// applied ON TOP of one of these types (see ConditionChip's NOT button below), not a selectable type of
// its own, since "a NOT of nothing" isn't a coherent condition.
// `as const satisfies` rather than a widening annotation: the label/hint maps below are keyed on
// `(typeof CONDITION_TYPES)[number]`, so with a widened type they demanded an entry for EVERY condition
// type — including the three that deliberately have no editor. `satisfies` still checks each entry is a
// real condition type, so a typo is caught, while the element type stays the actual list.
export const CONDITION_TYPES = [
  "detector",
  "keyword",
  "toolIn",
  "trustBelow",
  "sourceVerb",
  "paramRegex",
  // scalarFact is listed now that ConditionChip renders an editor for it. It is the ONLY way to write
  // a rules-mode (negative) condition on the engine-derived scalars — `direction`, `sql_normalized`,
  // `verb`, `tool_kind` and the three `mcp.*` facts. Allowlist mode could already require them as
  // grant facts, so "MCP is authorable" was half true: you could NARROW a grant with pin_status, but
  // you could not write "block when pin_status is drift" — which is precisely what the shipped
  // mcp_integration_guardrail template does, and therefore the one policy shape operators most want
  // to reproduce in the builder.
  "scalarFact"
] as const satisfies readonly Exclude<BuilderCondition["type"], "not">[];

// collectionFact / numericFact are DELIBERATELY NOT LISTED, and this is not an oversight.
// (scalarFact WAS in this list for the same reason and has now been given an editor — see above.)
// They are fully supported by the graph model, the compiler and the validator — they arrive via the
// /intents handoff (lib/intentToGraph.ts) and round-trip correctly. What does not exist yet is an
// EDITOR for them: ConditionChip renders field/op/value inputs for the listed types and nothing for
// these two. Listing them in the dropdown let an operator pick one and get a condition they could
// neither see nor fill in. Offering a control that cannot be used is worse than not offering it; they
// go back in the list the moment ConditionChip can render them.

/** True if `pattern` compiles as a JS RegExp — the same engine builderCompile.ts's validateCondition
 *  uses for paramRegex's `paramRegex_invalid` check, so the inline hint here agrees with the compiler. */
export function isValidRegexPattern(pattern: string): boolean {
  try {
    // Validity probe only — discarded immediately and never executed against input, so this is not the
    // ReDoS vector detect-non-literal-regexp guards against (the pattern runs only in OPA, on RE2).
    // eslint-disable-next-line no-new, security/detect-non-literal-regexp -- validity probe only, discarded
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

/** Slugify a string into a rego-safe token. */
function slugToken(text: string): string {
  return text.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}

/** The short prefix naming the tier a rule belongs to, so an audit row says which scope caught the call. */
const TIER_ID_PREFIX: Record<BuilderScope["kind"], string> = { class: "cls", namespace: "ns", workload: "wl" };

/** What a condition is ABOUT, in one token — the tool, detector, keyword or field it keys on. */
function conditionSubject(c: BuilderCondition | undefined): string {
  if (!c) return "";
  switch (c.type) {
    case "toolIn":     return slugToken((c.tools ?? [])[0] ?? "");
    case "detector":   return slugToken(c.detector ?? "");
    case "keyword":    return slugToken((c.keywords ?? [])[0] ?? "");
    case "paramRegex": return slugToken(c.field ?? "");
    case "sourceVerb": return slugToken(`${c.source ?? ""}_${c.verb ?? ""}`);
    case "trustBelow": return "low_trust";
    case "not":        { const inner = conditionSubject(c.inner); return inner ? `not_${inner}` : ""; }
    default:           return "";
  }
}

/**
 * The auto rule_id.
 *
 * This used to be a slug of the WHOLE reason sentence, which produced ids like
 * `record_deletion_is_not_permitted_for_analytics_agents` — 48 characters, truncated in every table it
 * appears in. And nothing anywhere told an operator what a good rule_id looks like, so the only options
 * were "accept a sentence" or "invent a convention". Neither is a product answer.
 *
 * The builder already knows the three things that identify a rule, so it derives them instead:
 * tier, decision, and what the first condition is about — `ns_block_ledger_snapshot`,
 * `cls_escalate_issue_refund`, `wl_block_export_bulk`. Short, scannable in an Audit Log, and the tier
 * prefix means a reader can see WHICH scope caught a call without cross-referencing the policy.
 *
 * It also makes the alphabetical tie-break legible: when several rules match one call the resolver
 * reports `sort([...])[0]`, so grouping by tier and decision is a more sensible ordering than whichever
 * sentence happened to start with an earlier letter.
 *
 * Falls back to the reason slug while no condition exists yet (the id must never be empty — that is a
 * validation error), and stays put the moment the author edits the field (`ruleIdTouched`).
 */
export function slugifyRuleId(reason: string, tier?: BuilderScope["kind"], rule?: BuilderRule): string {
  const subject = conditionSubject(rule?.conditions?.[0]?.[0]);
  if (tier && subject) {
    return [TIER_ID_PREFIX[tier], rule?.decision ?? "block", subject].filter(Boolean).join("_").slice(0, 60);
  }
  return slugToken(reason).slice(0, 60);
}

export function defaultConditionFor(type: BuilderCondition["type"]): BuilderCondition {
  switch (type) {
    case "detector":
      return { type: "detector", detector: "sql_injection" };
    case "keyword":
      return { type: "keyword", keywords: [], target: "both" };
    case "toolIn":
      return { type: "toolIn", tools: [] };
    case "trustBelow":
      return { type: "trustBelow", threshold: 0.5 };
    case "sourceVerb": {
      const source = CAPABILITY_SOURCE_ORDER[0];
      const verb = verbsForSource(source)[0];
      return { type: "sourceVerb", source, verb };
    }
    case "paramRegex":
      return { type: "paramRegex", field: "", pattern: "" };
    case "scalarFact":
      // param_paths is the reason this type exists — it addresses ONE argument at any depth, which the
      // flat `field` of paramRegex cannot reach. Default to it rather than to a fixed field.
      return { type: "scalarFact", field: "param_paths.", op: "equals", value: "" };
    case "collectionFact":
      return { type: "collectionFact", field: "data_classes", op: "anyOf", values: ["secret"] };
    case "numericFact":
      return { type: "numericFact", field: "param_bytes", op: "max", value: 65536 };
    case "not":
      // Not offered by the type dropdown (see CONDITION_TYPES) — only reachable via the NOT toggle,
      // which constructs `{type:"not", inner: <current condition>}` itself rather than calling this.
      // Kept here only so the switch stays exhaustive against the full BuilderCondition["type"] union.
      return { type: "not", inner: defaultConditionFor("detector") };
  }
}

function errorsForRule(errors: BuilderError[], ruleIndex: number): BuilderError[] {
  return errors.filter((e) => e.ruleIndex === ruleIndex);
}

// De-jargoned (Phase 2f): operator language instead of the wire type names. The wire VALUES
// (detector/toolIn/keyword/trustBelow/sourceVerb/paramRegex, used for BuilderCondition["type"] and
// hence the compiler/graph JSON) are unchanged — only what the dropdown DISPLAYS changed.
export const CONDITION_TYPE_LABEL: Record<(typeof CONDITION_TYPES)[number], string> = {
  detector: "Content detector (injection / PII / secrets / destructive tool)",
  toolIn: "Tool name is one of",
  keyword: "Keyword in tool params",
  trustBelow: "Agent trust below",
  sourceVerb: "Source + verb (capability)",
  paramRegex: "Param matches regex",
  scalarFact: "Engine fact is / is not (MCP pin, scan severity, plane, verb, SQL)"
};

/** One-line hint shown near the type dropdown for whichever type is currently selected — the label
 *  above names the operator, this explains when it fires. */
export const CONDITION_TYPE_HINT: Record<(typeof CONDITION_TYPES)[number], string> = {
  detector: "Fires when a built-in content scanner flags the call — pick which detector below.",
  toolIn: "Fires when the tool name exactly matches one of the names listed below.",
  keyword: "Fires when any listed keyword appears in the tool name and/or its parameters.",
  trustBelow: "Fires when the calling agent's live trust score is below this threshold.",
  scalarFact:
    "Fires on a fact the ENGINE derived about the call, not on its arguments — the MCP pin status or " +
    "scan severity for the tool, which plane it is on, its verb, or the normalised SQL.",
  sourceVerb: "Fires on a CAPABILITY (e.g. any 'delete' on Postgres) without listing every tool name.",
  paramRegex: "Fires when a specific parameter's value matches the regex pattern below."
};

/** Groups the type dropdown into optgroups by category — purely a display grouping, the wire value
 *  and CONDITION_TYPES's flat validation universe are untouched. */
// THE DROPDOWN RENDERS FROM HERE, not from CONDITION_TYPES. The element type is
// `(typeof CONDITION_TYPES)[number]`, which checks that every entry is a REAL condition type but says
// nothing about coverage — so a type added to CONDITION_TYPES and not to a group compiles, passes the
// label/hint exhaustiveness checks, passes a unit test that asserts CONDITION_TYPES, and is still
// absent from the only control an operator can reach. That is exactly what happened when scalarFact
// was added: two lists keyed on one concept, the same defect this codebase keeps producing.
//
// `assertGroupsCoverConditionTypes` below closes it: the groups must partition CONDITION_TYPES
// exactly, and the check runs at module load so a mismatch fails the first test that imports this
// file rather than shipping a control nobody can find.
const CONDITION_TYPE_GROUPS: { label: string; types: (typeof CONDITION_TYPES)[number][] }[] = [
  { label: "Content", types: ["detector", "keyword", "paramRegex"] },
  { label: "Tool", types: ["toolIn", "sourceVerb"] },
  { label: "Trust", types: ["trustBelow"] },
  // Facts the ENGINE derived about the call rather than anything in its arguments — the MCP pin status
  // and scan severity, which plane it is on, its verb, the normalised SQL. This group is what makes
  // "block when the MCP pin drifted" — the shipped guardrail's shape — expressible in the builder.
  { label: "Engine facts (MCP, plane, verb, SQL)", types: ["scalarFact"] }
];

/** Every condition type must appear in exactly one group, or it is unreachable from the UI. */
export function assertGroupsCoverConditionTypes(): void {
  const grouped = CONDITION_TYPE_GROUPS.flatMap((g) => g.types);
  const missing = CONDITION_TYPES.filter((t) => !grouped.includes(t));
  const duplicated = grouped.filter((t, i) => grouped.indexOf(t) !== i);
  if (missing.length || duplicated.length) {
    throw new Error(
      `CONDITION_TYPE_GROUPS must partition CONDITION_TYPES — missing: [${missing.join(", ")}]` +
        `, duplicated: [${duplicated.join(", ")}]`
    );
  }
}
assertGroupsCoverConditionTypes();

// --- condition chip -------------------------------------------------------------------------------

function ConditionChip({
  cond,
  testPrefix,
  knownTools,
  onChange,
  onRemove
}: {
  cond: BuilderCondition;
  testPrefix: string;
  /** Tool-name autocomplete/warning data (Phase 2f): the lower-cased set of names Norviq has actually
   *  observed for the target namespace, plus the capability registry's known fragments — `null` while
   *  no concrete target namespace is set yet (no data to check against, so no warning is shown). */
  knownTools: Set<string> | null;
  onChange: (next: BuilderCondition) => void;
  onRemove: () => void;
}) {
  // NOT (Phase 2b) wraps in place: `cond` is either the condition itself, or `{type:"not", inner}`.
  // Every control below configures `inner` (the wrapped condition when NOT is on, else `cond`
  // unchanged) — toggling NOT re-wraps/unwraps without touching the inner condition's own fields.
  const isNot = cond.type === "not";
  const inner: BuilderCondition = isNot ? (cond as BuilderConditionNot).inner : cond;
  const setInner = (nextInner: BuilderCondition) => {
    onChange(isNot ? { type: "not", inner: nextInner } : nextInner);
  };
  const toggleNot = () => {
    onChange(isNot ? (cond as BuilderConditionNot).inner : { type: "not", inner: cond });
  };

  return (
    <div
      data-testid={testPrefix}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 6,
        flexWrap: "wrap",
        padding: "6px 8px",
        borderRadius: 8,
        background: "var(--bg-surface)",
        border: `1px solid ${isNot ? "#ff8a3d55" : "var(--border)"}`
      }}
    >
      <button
        type="button"
        data-testid={`${testPrefix}-not-toggle`}
        aria-pressed={isNot}
        data-active={isNot}
        title={isNot ? "Negated — click to remove NOT" : "Negate this condition (NOT)"}
        style={{
          fontSize: 10.5,
          fontWeight: 800,
          letterSpacing: ".04em",
          padding: "3px 7px",
          borderRadius: 6,
          border: `1px solid ${isNot ? "#ff8a3d" : "var(--border)"}`,
          background: isNot ? "#ff8a3d1e" : "transparent",
          color: isNot ? "#ff8a3d" : "var(--text-muted)",
          cursor: "pointer"
        }}
        onClick={toggleNot}
      >
        NOT
      </button>

      <select
        data-testid={`${testPrefix}-type`}
        className="input"
        style={{ fontSize: 12, padding: "3px 6px", width: 190 }}
        value={inner.type}
        onChange={(e) => setInner(defaultConditionFor(e.target.value as BuilderCondition["type"]))}
      >
        {CONDITION_TYPE_GROUPS.map((g) => (
          <optgroup key={g.label} label={g.label}>
            {g.types.map((t) => (
              <option key={t} value={t}>
                {CONDITION_TYPE_LABEL[t]}
              </option>
            ))}
          </optgroup>
        ))}
      </select>
      <div
        data-testid={`${testPrefix}-hint`}
        style={{ width: "100%", fontSize: 10.5, color: "var(--text-muted)", order: 99 }}
      >
        {/* `inner` is always a non-"not" condition in practice (NOT wraps it, never nests inside
            itself) but is typed as the full BuilderCondition union — see BuilderConditionNot's own
            doc comment in builderGraph.ts for why that typing is deliberate. The `?? ""` covers the
            type-level "not" case defensively without a runtime-unreachable assertion. */}
        {CONDITION_TYPE_HINT[inner.type as keyof typeof CONDITION_TYPE_HINT] ?? ""}
      </div>

      {inner.type === "detector" && (
        <select
          data-testid={`${testPrefix}-detector`}
          className="input"
          style={{ fontSize: 12, padding: "3px 6px" }}
          value={inner.detector}
          onChange={(e) => setInner({ type: "detector", detector: e.target.value as BuilderDetector })}
        >
          {DETECTORS.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </select>
      )}

      {inner.type === "keyword" && (
        <>
          <input
            data-testid={`${testPrefix}-keywords`}
            className="input mono"
            placeholder="drop table,rm -rf"
            style={{ fontSize: 12, padding: "3px 6px", minWidth: 160 }}
            // split(",")/join(",") is a bijection on the raw text — no trim/dedupe here (that happens
            // at compile time in builderCompile.ts's normalizeKeywords) so the input never reformats
            // out from under an in-progress keystroke.
            value={inner.keywords.join(",")}
            onChange={(e) => setInner({ ...inner, keywords: e.target.value.split(",") })}
          />
          <select
            data-testid={`${testPrefix}-target`}
            className="input"
            style={{ fontSize: 12, padding: "3px 6px" }}
            value={inner.target}
            onChange={(e) => setInner({ ...inner, target: e.target.value as BuilderKeywordTarget })}
          >
            {KEYWORD_TARGETS.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </>
      )}

      {inner.type === "toolIn" && (
        <>
          <input
            data-testid={`${testPrefix}-tools`}
            className="input mono"
            list="builder-known-tools"
            placeholder="execute_sql,delete_record"
            style={{ fontSize: 12, padding: "3px 6px", minWidth: 180 }}
            value={inner.tools.join(",")}
            onChange={(e) => setInner({ ...inner, tools: e.target.value.split(",") })}
          />
          {knownTools != null &&
            (() => {
              const unknown = [...new Set(inner.tools.map((t) => t.trim()).filter((t) => t !== ""))].filter(
                (t) => !knownTools.has(t.toLowerCase())
              );
              return unknown.length > 0 ? (
                <div
                  data-testid="builder-unknown-tool-warning"
                  role="status"
                  style={{ width: "100%", order: 98, fontSize: 10.5, color: "var(--escalate)" }}
                >
                  {unknown.map((t) => (
                    // Worth stating more sharply here than in allowlist mode. A rules-mode block that
                    // names a tool nothing will ever send is not merely inert — it is a restriction the
                    // operator believes is in force while every call sails past the default. Allowlist
                    // mode fails the safe way round; this one does not.
                    <div key={t}>⚠ "{t}" is not in this namespace's tool registry — this rule will never fire</div>
                  ))}
                </div>
              ) : null;
            })()}
        </>
      )}

      {inner.type === "trustBelow" && (
        <input
          data-testid={`${testPrefix}-trust`}
          className="input mono"
          type="number"
          min={0}
          max={1}
          step={0.05}
          style={{ fontSize: 12, padding: "3px 6px", width: 80 }}
          value={inner.threshold}
          onChange={(e) => setInner({ ...inner, threshold: parseFloat(e.target.value) })}
        />
      )}

      {inner.type === "scalarFact" && (
        <>
          <select
            data-testid={`${testPrefix}-fact-field`}
            className="input"
            style={{ fontSize: 12, padding: "3px 6px" }}
            value={inner.field}
            onChange={(e) => {
              const field = e.target.value;
              // Re-seed the op AND the value together. `factOpsFor` narrows closed-vocabulary fields to
              // equals/in, so moving from `sql_normalized` (which offers `matches`) to `mcp.pin_status`
              // must not leave a `matches` op the field no longer offers — that compiles to a regex over
              // a three-word vocabulary and burns the server's 25-op budget to say what `in` says free.
              const ops = factOpsFor("scalar", field);
              const op = (ops.includes(inner.op) ? inner.op : ops[0]) as "equals" | "in" | "matches" | "notMatches";
              const enums = SCALAR_ENUM_VALUES[field];
              // A value carried over from another field is almost never valid for the new one, and a
              // stale value that silently matches nothing is the exact failure the enum picker exists
              // to prevent. Seed the first legal value instead of preserving nonsense.
              const seed = enums ? enums[0] : "";
              setInner(op === "in"
                ? { type: "scalarFact", field, op, values: enums ? [seed] : [] }
                : { type: "scalarFact", field, op, value: seed });
            }}
          >
            {FACT_FIELDS.filter((f) => f.kind === "scalar").map((f) => (
              <option key={f.field} value={f.field}>
                {FACT_FIELD_LABEL[f.field] ?? f.field}
              </option>
            ))}
          </select>
          <select
            data-testid={`${testPrefix}-fact-op`}
            className="input"
            style={{ fontSize: 12, padding: "3px 6px" }}
            value={inner.op}
            /* The SAME op-retarget the grant-fact editor uses, so a value survives an op change
               identically in both surfaces instead of one of them quietly discarding it. */
            onChange={(e) => setInner(retypedFact(inner, "scalar", e.target.value) as BuilderCondition)}
          >
            {factOpsFor("scalar", inner.field).map((op) => (
              <option key={op} value={op}>
                {op}
              </option>
            ))}
          </select>
          {/* A CLOSED vocabulary gets a picker, not a text box. `factOpsFor` already stopped these
              fields offering regex ops, but the VALUE stayed free text — so `drifted` for `drift`, or
              `Pinned` capitalised, compiled fine, validated fine, and then matched nothing for ever.
              A security rule that silently never fires looks identical to one that fires and finds
              nothing, which is the worse of the two to ship. */}
          {SCALAR_ENUM_VALUES[inner.field] ? (
            inner.op === "in" ? (
              <span data-testid={`${testPrefix}-fact-enum-multi`} style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {SCALAR_ENUM_VALUES[inner.field].map((v) => {
                  const picked = (inner.values ?? []).includes(v);
                  return (
                    <button
                      key={v}
                      type="button"
                      data-testid={`${testPrefix}-fact-enum-${v}`}
                      aria-pressed={picked}
                      onClick={() => {
                        const next = picked
                          ? (inner.values ?? []).filter((x) => x !== v)
                          : [...(inner.values ?? []), v];
                        setInner({ ...inner, values: next });
                      }}
                      style={{
                        fontSize: 11, padding: "2px 8px", borderRadius: 6, cursor: "pointer",
                        border: `1px solid ${picked ? "var(--accent)" : "var(--border)"}`,
                        background: picked ? "rgba(45,218,184,0.14)" : "transparent",
                        color: picked ? "var(--accent)" : "var(--text-secondary)"
                      }}
                    >
                      {v}
                    </button>
                  );
                })}
              </span>
            ) : (
              <select
                data-testid={`${testPrefix}-fact-enum`}
                className="input"
                style={{ fontSize: 12, padding: "3px 6px" }}
                value={inner.value ?? ""}
                onChange={(e) => setInner({ ...inner, value: e.target.value })}
              >
                {SCALAR_ENUM_VALUES[inner.field].map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            )
          ) : (
            <input
              data-testid={`${testPrefix}-fact-value`}
              className="input"
              style={{ fontSize: 12, padding: "3px 6px", minWidth: 160 }}
              placeholder={inner.op === "in" ? "value, value" : "value"}
              value={inner.op === "in" ? (inner.values ?? []).join(", ") : (inner.value ?? "")}
              onChange={(e) =>
                setInner(
                  inner.op === "in"
                    ? { ...inner, values: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) }
                    : { ...inner, value: e.target.value }
                )
              }
            />
          )}
        </>
      )}

      {inner.type === "sourceVerb" && (
        <>
          <select
            data-testid={`${testPrefix}-source`}
            className="input"
            style={{ fontSize: 12, padding: "3px 6px" }}
            value={inner.source}
            onChange={(e) => {
              const nextSource = e.target.value;
              const verbs = verbsForSource(nextSource);
              // Preserve the current verb if the newly-picked source still supports it (e.g. read on
              // one datastore -> read on another), else fall back to that source's first verb — never
              // leave the pair pointing at a (source,verb) combo the source doesn't expose.
              const nextVerb = verbs.includes(inner.verb) ? inner.verb : verbs[0];
              setInner({ type: "sourceVerb", source: nextSource, verb: nextVerb });
            }}
          >
            {CAPABILITY_SOURCE_ORDER.map((s) => (
              <option key={s} value={s}>
                {CAPABILITY_SOURCES[s].display}
              </option>
            ))}
          </select>
          <select
            data-testid={`${testPrefix}-verb`}
            className="input"
            style={{ fontSize: 12, padding: "3px 6px" }}
            value={inner.verb}
            onChange={(e) => setInner({ ...inner, verb: e.target.value as CapabilityVerb })}
          >
            {verbsForSource(inner.source).map((v) => (
              <option key={v} value={v}>
                {v}
              </option>
            ))}
          </select>
        </>
      )}

      {inner.type === "paramRegex" && (
        <>
          <input
            data-testid={`${testPrefix}-field`}
            className="input mono"
            placeholder="field name"
            style={{ fontSize: 12, padding: "3px 6px", minWidth: 110 }}
            value={inner.field}
            onChange={(e) => setInner({ ...inner, field: e.target.value })}
          />
          <input
            data-testid={`${testPrefix}-pattern`}
            className="input mono"
            placeholder="regex pattern"
            style={{ fontSize: 12, padding: "3px 6px", minWidth: 140 }}
            value={inner.pattern}
            onChange={(e) => setInner({ ...inner, pattern: e.target.value })}
          />
          {inner.pattern !== "" && !isValidRegexPattern(inner.pattern) && (
            <span
              data-testid={`${testPrefix}-pattern-invalid`}
              style={{ fontSize: 10.5, color: "var(--danger,#e5484d)" }}
            >
              invalid regex
            </span>
          )}
        </>
      )}

      <button
        type="button"
        data-testid={`${testPrefix}-remove`}
        className="icon-btn"
        style={{ width: 20, height: 20, marginLeft: "auto" }}
        title="Remove condition"
        onClick={onRemove}
      >
        <X size={12} />
      </button>
    </div>
  );
}

// --- rule card -------------------------------------------------------------------------------------

function RuleCard({
  rule,
  index,
  tier,
  errors,
  ruleIdTouched,
  knownTools,
  onChange,
  onRemove,
  onRuleIdTouched
}: {
  rule: BuilderRule;
  index: number;
  tier: BuilderScope["kind"];
  errors: BuilderError[];
  ruleIdTouched: boolean;
  knownTools: Set<string> | null;
  onChange: (next: BuilderRule) => void;
  onRemove: () => void;
  onRuleIdTouched: () => void;
}) {
  const setRow = (ri: number, row: BuilderCondition[]) => {
    const conditions = rule.conditions.map((r, i) => (i === ri ? row : r));
    // Re-derive the id: its subject comes from the first condition, so picking or changing one must update
    // it. Without this the id kept the reason-slug fallback chosen before any condition existed.
    const next = { ...rule, conditions };
    onChange(ruleIdTouched ? next : { ...next, ruleId: slugifyRuleId(rule.reason, tier, next) });
  };

  return (
    <div
      data-testid={`builder-rule-${index}`}
      // Internal id from the per-sheet rule-id generator (see BuilderSheet's `ruleSeq` ref) —
      // exposed purely for testability (uniqueness / no-collision assertions), not consumed elsewhere.
      data-rule-internal-id={rule.id}
      style={{
        border: "1px solid var(--border)",
        borderRadius: 10,
        padding: 12,
        marginBottom: 12,
        background: "var(--bg-elevated)"
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-end", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
        <label style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <span className="vpb-field-label">Decision</span>
          <select
            data-testid={`builder-rule-decision-${index}`}
            className="input"
            style={{ fontSize: 12.5, padding: "4px 8px", width: 110 }}
            value={rule.decision}
            onChange={(e) => onChange({ ...rule, decision: e.target.value as BuilderDecision })}
          >
            {DECISIONS.map((d) => (
              <option key={d} value={d}>
                {d}
              </option>
            ))}
          </select>
        </label>
        {/* The rule id had NO label — only a placeholder, which vanishes the moment the field auto-fills
            from the reason. An operator saw a mono string appear with no clue what it was, that it could
            be changed, or where it surfaces. Not cosmetic: this id is stamped on every decision and audit
            row for the rule, and dashboards group by it. */}
        <label style={{ display: "flex", flexDirection: "column", gap: 4, flex: "1 1 200px" }}>
          <span className="vpb-field-label">
            Rule ID{" "}
            <span style={{ fontWeight: 400, textTransform: "none", letterSpacing: 0, color: "var(--text-muted)" }}>
              — {ruleIdTouched ? "custom" : "auto"}
            </span>
          </span>
          <input
            data-testid={`builder-rule-id-${index}`}
            className="input mono"
            placeholder="e.g. ns_ledger_snapshot_blocked"
            style={{ fontSize: 12.5, padding: "4px 8px", width: "100%" }}
            value={rule.ruleId}
            onChange={(e) => {
              onRuleIdTouched();
              onChange({ ...rule, ruleId: e.target.value });
            }}
          />
        </label>
          <button
            type="button"
          data-testid={`builder-remove-rule-${index}`}
          className="icon-btn"
          title="Remove rule"
          onClick={onRemove}
        >
          <Trash2 size={14} />
        </button>
      </div>
      <input
        data-testid={`builder-rule-reason-${index}`}
        className="input"
        placeholder="Why this rule exists — shown to the operator when it fires"
        style={{ fontSize: 12.5, padding: "4px 8px", width: "100%", marginBottom: 10 }}
        value={rule.reason}
        onChange={(e) => {
          const reason = e.target.value;
          const ruleId = ruleIdTouched ? rule.ruleId : slugifyRuleId(reason, tier, { ...rule, reason });
          onChange({ ...rule, reason, ruleId });
        }}
      />
        <div style={{ fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.5, marginBottom: 10 }}>
          The <strong>reason</strong> is the sentence an operator reads when this rule fires. The{" "}
          <strong>rule ID</strong> is the short identifier stamped on the decision and on every Audit Log row
          for it — dashboards and exports group by it, so keep it stable once the rule is live. You do not have
          to invent one: it is built from this rule\u2019s tier, decision and first condition (e.g.{" "}
          <span className="mono">ns_block_ledger_snapshot</span>). Type your own if you prefer a house
          convention — it then stops tracking, so you can reword the reason freely.
        </div>

      <div className="section-label" style={{ marginBottom: 6 }}>
        Conditions (OR of AND)
      </div>
      {rule.conditions.map((row, ri) => (
        <div key={ri}>
          {ri > 0 && (
            <div style={{ textAlign: "center", fontSize: 10.5, color: "var(--text-muted)", margin: "4px 0" }}>OR</div>
          )}
          <div
            data-testid={`builder-row-${index}-${ri}`}
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 6,
              padding: 8,
              borderRadius: 8,
              border: "1px dashed var(--border)"
            }}
          >
            {row.map((cond, ci) => (
              <ConditionChip
                key={ci}
                testPrefix={`builder-cond-${index}-${ri}-${ci}`}
                cond={cond}
                knownTools={knownTools}
                onChange={(next) => {
                  const nextRow = row.map((c, i) => (i === ci ? next : c));
                  setRow(ri, nextRow);
                }}
                onRemove={() => setRow(ri, row.filter((_, i) => i !== ci))}
              />
            ))}
            <div style={{ display: "flex", gap: 8 }}>
              <button
                type="button"
                data-testid={`builder-add-condition-${index}-${ri}`}
                className="sb-link"
                style={{ fontSize: 11.5, color: "#2DDAB8", padding: "3px 6px" }}
                onClick={() => setRow(ri, [...row, defaultConditionFor("detector")])}
              >
                <Plus size={12} /> AND condition
              </button>
              {rule.conditions.length > 1 && (
                <button
                  type="button"
                  data-testid={`builder-remove-row-${index}-${ri}`}
                  className="sb-link"
                  style={{ fontSize: 11.5, color: "var(--text-muted)", padding: "3px 6px" }}
                  onClick={() => onChange({ ...rule, conditions: rule.conditions.filter((_, i) => i !== ri) })}
                >
                  Remove row
                </button>
              )}
            </div>
          </div>
        </div>
      ))}
      <button
        type="button"
        data-testid={`builder-add-row-${index}`}
        className="sb-link"
        style={{ fontSize: 11.5, color: "#2DDAB8", padding: "3px 6px", marginTop: 6 }}
        onClick={() => onChange({ ...rule, conditions: [...rule.conditions, []] })}
      >
        <Plus size={12} /> OR row
      </button>

      {errors.length > 0 && (
        <div style={{ marginTop: 8, fontSize: 11.5, color: "var(--danger,#e5484d)" }}>
          {errors.map((e, i) => (
            <div key={i}>{e.message}</div>
          ))}
        </div>
      )}
    </div>
  );
}

// --- namespace + tool-name suggestion helpers (Phase 2f) ---------------------------------------------

/** "" and "all" are the two spellings of "no single namespace chosen" this app uses (the global
 *  selector's aggregate view, and BuilderSheet's own empty init) — everything else is a real, postable
 *  target. Centralized here so the Save-gate, the summary line, and the initial state all agree. */
function isConcreteNamespace(ns: string): boolean {
  const t = ns.trim();
  return t !== "" && t.toLowerCase() !== "all";
}

/** The plain-English sentence that replaces the old cryptic "Will create in namespace: X ·
 *  agent-class: Y" key summary (UX redesign) — states MEANING per tier rather than wire fields. Callers
 *  still render the loader key alongside this (in muted small text) so the honesty guarantee — the
 *  operator can always see the exact key that will be written — is preserved. */
export function scopeSentence(params: {
  scopeReady: boolean;
  namespaceReady: boolean;
  tier: BuilderScope["kind"];
  agentClass: string;
  workloadName: string;
  targetNamespace: string;
}): string {
  const { scopeReady, namespaceReady, tier, agentClass, workloadName, targetNamespace } = params;
  if (!scopeReady || !namespaceReady) return "Pick who this policy is for to continue.";
  const ns = targetNamespace.trim();
  if (tier === "class") return `Applies to every \`${agentClass.trim()}\` agent in namespace \`${ns}\`.`;
  if (tier === "namespace") return `Applies to every agent in namespace \`${ns}\`, whatever its class.`;
  return `Applies to agents of Deployment \`${workloadName.trim()}\` in namespace \`${ns}\`.`;
}

/** Every tool-name fragment the capability registry mirror knows about (across all sources/verbs),
 *  flattened and deduped — one of the "known" suggestion sources for the toolIn / allowlist tool-name
 *  fields (see capabilitySources.ts's own header comment for what this mirrors). Computed once at
 *  module load since CAPABILITY_SOURCES is a static table, not per-render. */
const ALL_CAPABILITY_FRAGMENTS: string[] = [
  ...new Set(
    CAPABILITY_SOURCE_ORDER.flatMap((source) => Object.values(CAPABILITY_SOURCES[source].verbs).flatMap((frags) => frags ?? []))
  )
];

// --- top-level sheet ---------------------------------------------------------------------------------

export function BuilderSheet({
  namespace,
  onClose,
  onSaved,
  seedGraph
}: {
  /** RAW global-selector value (Phase 2f: the caller no longer silently resolves "all" — pass it
   *  straight through). Only ever used here to seed `targetNamespace`'s initial value: when concrete,
   *  it pre-fills the target-namespace field; when "all"/"", that field starts empty and Save is gated
   *  until the operator picks a concrete namespace explicitly (see `namespaceReady`). */
  namespace: string;
  onClose: () => void;
  /** Fired after a successful Save & enforce (e.g. so the caller can refresh the policy list). */
  onSaved?: (result: { namespace: string; agentClass: string; version?: number }) => void;
  /** Pre-populate the sheet from an existing graph — used by the /intents handoff, which proposes a
   *  policy from recorded traffic and then hands it here to be edited (see lib/intentToGraph.ts).
   *  Seeds INITIAL state only: once the sheet is open the operator owns it, so a later prop change
   *  must not silently rewrite what they are editing. */
  seedGraph?: BuilderGraph | null;
}) {
  const [agentClass, setAgentClass] = useState(() =>
    seedGraph?.scope.kind === "class" ? seedGraph.scope.agentClass : ""
  );
  const [rules, setRules] = useState<BuilderRule[]>(() => seedGraph?.rules ?? []);
  const [defaults, setDefaults] = useState<BuilderDefaults>(
    () => seedGraph?.defaults ?? { decision: "allow", reason: "No builder rule matched" }
  );
  const [ruleIdTouched, setRuleIdTouched] = useState<Record<string, boolean>>({});
  const [knownClasses, setKnownClasses] = useState<string[]>([]);

  // Policy tier (Phase 3): "class" (unchanged MVP scope) | "namespace" | "workload" (deployment only —
  // see builderGraph.ts's BuilderScopeWorkload doc comment for why no other workload kind is offered).
  // The namespace tier deliberately has NO separate identifier state of its own: its identifier IS
  // `targetNamespace` below (the same field every tier already POSTs as the `namespace` body field) —
  // reusing it, rather than tracking a second value that could drift out of sync, is what guarantees
  // the namespace-tier rego guard and the loader key (`namespace:<ns>`) always agree on which
  // namespace. The workload tier gets its own `workloadName` identifier (a deployment name is not a
  // namespace) alongside the still-required `targetNamespace` (which namespace that deployment lives
  // in — needed both for the loader key `deployment:<name>` and the compiled guard, see
  // builderCompile.ts's `scopeGuardLine`).
  const [tier, setTier] = useState<BuilderScope["kind"]>("class");
  const [workloadName, setWorkloadName] = useState("");

  // Namespace honesty (Phase 2f): `namespace` is now the RAW global-selector value — the caller no
  // longer silently resolves "all" to "default". `targetNamespace` is the operator's own choice, seeded
  // from the prop only when it's already concrete; when the selector is "all"/"" this starts empty and
  // Save stays gated (see `namespaceReady`/`canSave` below) until the operator picks one explicitly.
  const [targetNamespace, setTargetNamespace] = useState(() => (isConcreteNamespace(namespace) ? namespace : ""));
  const [knownNamespaces, setKnownNamespaces] = useState<string[]>([]);
  const namespaceReady = isConcreteNamespace(targetNamespace);

  useEffect(() => {
    let live = true;
    fetchClusterInfo()
      .then((info) => {
        if (live) setKnownNamespaces(info.namespaces ?? []);
      })
      .catch(() => {
        // Best-effort prefill only — free-text entry still works with no suggestions.
      });
    return () => {
      live = false;
    };
  }, []);

  // Tool-name autocomplete + unknown-tool warning: `registry` is `null` until a concrete target
  // namespace is chosen AND the fetch resolves — while `null`, ConditionChip/allowlist suppress the
  // unknown-tool warning entirely (there's nothing trustworthy to compare against yet), so the warning
  // never fires against the WRONG namespace's traffic or before one is even picked.
  //
  // GET /api/v1/tools returns two tiers, each row tagged with its own `source`, and they must stay
  // apart: `mcp_declared` was read from an approved definition and may carry a JSON Schema; `observed`
  // only proves the name appeared in real traffic. Flattening them back into one set is the bug this
  // endpoint was built to retire.
  const [registry, setRegistry] = useState<ToolRegistryEntry[] | null>(null);

  useEffect(() => {
    let live = true;
    const ns = targetNamespace.trim();
    if (!isConcreteNamespace(ns)) {
      setRegistry(null);
      return;
    }
    setRegistry(null); // reset while (re)loading — avoid warning against a just-abandoned namespace's data
    fetchTools(ns)
      .then((entries) => {
        if (live) setRegistry(entries);
      })
      // A FAILED fetch must not read as "this namespace has no tools". The previous code caught each
      // request into `[]`, which made an outage indistinguishable from an empty estate and pointed the
      // unknown-tool warning at every name the operator typed. `null` is the honest state: we do not
      // know yet, so we claim nothing.
      .catch(() => {
        if (live) setRegistry(null);
      });
    return () => {
      live = false;
    };
  }, [targetNamespace]);

  // `null` propagates (suppress the warning) until we have something trustworthy to compare against.
  //
  // AN EMPTY REGISTRY COUNTS AS `null`. It means no MCP server has been pinned AND no real traffic was
  // recorded in the window — i.e. we know nothing, not that nothing exists. That is the common case, not
  // an edge one: helm ships `webhook.injection.mcp.enabled: false`, so most estates have no pins at all.
  // Warning on every name an operator types in that state is noise, and noise is how a warning gets
  // trained out of existence before the one time it matters.
  //
  // CAPABILITY FRAGMENTS ARE DELIBERATELY ABSENT. They used to be unioned in here, and they are
  // SUBSTRINGS ("post", "http", "delete", "send") meant for `contains()` matching inside the sourceVerb
  // condition — not tool names. Because the same set fed the datalist, the UI offered names that could
  // not exist and then suppressed its own warning for precisely those names: typing `delete` was silent
  // while `delete_record` warned. An existence oracle may only contain things that exist.
  const knownToolNames = useMemo<Set<string> | null>(() => {
    if (registry === null || registry.length === 0) return null;
    return new Set(registry.flatMap((t) => [t.name.toLowerCase(), t.name_skeleton.toLowerCase()]));
  }, [registry]);

  /** Names backed by a real, approved definition — a superset claim over `knownToolNames`, used to tell
   *  "declared but never called" apart from "seen once in traffic". */
  const declaredToolNames = useMemo<Set<string>>(
    () => new Set(registry?.filter((t) => t.source === "mcp_declared").map((t) => t.name.toLowerCase()) ?? []),
    [registry]
  );

  /** The tools whose arguments we can actually describe, by lower-cased name. Feeds the scope picker. */
  const schemaByTool = useMemo<Map<string, Record<string, unknown>>>(() => {
    const out = new Map<string, Record<string, unknown>>();
    for (const t of registry ?? []) {
      if (t.schema_available && t.input_schema) out.set(t.name.toLowerCase(), t.input_schema);
    }
    return out;
  }, [registry]);

  /** Each tool's declared argument paths, walked once per registry load rather than per render. */
  const pathsByTool = useMemo<Map<string, SchemaPath[]>>(() => {
    const out = new Map<string, SchemaPath[]>();
    for (const [tool, schema] of schemaByTool) out.set(tool, schemaPaths(schema));
    return out;
  }, [schemaByTool]);

  /**
   * The declared `enum` for a fact's argument, when there is one and the operator is comparing by
   * membership. A typo'd literal in a value list is a silently dead restriction — fail-closed and noisy
   * inside an allowlist grant, fail-open and silent in rules mode — so where the schema states the legal
   * values, offering them beats asking someone to retype one.
   *
   * `equals` only, deliberately: `in` takes a LIST, and a single-select cannot express one. Free text
   * stays the way to write a list, and the enum remains a suggestion rather than a restriction either
   * way — a schema can be stale, and the compiler has never required a value to be declared.
   */
  const factEnumOptions = (f: BuilderGrantFact, tool: string): string[] | null => {
    if (f.type !== "scalarFact" || f.op !== "equals" || !f.field.startsWith(PARAM_PATH_PREFIX)) return null;
    const path = f.field.slice(PARAM_PATH_PREFIX.length);
    return (pathsByTool.get(tool.toLowerCase()) ?? []).find((p) => p.path === path)?.enumValues ?? null;
  };

  /** The declared `enum` for a per-field CONSTRAINT's argument, when comparing by membership. */
  const constraintEnumListId = (c: BuilderParamConstraint, tool: string): string[] | null => {
    if (c.kind !== "oneOf" && c.kind !== "noneOf") return null;
    if (!c.field) return null;
    return (pathsByTool.get(tool.toLowerCase()) ?? []).find((p) => p.path === c.field)?.enumValues ?? null;
  };

  /** Top-level argument names a tool declares — datalist fodder for the constraint field box. Only the
   *  addressable, single-segment ones: a constraint addresses ONE flat `tool_params[field]`, so a nested
   *  path suggested here would point at an argument that does not exist under that name. */
  const flatArgNames = (tool: string): string[] =>
    (pathsByTool.get(tool.toLowerCase()) ?? [])
      .filter((p) => p.addressable && !p.path.includes("."))
      .map((p) => p.path);

  /**
   * The condition picker's two-and-a-bit groups, built from what the registry actually says.
   *
   * Group order is the argument: this tool's OWN arguments first, because they are the most specific
   * thing anyone can say about a call and until recently they could not be said at all. Whole-call
   * facts second — broader, and they hold even when the payload moves between fields. The undeclared
   * escape hatch last, because reaching for it means the schema did not describe what you want.
   */
  const pickerGroupsFor = (tool: string): PickerGroup[] => {
    const key = tool.toLowerCase();
    const paths = pathsByTool.get(key) ?? [];
    // A grant fact may be a `not` wrapper, which carries the field on `.inner` — unwrap before reading
    // it, or a negated clause silently stops counting as "already used".
    const factField = (f: BuilderGrantFact): string =>
      f.type === "not" ? ((f.inner as { field?: string }).field ?? "") : ((f as { field?: string }).field ?? "");
    const usedFields = new Set((allowlistGrantFacts[tool] ?? []).map(factField).filter(Boolean));
    const usedArgPaths = new Set(
      [...usedFields].filter((f) => f.startsWith(PARAM_PATH_PREFIX)).map((f) => f.slice(PARAM_PATH_PREFIX.length))
    );

    const argOptions: PickerOption[] = paths.map((pth) => ({
      id: pth.path,
      label: pth.path,
      // The name the REST of the product uses for this same argument. Picking it calls
      // `addFact(`${PARAM_PATH_PREFIX}${path}`)`, so the chip on the row and the line in the compiled
      // rego both read `param_paths.to` while this list says `to` — and the operator searches with the
      // string they were shown.
      aliases: [`${PARAM_PATH_PREFIX}${pth.path}`],
      meta: [pth.type, pth.path.includes(".") ? "nested" : null].filter(Boolean).join(" · "),
      required: pth.required,
      disabled: !pth.addressable,
      // Never rendered without one — a greyed row with no reason is the thing this replaced.
      reason: pth.addressable ? undefined : (pth.note ?? "This argument cannot be addressed by param_paths."),
      used: usedArgPaths.has(pth.path)
    }));

    const groups: PickerGroup[] = [
      {
        key: "args",
        label: `${tool} arguments`,
        tone: "accent",
        sub: schemaByTool.has(key)
          ? paths.length === 0
            ? "Its declared schema lists no properties, so there is nothing to address by path."
            : "From the approved MCP definition. Unusable ones are shown with the reason, never hidden."
          : `No declared schema for ${tool} — nothing here to list. Use a whole-call fact below, or scope a path you know.`,
        options: argOptions
      },
      {
        key: "facts",
        label: "What the call carries or reaches",
        tone: "audit",
        sub: "Derived by the engine from the whole call, so they hold wherever the value sits in the payload.",
        options: FACT_FIELDS.map((f) => ({
          id: f.field,
          label: factFieldLabel(f.field),
          hint: FACT_FIELD_HINT[f.field],
          used: usedFields.has(f.field)
        }))
      },
      {
        key: "undeclared",
        label: "When the argument was never declared",
        tone: "audit",
        sub: "Names a path yourself. The row you get lets you change the operator.",
        options: CONSTRAINT_KINDS.map((k) => ({
          id: k,
          label: `any parameter — ${CONSTRAINT_VERB[k]}`,
          hint: CONSTRAINT_HINT[k]
        }))
      }
    ];
    return groups;
  };

  // Datalist suggestions: real registry names when we have any. Capability fragments remain ONLY as a
  // last-resort vocabulary when the registry is empty — which is the default in most deployments, since
  // `mcp_tool_pins` is populated only when MCP injection is switched on. They are a hint of the shape of
  // a name, never a claim that one exists, which is why they no longer reach `knownToolNames`.
  const toolSuggestions = useMemo(() => {
    const names = (registry ?? []).map((t) => t.name);
    return names.length > 0 ? [...new Set(names)].sort() : [...new Set(ALL_CAPABILITY_FRAGMENTS)].sort();
  }, [registry]);

  /**
   * The suggestion list, split by whether the name can be trusted to look like itself.
   *
   * A `<datalist>` option is a bare string: it cannot carry a badge, a colour, or a note. So offering
   * `send_email` and `sеnd_email` (U+0435) side by side offers two entries that are pixel-identical in
   * this font, with no way to tell which is which and no way to mark either. The impostor is then one
   * arrow-key away from becoming a GRANT on a deny-by-default policy.
   *
   * Withholding it from the datalist is not hiding it — hiding an observed name would be its own lie.
   * The flagged names are surfaced right below the field in a list that CAN say what they are, using
   * the same `lookalikeOf` detector and the same masked form the rest of the console uses.
   */
  const asciiToolSuggestions = useMemo(() => toolSuggestions.filter((t) => lookalikeOf(t) === null), [toolSuggestions]);
  // Read off the REGISTRY, not off `toolSuggestions`. The two are the same set whenever the registry
  // has anything, but `toolSuggestions` falls back to `ALL_CAPABILITY_FRAGMENTS` — a hardcoded
  // vocabulary that is "a hint of the shape of a name, never a claim that one exists". The list below
  // is captioned "Observed in this namespace", and that sentence has to be true STRUCTURALLY, not by
  // the accident that today's fragment list happens to be pure ASCII.
  const lookalikeToolSuggestions = useMemo(
    () => (registry ?? []).map((t) => lookalikeOf(t.name)).filter((l): l is Lookalike => l !== null),
    [registry]
  );

  // Intent Allowlist mode (Phase 2c) — kept as SEPARATE state from rules/defaults above (rather than
  // overwriting them on a mode switch) so toggling the mode preserves each mode's own in-progress state:
  // switching to allowlist and back to rules leaves the rule rail exactly as it was, and vice versa.
  // Seeded from `seedGraph` too, so an intent handed over from /intents arrives in ALLOWLIST mode
  // with its tools and per-tool constraints intact. An intent is default-deny; opening it in rules
  // mode (default-allow) would invert its meaning on arrival.
  const [mode, setMode] = useState<BuilderMode>(() => seedGraph?.mode ?? "rules");
  const [allowlistTools, setAllowlistTools] = useState<string[]>(() => seedGraph?.allowlist?.tools ?? []);
  const [allowlistRefinements, setAllowlistRefinements] = useState<BuilderAllowlistRefinements>(
    () => seedGraph?.allowlist?.refinements ?? EMPTY_REFINEMENTS
  );
  const [allowlistToolInput, setAllowlistToolInput] = useState("");
  // Per-tool constraints (Phase 2d), keyed by the tool name exactly as it appears in `allowlistTools`.
  // A Record rather than an array so the editor never has to reconcile two orderings, and so removing a
  // tool can drop its constraints in the same action — an orphan grant is a hard compile error
  // (`grant_not_allowlisted`), and leaving one behind would break the policy from an unrelated edit.
  // Grant FACTS, kept beside the constraints and keyed the same way. The sheet has no editor for them
  // yet (they arrive only via the /intents handoff), but they must survive a round trip — dropping
  // them silently produces a policy strictly more permissive than the one the operator dry-ran, and
  // `dropped` stays empty because intentToGraph converted them successfully.
  const [allowlistGrantFacts, setAllowlistGrantFacts] = useState<Record<string, BuilderGrantFact[]>>(() =>
    Object.fromEntries(
      (seedGraph?.allowlist?.grants ?? [])
        .filter((g) => (g.facts ?? []).length > 0)
        .map((g) => [g.tool, g.facts as BuilderGrantFact[]])
    )
  );
  const [allowlistGrants, setAllowlistGrants] = useState<Record<string, BuilderParamConstraint[]>>(() =>
    // BOTH halves of a grant. Seeding only `constraints` silently dropped every scoping FACT, so an
    // intent handed over from /intents lost exactly the narrowing that closed the credential-egress
    // gap — and lost it invisibly, because intentToGraph reports nothing in `dropped` (it converted
    // them fine), so the handoff refusal could not fire. The operator would then save a policy
    // strictly more permissive than the one they dry-ran.
    Object.fromEntries(
      (seedGraph?.allowlist?.grants ?? []).map((g) => [g.tool, g.constraints])
    )
  );
  const [openGrantTool, setOpenGrantTool] = useState<string | null>(null);
  const addAllowlistTool = () => {
    const t = allowlistToolInput.trim();
    if (t === "") return;
    setAllowlistTools((ts) => (ts.includes(t) ? ts : [...ts, t]));
    setAllowlistToolInput("");
  };
  const removeAllowlistTool = (t: string) => {
    setAllowlistTools((ts) => ts.filter((x) => x !== t));
    // BOTH scope stores, for the same reason the chip counts both. Dropping only `allowlistGrants` left
    // the tool's FACTS behind, so removing a tool and re-adding it silently resurrected scoping the
    // operator had discarded. Harmless only by accident today — the graph memo iterates `allowlistTools`
    // — which makes it exactly the kind of latent divergence that becomes a live bug the moment some
    // other consumer reads the record directly.
    setAllowlistGrants(({ [t]: _droppedConstraints, ...rest }) => rest);
    setAllowlistGrantFacts(({ [t]: _droppedFacts, ...rest }) => rest);
    setOpenGrantTool((cur) => (cur === t ? null : cur));
  };
  const setToolConstraints = (tool: string, next: BuilderParamConstraint[]) =>
    setAllowlistGrants((g) => {
      if (next.length === 0) {
        const { [tool]: _empty, ...rest } = g;
        return rest; // an empty grant is a compile error — represent "no constraints" as absence
      }
      return { ...g, [tool]: next };
    });
  const addConstraint = (tool: string, kind: BuilderParamConstraint["kind"]) =>
    setToolConstraints(tool, [...(allowlistGrants[tool] ?? []), blankConstraint(kind)]);
  const updateConstraint = (tool: string, idx: number, next: BuilderParamConstraint) =>
    setToolConstraints(tool, (allowlistGrants[tool] ?? []).map((c, i) => (i === idx ? next : c)));
  const removeConstraint = (tool: string, idx: number) =>
    setToolConstraints(tool, (allowlistGrants[tool] ?? []).filter((_, i) => i !== idx));
  const setToolFacts = (tool: string, facts: BuilderGrantFact[]) =>
    setAllowlistGrantFacts((prev) => {
      if (facts.length === 0) {
        const { [tool]: _empty, ...rest } = prev;
        return rest; // absence, not an empty array — same doctrine as `setToolConstraints` above
      }
      return { ...prev, [tool]: facts };
    });
  const addFact = (tool: string, field: string, kind: FactFieldKind) =>
    setToolFacts(tool, [...(allowlistGrantFacts[tool] ?? []), blankFact(field, kind, factOpsFor(kind, field)[0])]);
  const updateFact = (tool: string, idx: number, next: BuilderGrantFact) =>
    setToolFacts(tool, (allowlistGrantFacts[tool] ?? []).map((f, i) => (i === idx ? next : f)));
  const removeFact = (tool: string, idx: number) =>
    setToolFacts(tool, (allowlistGrantFacts[tool] ?? []).filter((_, i) => i !== idx));

  const [dryRunLoading, setDryRunLoading] = useState(false);
  const [dryRunResult, setDryRunResult] = useState<DryRunReplay | null>(null);
  const [dryRunError, setDryRunError] = useState<string | null>(null);
  // The exact rego a dry-run was computed against — a recompile (any graph edit) makes this stale, the
  // same staleness doctrine PolicyCatalog's raw editor uses for its own dry-run panel.
  const [dryRunRego, setDryRunRego] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null);

  // Per-INSTANCE rule-id sequence — a useRef (not module-level state) so two mounted BuilderSheets
  // (or a remount of the same one) each get their own counter starting fresh at 0, and never share or
  // collide on a global counter (round B fix: this used to be `let ruleSeq = 0` at module scope).
  const ruleSeqRef = useRef(0);
  const nextRuleId = (): string => {
    ruleSeqRef.current += 1;
    return `bld_rule_${Date.now().toString(36)}_${ruleSeqRef.current}`;
  };
  const newRule = (): BuilderRule => ({ id: nextRuleId(), decision: "block", ruleId: "", reason: "", conditions: [[]] });

  // Editor expand/collapse — the Compiled Rego preview defaults to a compact 260px but can be expanded
  // to see a tall policy in full; toggled by the button next to the section label below.
  const [editorExpanded, setEditorExpanded] = useState(false);

  // Unsaved-changes guard: `saved` flips true immediately after a successful Save & enforce and flips
  // back to false the moment the author edits the graph again (see the effect below, keyed on `graph`
  // identity) — so closing right after a save never prompts, but any edit afterward re-arms the guard.
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    let live = true;
    fetchAllAgents()
      .then((agents) => {
        if (!live) return;
        const classes = [...new Set(agents.map((a) => a.agent_class).filter((c): c is string => !!c))].sort();
        setKnownClasses(classes);
      })
      .catch(() => {
        // Best-effort prefill only — free-text entry still works with no suggestions.
      });
    return () => {
      live = false;
    };
  }, []);

  // Scope (Phase 3): tier-dispatched. The namespace tier reuses `targetNamespace` directly as its own
  // identifier (see the `tier`/`workloadName` state doc comment above for why) rather than tracking a
  // second value that could drift out of sync with the loader key.
  const scope: BuilderScope = useMemo(() => {
    if (tier === "namespace") return { kind: "namespace", namespace: targetNamespace.trim() };
    if (tier === "workload") return { kind: "workload", workloadName: workloadName.trim() };
    return { kind: "class", agentClass: agentClass.trim() };
  }, [tier, targetNamespace, agentClass, workloadName]);

  const graph: BuilderGraph = useMemo(
    () => ({
      schemaVersion: 1,
      scope,
      mode,
      rules,
      defaults,
      ...(mode === "allowlist"
        ? {
            allowlist: {
              tools: allowlistTools,
              refinements: allowlistRefinements,
              // Emitted only when at least one tool is actually constrained, so a policy with no
              // constraints carries no `grants` key at all and compiles byte-identically to a pre-2d one.
              // Ordered by `allowlistTools` rather than by Record insertion so the compiled output is
              // stable across edits that only reorder state.
              ...(() => {
                const grants = allowlistTools
                  .filter((t) => (allowlistGrants[t] ?? []).length > 0 || (allowlistGrantFacts[t] ?? []).length > 0)
                  .map((t) => ({
                    tool: t,
                    constraints: allowlistGrants[t] ?? [],
                    ...((allowlistGrantFacts[t] ?? []).length ? { facts: allowlistGrantFacts[t] } : {})
                  }));
                return grants.length ? { grants } : {};
              })()
            }
          }
        : {})
    }),
    [scope, rules, defaults, mode, allowlistTools, allowlistRefinements, allowlistGrants, allowlistGrantFacts]
  );
  // `targetNamespace` is passed as the compiler's 2nd argument for every tier (class/namespace tiers
  // ignore it; the workload tier needs it for its `input.agent.namespace` guard — see
  // builderCompile.ts's `compileGraph` doc comment).
  const compiled = useMemo(() => compileGraph(graph, targetNamespace.trim()), [graph, targetNamespace]);

  // Any edit to the graph after a save re-arms the unsaved-changes guard (see the `saved` state above).
  useEffect(() => {
    setSaved(false);
  }, [graph]);

  const hasErrors = compiled.errors.length > 0;
  // Reserved-scope errors (Item A, P1 fix) surfaced right next to the identifier field that caused
  // them — a subset of `compiled.errors`, so they ALSO already disable Save/Dry-run via `hasErrors`
  // (this is only for the inline, field-adjacent message; it adds no separate gate of its own).
  const scopeReservedErrors = useMemo(() => compiled.errors.filter((e) => e.code === "reserved_scope"), [compiled.errors]);
  // Per-tier "an identifier has been entered" check. The namespace tier's identifier IS
  // `targetNamespace` (see above), so its own readiness collapses to `namespaceReady` — the `&&
  // namespaceReady` already ANDed into canDryRun/canSave below makes that redundant-but-correct rather
  // than a second, possibly-inconsistent check.
  const scopeReady = tier === "class" ? agentClass.trim().length > 0 : tier === "namespace" ? namespaceReady : workloadName.trim().length > 0;
  /** Allowed tools with NO condition on them at all — the grants that are exactly as wide as the tool.
   *
   *  Both stores, always. Counting only `allowlistGrants` is the defect that has recurred through this
   *  work: a tool narrowed purely by scoping FACTS would be reported as unscoped by the very banner
   *  that exists to tell the operator what is left to do. */
  const unscopedTools = useMemo(
    () => allowlistTools.filter((t) => (allowlistGrants[t] ?? []).length + (allowlistGrantFacts[t] ?? []).length === 0),
    [allowlistTools, allowlistGrants, allowlistGrantFacts]
  );

  /** Per-tool newly-denied counts, from the dry run's SAMPLE of decision flips.
   *
   *  `null` until a dry run has been done — the scope cell then says nothing about traffic rather than
   *  implying zero.
   *
   *  THE SAMPLE IS NOT THE TOTAL, AND `truncated` DOES NOT SAY THAT IT ISN'T. The server appends flips
   *  to `newly_blocked_samples` only `if len(flip_samples) < 8` — an unconditional 8-row cap across ALL
   *  tools — while `truncated` reports something else entirely: that the REPLAY hit its 500-record cap.
   *  Keying "this number is a lower bound" on `truncated` therefore printed an 8-row sample as a
   *  per-tool total on every ordinary dry run, and gave every tool the sample cut off ScopeCell's
   *  affirmative 0-case, "No replayed call would be denied by this grant." A grant nobody measured must
   *  never read as a grant measured and found harmless — so the counts below are passed as a lower
   *  bound, withheld entirely where the sample cannot speak for a tool, and the sample's own size is
   *  stated on the row (`builder-scope-sample-note-*`) so the gap is visible rather than merely absent. */
  const newlyDeniedByTool = useMemo<Map<string, number> | null>(() => {
    const samples = dryRunResult?.newly_blocked_samples;
    if (!samples) return null;
    const out = new Map<string, number>();
    for (const s of samples) {
      const name = (s.tool_name ?? "").toLowerCase();
      if (name) out.set(name, (out.get(name) ?? 0) + 1);
    }
    return out;
  }, [dryRunResult]);
  // Declared before the traffic derivations below because they all depend on it: a run against an
  // EARLIER rego is not a measurement of the policy currently on screen.
  const dryRunStale = dryRunRego !== null && dryRunRego !== compiled.rego;
  const flipSampleSize = dryRunResult?.newly_blocked_samples?.length ?? 0;
  /** `newly_blocked` is optional on the wire. Absent, it is UNKNOWN — `?? 0` would turn a missing total
   *  into "the sample is everything", which is the same fallback-to-zero this whole fix is about. */
  const flipTotalReported = typeof dryRunResult?.newly_blocked === "number";
  const flipTotal = dryRunResult?.newly_blocked ?? 0;
  /** TWO INDEPENDENT REASONS the flip list is not the whole truth, kept APART because they are
   *  different facts with different remedies, and one sentence covering both refuted itself:
   *
   *    `flipSampleCapped` — more flips were COUNTED than were NAMED (the server names at most 8 across
   *      all tools). With no total reported at all this is unknowable, so it is assumed — WHATEVER the
   *      sample's size, zero included. "Cannot be shown to be complete" is not "is complete": an empty
   *      flip list with no total scored as a complete sample and handed every row ScopeCell's
   *      affirmative "No replayed call would be denied by this grant.", on the same screen whose
   *      headline said the count was never reported.
   *    `replayCapped` — `truncated`: the REPLAY stopped at its 500-record cap, so calls exist that were
   *      never evaluated at all. A flip list can be 3 of 3 and still miss every one of them, which is
   *      why this cannot be folded into the sentence about the sample's size — "sample of 3 of 3
   *      newly-blocked calls, this tool's real number can be higher" sends the operator hunting for
   *      flips that do not exist instead of at the records the run never reached. */
  const flipSampleCapped = flipTotalReported ? flipTotal > flipSampleSize : true;
  const replayCapped = dryRunResult?.truncated === true;
  const flipSampleIncomplete = flipSampleCapped || replayCapped;
  /** The scale of what was named, in the words both the row note and the chip label use. */
  const flipSampleScale = flipTotalReported
    ? `${flipSampleSize} of ${flipTotal} newly-blocked calls`
    : `${flipSampleSize} newly-blocked calls, with no total reported`;
  /** How much traffic the replay examined. `total_records_checked` is optional exactly like
   *  `newly_blocked`: ABSENT is not zero, and zero is not "clean" — both mean the grant's effect on
   *  real traffic went unmeasured, and neither may be rendered as a measurement. */
  const replayCountReported = typeof dryRunResult?.total_records_checked === "number";
  const replayCount = dryRunResult?.total_records_checked ?? 0;
  const replayUnmeasured = dryRunResult != null && (!replayCountReported || replayCount === 0);
  /** What the scope cell is allowed to state about one tool's traffic.
   *
   *  `null` wherever the dry run cannot answer, because ScopeCell renders 0 as the affirmative "No
   *  replayed call would be denied by this grant." — the one sentence a capped sample has not earned.
   *  `trafficNoteFor` says WHY it is silent instead; silence alone would read as "nothing to report". */
  const newlyDeniedFor = (toolKey: string): number | null => {
    if (newlyDeniedByTool === null) return null;
    // Measured, but against a policy the operator has since edited past — it describes a rego that is
    // no longer on screen, and the row has no way to say "this number is about something else".
    if (dryRunStale) return null;
    const n = newlyDeniedByTool.get(toolKey) ?? 0;
    // A flip the run NAMED for this tool is evidence in its own right, and stays visible as a lower
    // bound: withholding a real number because some OTHER field of the response was unreported would
    // be the mirror image of the same defect — an unknown hiding a measurement.
    if (n > 0) return n;
    if (replayUnmeasured || flipSampleIncomplete) return null;
    return 0;
  };
  /** Why a row is silent, or why its number is a floor rather than a total — in the SAME words for the
   *  same cause, so the note can never describe a different gap than the one `newlyDeniedFor` acted on. */
  const trafficNoteFor = (toolKey: string): string | null => {
    if (dryRunResult == null) return null;
    if (dryRunStale)
      return "This dry-run ran against an earlier version of the policy, so its numbers do not describe this grant — re-run it.";
    const named = (newlyDeniedByTool?.get(toolKey) ?? 0) > 0;
    // "Nothing was replayed" cannot be said on a row the run named flips for — a named flip IS a
    // replayed call, and the two sentences side by side would contradict each other on one line. Such a
    // response is self-inconsistent; the row falls through to what it can support, the flip count.
    if (replayUnmeasured && !named)
      return replayCountReported
        ? "The dry-run replayed no recent calls, so this grant's effect on real traffic is unmeasured — not zero."
        : "The dry-run did not report how many calls it replayed, so this grant's effect on real traffic is unmeasured — not zero.";
    if (!flipSampleIncomplete) return null;
    if (flipSampleCapped) {
      if (flipSampleSize === 0 && !flipTotalReported)
        return "The dry-run named no newly-blocked calls and reported no total, so this grant's effect on real traffic is unmeasured — not zero.";
      return named
        ? `Counted from the dry-run's sample of ${flipSampleScale} — this tool's real number can be higher.`
        : `Not named in the dry-run's sample of ${flipSampleScale} — this grant may still deny replayed calls.`;
    }
    // The flip list IS whole; what is missing is the traffic the replay never reached.
    return named
      ? "Every newly-blocked call the dry-run found is named, but its replay stopped at its record cap — calls beyond it were never evaluated, so this tool's real number can be higher."
      : "The dry-run's replay stopped at its record cap, so calls beyond it were never evaluated — this grant may still deny replayed calls.";
  };

  // Both the dry-run and the save POST a concrete namespace to the server (dry-run replays that
  // namespace's real traffic) — neither may proceed while the target is still "all"/"" (see
  // `namespaceReady` above, seeded from `targetNamespace`). Every tier needs a concrete target
  // namespace (class/namespace: it's where the row is written; workload: it's also baked into the
  // guard and the loader key), so this ANDs in regardless of tier.
  const canDryRun = scopeReady && namespaceReady && !hasErrors && !dryRunLoading;
  const canSave = scopeReady && namespaceReady && !hasErrors && dryRunResult?.valid === true && !dryRunStale && !saving;
  // Meaningful unsaved content (some scope identifier typed for whichever tier is selected, at least
  // one rule added, or — in allowlist mode — at least one tool added) with no successful save since
  // the last edit — this is what requestClose() checks before discarding the graph.
  const hasUnsavedContent = scopeIdentifier(scope).trim().length > 0 || rules.length > 0 || (mode === "allowlist" && allowlistTools.length > 0);
  const isDirty = hasUnsavedContent && !saved;

  // --- numbered-step progressive disclosure (UX redesign) --------------------------------------------
  // "Step ① valid" = a tier is chosen AND its identifier is non-empty AND not reserved AND a concrete
  // target namespace is set. This is intentionally NARROWER than `!hasErrors` (which also trips on rule
  // condition errors) — a bad rule shouldn't lock step ① back up.
  const step1Valid = scopeReady && namespaceReady && scopeReservedErrors.length === 0;
  // "Step ② valid" = rules mode: at least one rule with no compile errors of its own; allowlist mode:
  // the mode itself has been chosen (an empty allowlist is legal — deny-all — so no tool is required).
  const step2Valid = mode === "allowlist" ? true : rules.some((_, idx) => errorsForRule(compiled.errors, idx).length === 0);
  // Steps dim (opacity only, never disabled — see BuilderSteps.css) until the prior step is valid. The
  // REAL gating for dry-run/Save is untouched — canDryRun/canSave above, unaffected by these.
  // The identifier field step ① ACTUALLY DRAWS for the currently selected tier. A tier-blind "Set an
  // agent class first." is not a rounded-off version of the truth: the workload tier renders no
  // agent-class control anywhere on screen, so the one sentence naming a field sent the operator
  // hunting for a control that does not exist while the field that is missing — "Workload name
  // (Deployment)" — sat unnamed in front of them. The namespace tier's identifier IS `targetNamespace`
  // and is absorbed by the `!namespaceReady` branch below, so its string here is unreachable-but-true
  // rather than a fourth thing to keep in sync.
  const scopeIdentifierPrompt =
    tier === "workload"
      ? "Set a workload (Deployment) name first."
      : tier === "namespace"
        ? "Set a target namespace first."
        : "Set an agent class first.";
  // WHY SAVE IS BLOCKED, as a sentence the operator can read without hovering a control that cannot
  // be hovered. Ordered by what must be fixed FIRST — naming the dry-run while the namespace is still
  // unset would send them to the wrong field.
  const saveBlockedReason = !canSave
    ? !namespaceReady
      ? "Pick a concrete target namespace first — the global scope is All namespaces."
      : !scopeReady
        ? scopeIdentifierPrompt
        : hasErrors
          ? "Fix the compile errors before saving."
          : dryRunStale
            ? "The policy changed since the last dry-run — re-run it."
            : dryRunResult?.valid !== true
              ? "Run a dry-run first — save is blocked until it passes."
              : undefined
    : undefined;

  const step1State: "active" | "done" = step1Valid ? "done" : "active";
  const step2State: "locked" | "active" | "done" = !step1Valid ? "locked" : step2Valid ? "done" : "active";
  const step3State: "locked" | "active" | "done" = !step2Valid ? "locked" : saved ? "done" : "active";

  // Auto-focus (Phase: numbered steps) — whichever tier is selected, its own identifier field gets
  // focus: on the initial mount (tier defaults to "class") and again every time the tier changes. Only
  // ONE of the three identifier inputs below attaches this ref at a time (tier-dispatched JSX), so this
  // single ref always points at "the" current identifier field, never a stale one.
  const identifierRef = useRef<HTMLInputElement>(null);
  useEffect(() => {
    identifierRef.current?.focus();
  }, [tier]);

  const primaryEnforcementMode = rules.some((r) => r.decision === "block")
    ? "block"
    : rules.some((r) => r.decision === "escalate")
    ? "escalate"
    : rules.some((r) => r.decision === "audit")
    ? "audit"
    : "block";

  const runDryRun = async () => {
    if (!canDryRun) return;
    setDryRunLoading(true);
    setDryRunError(null);
    const ranAgainst = compiled.rego;
    try {
      const result = await dryRunPolicy({
        namespace: targetNamespace.trim(),
        // Dry-run's `agent_class` has a DIFFERENT meaning than Save's (below): the server's own
        // `_replay_recent` filters REPLAYED audit records by `AuditLogEntry.agent_class == agent_class`
        // when truthy, and its docstring says "a class-less (namespace/workload) policy replays the
        // whole namespace" when it's falsy. Sending the namespace/workload tier's LOADER key here (e.g.
        // "namespace:default") would filter for a literal agent_class no real record ever has —
        // always zero replay — so those two tiers send "" instead, matching the server's own doctrine.
        agent_class: tier === "class" ? agentClass.trim() : "",
        rego_source: ranAgainst
      });
      setDryRunResult(result);
      setDryRunRego(ranAgainst);
    } catch {
      // Never fabricate a zero-impact result on a swallowed failure — null it and surface an error.
      setDryRunResult(null);
      setDryRunRego(null);
      setDryRunError("Dry-run could not evaluate — no result (retry).");
    } finally {
      setDryRunLoading(false);
    }
  };

  const saveAndEnforce = async () => {
    if (!canSave) return;
    setSaving(true);
    // The REAL loader key this tier POSTs — `<class>` / `namespace:<ns>` / `deployment:<name>` — mirrors
    // the server's own `resolve_policy_key` exactly (see builderCompile.ts's `loaderKeyFor`). This is
    // NOT the same value dry-run sends as `agent_class` above (see runDryRun's comment for why).
    const key = loaderKeyFor(scope);
    const ns = targetNamespace.trim(); // ALWAYS concrete here — canSave requires namespaceReady
    try {
      const res = await apiSend<{ version?: number }>("/api/v1/policies", "POST", {
        namespace: ns,
        agent_class: key,
        rego_source: compiled.rego,
        enforcement_mode: primaryEnforcementMode,
        // Explicit per-tier priority. Omitting it defaulted EVERY tier to the server's 100, which put a
        // Namespace policy on the same number as an Agent-class one while the console rendered it under
        // "Catch-all fallback · lowest priority" — see SCOPE_TIER_PRIORITY.
        priority: SCOPE_TIER_PRIORITY[tier]
      });
      const ver = res?.version;
      setApplyResult({
        kind: "local",
        title: `Created ${ns}/${key}${ver ? ` · v${ver}` : ""}`,
        ok: true,
        outcome: `Policy authored via the Visual Policy Builder for ${SCOPE_TIER_LABEL[tier].toLowerCase()} "${scopeIdentifier(scope)}" (loader key "${key}") in namespace "${ns}" and loaded into this cluster's policy engine — enforcing "${primaryEnforcementMode}". Effective on the next matching tool call.`,
        manifest: { namespace: ns, agent_class: key, enforcement_mode: primaryEnforcementMode, rego: compiled.rego },
        expectedVersion: ver,
        expectedMode: primaryEnforcementMode
      });
      onSaved?.({ namespace: ns, agentClass: key, version: ver });
      // Successful save — clear the unsaved-changes guard so closing right after does not prompt.
      setSaved(true);
    } catch (e) {
      const msg = String(e).replace(/^Error:\s*/, "");
      const codeMatch = msg.match(/NRVQ-[A-Z]+-\d+/);
      setApplyResult({
        kind: "local",
        title: "Save rejected",
        ok: false,
        outcome: msg,
        code: codeMatch ? codeMatch[0] : undefined,
        manifest: { namespace: ns, agent_class: key, enforcement_mode: primaryEnforcementMode }
      });
    } finally {
      setSaving(false);
    }
  };

  /** Gate for all three close paths (overlay click, X button, Cancel button): a dirty, unsaved graph
   *  requires an explicit confirm before it's discarded. A pristine sheet (no class, no rules) or one
   *  that was just successfully saved closes immediately, no prompt. */
  const requestClose = () => {
    if (isDirty && !window.confirm("Discard this unsaved policy?")) return;
    onClose();
  };

  const addRule = () => setRules((rs) => [...rs, newRule()]);
  const updateRule = (idx: number, next: BuilderRule) => setRules((rs) => rs.map((r, i) => (i === idx ? next : r)));
  const removeRule = (idx: number) =>
    setRules((rs) => {
      const removed = rs[idx];
      setRuleIdTouched((t) => {
        const next = { ...t };
        delete next[removed.id];
        return next;
      });
      return rs.filter((_, i) => i !== idx);
    });

  return (
    <>
      <div className="sheet-overlay" onClick={requestClose} />
      <div
        data-testid="builder-sheet"
        className="sheet-kit vpb-sheet-fullscreen"
        style={{ display: "flex", flexDirection: "column" }}
      >
        <div className="sheet-head">
          <div>
            <div className="sheet-title">Visual Policy Builder</div>
            <div className="panel-sub mono" style={{ marginTop: 3 }}>
              {SCOPE_TIER_LABEL[tier]}: {scopeIdentifier(scope).trim() || `new ${tier}`} · {targetNamespace.trim() || "no namespace set"}
            </div>
          </div>
          <button className="icon-btn" data-testid="builder-close" onClick={requestClose}>
            <X size={18} />
          </button>
        </div>

        <div className="vpb-body" style={{ display: "flex", gap: 20, flex: 1, minHeight: 0 }}>
          {/* LEFT: three numbered, progressively-revealed steps (UX redesign) — who this policy is for,
              what it should do, then check & enforce. Replaces the old flat wall of two identical-
              looking tab rows + two text fields, which gave the operator no ordering cue at all. */}
          <div className="vpb-form-pane" style={{ flex: "1 1 480px", minWidth: 0, overflowY: "auto", paddingRight: 8 }}>
            {/* --- Step ① — Who is this policy for? (never locked — it's the first step) --- */}
            <div className="vpb-step" data-testid="builder-step-1" data-step-state={step1State}>
              <div className="vpb-step-header">
                <span className="vpb-step-badge">1</span>
                <span className="vpb-step-title">Who is this policy for?</span>
                <span className="vpb-step-chip" data-testid="builder-step-1-chip" data-done={step1Valid}>
                  {step1Valid ? "✓ Done" : "Needs input"}
                </span>
              </div>

              <div className="vpb-step-body">
                {/* Tier picker (Phase 3, now three selectable CARDS not a tab row — radiogroup semantics
                    so it reads as a single choice, visually distinct from step ②'s mode chooser below).
                    Switches which identifier field(s) below are shown/required and which loader key +
                    rego guard the compiler emits (builderCompile.ts's scope helpers) — see
                    builderGraph.ts's BuilderScope doc comments for the full class/namespace/workload
                    semantics. Switching tiers does NOT clear the other tiers' typed-in state (agentClass /
                    workloadName each keep their own value), so flipping back and forth doesn't lose work. */}
                <div
                  data-testid="builder-tier-picker"
                  role="radiogroup"
                  aria-label="Who is this policy for?"
                  className="vpb-tier-cards"
                  onKeyDown={(e) => {
                    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
                    e.preventDefault();
                    const idx = SCOPE_TIERS.indexOf(tier);
                    const delta = e.key === "ArrowRight" ? 1 : -1;
                    const next = SCOPE_TIERS[(idx + delta + SCOPE_TIERS.length) % SCOPE_TIERS.length];
                    setTier(next);
                  }}
                >
                  {SCOPE_TIERS.map((t) => (
                    <button
                      key={t}
                      type="button"
                      role="radio"
                      data-testid={`builder-tier-${t}`}
                      aria-checked={tier === t}
                      className="vpb-tier-card"
                      onClick={() => setTier(t)}
                    >
                      <span className="vpb-tier-card-title">{SCOPE_TIER_LABEL[t]}</span>
                      <span className="vpb-tier-card-desc">{SCOPE_TIER_DESCRIPTION[t]}</span>
                      <span className="vpb-tier-card-eg">{SCOPE_TIER_EXAMPLE[t]}</span>
                      {t === "workload" && (
                        <span className="vpb-tier-card-note">
                          Deployments only — other workload kinds are never evaluated.
                        </span>
                      )}
                    </button>
                  ))}
                </div>

                {tier === "class" && (
                  <div className="field-row" style={{ marginTop: 10 }}>
                    <label className="field-label">Agent class</label>
                    <input
                      ref={identifierRef}
                      data-testid="builder-agent-class"
                      className="input mono"
                      list="builder-known-classes"
                      placeholder="e.g. builder-spike"
                      value={agentClass}
                      onChange={(e) => setAgentClass(e.target.value)}
                      style={{ width: "100%" }}
                    />
                    <datalist id="builder-known-classes">
                      {knownClasses.map((c) => (
                        <option key={c} value={c} />
                      ))}
                    </datalist>
                  </div>
                )}

                {tier === "workload" && (
                  <div className="field-row" style={{ marginTop: 10 }}>
                    <label className="field-label">Workload name (Deployment)</label>
                    <input
                      ref={identifierRef}
                      data-testid="builder-scope-identifier"
                      className="input mono"
                      placeholder="e.g. checkout"
                      value={workloadName}
                      onChange={(e) => setWorkloadName(e.target.value)}
                      style={{ width: "100%" }}
                    />
                    <div className="panel-sub" style={{ fontSize: 10.5, marginTop: 4 }}>
                      Deployments only — other workload kinds (StatefulSet, DaemonSet, …) are never enforced
                      by the policy engine, so this tier only ever targets a Deployment name.
                    </div>
                  </div>
                )}

                {scopeReservedErrors.length > 0 && (
                  <div
                    data-testid="builder-scope-reserved-error"
                    role="alert"
                    style={{ fontSize: 11.5, color: "var(--danger,#e5484d)", marginTop: 4 }}
                  >
                    {scopeReservedErrors.map((e, i) => (
                      <div key={i}>{e.message}</div>
                    ))}
                  </div>
                )}

                {/* Namespace honesty (Phase 2f): the global selector's raw value flows straight through
                    as the `namespace` prop — if it's "all"/"" there is no single concrete namespace to
                    silently pick for the operator, so this field REQUIRES an explicit choice before Save
                    unlocks (see `namespaceReady`/`canSave`). When the selector already had a concrete
                    namespace, this is pre-filled but stays editable. Namespace tier (Phase 3): this SAME
                    field doubles as the tier's own scope identifier (single field, not two that could
                    drift apart) — its label/testid/helper text switch accordingly, and — per the numbered-
                    step design — it is NOT rendered a second time for that tier (see the tier === "class"
                    / tier === "workload" identifier blocks above, which are each tier's OWN field). */}
                <div className="field-row" style={{ marginTop: 10 }}>
                  <label className="field-label">{tier === "namespace" ? "Namespace" : "Target namespace"}</label>
                  <input
                    ref={tier === "namespace" ? identifierRef : undefined}
                    data-testid={tier === "namespace" ? "builder-scope-identifier" : "builder-target-namespace"}
                    className="input mono"
                    list="builder-known-namespaces"
                    placeholder={isConcreteNamespace(namespace) ? namespace : "Pick a namespace — required (scope is All namespaces)"}
                    value={targetNamespace}
                    onChange={(e) => setTargetNamespace(e.target.value)}
                    style={{ width: "100%", borderColor: namespaceReady ? undefined : "var(--escalate)" }}
                  />
                  <datalist id="builder-known-namespaces">
                    {knownNamespaces.map((n) => (
                      <option key={n} value={n} />
                    ))}
                  </datalist>
                  {tier === "namespace" && (
                    <div className="panel-sub" style={{ fontSize: 10.5, marginTop: 4 }}>
                      Namespace-tier policies apply to EVERY call in this namespace, regardless of the
                      calling agent's class — like a namespace-scoped baseline.
                    </div>
                  )}
                  {!namespaceReady && (
                    <div
                      data-testid="builder-namespace-required-warning"
                      role="alert"
                      style={{ fontSize: 11.5, color: "var(--escalate)", marginTop: 4 }}
                    >
                      The global scope is "All namespaces" — pick exactly one concrete namespace to create
                      this policy in before you can dry-run or save.
                    </div>
                  )}
                </div>

                {/* ASCII names only — see `asciiToolSuggestions` for why a datalist may not carry a
                    name whose appearance it cannot qualify. */}
                <datalist id="builder-known-tools">
                  {asciiToolSuggestions.map((t) => (
                    <option key={t} value={t} />
                  ))}
                </datalist>
              </div>
            </div>

            {/* --- Step ② — What should it do? (dimmed until step ① is valid) --- */}
            <div className="vpb-step" data-testid="builder-step-2" data-step-state={step2State}>
              <div className="vpb-step-header">
                <span className="vpb-step-badge">2</span>
                <span className="vpb-step-title">What should it do?</span>
                <span className="vpb-step-chip" data-testid="builder-step-2-chip" data-done={step2Valid}>
                  {step2Valid ? "✓ Done" : "Needs input"}
                </span>
              </div>
              {step2State === "locked" && (
                <div className="vpb-step-hint">Choose who this policy is for first.</div>
              )}

              <div className="vpb-step-body">
                <div data-testid="builder-mode-toggle" className="vpb-mode-options">
                  <button
                    type="button"
                    data-testid="builder-mode-rules"
                    aria-pressed={mode === "rules"}
                    className="vpb-mode-option"
                    onClick={() => setMode("rules")}
                  >
                    <div className="vpb-mode-option-title">{MODE_LABEL.rules}</div>
                    <div className="vpb-mode-option-desc">{MODE_DESCRIPTION.rules}</div>
                  </button>
                  <button
                    type="button"
                    data-testid="builder-mode-allowlist"
                    aria-pressed={mode === "allowlist"}
                    className="vpb-mode-option"
                    onClick={() => setMode("allowlist")}
                  >
                    <div className="vpb-mode-option-title">{MODE_LABEL.allowlist}</div>
                    <div className="vpb-mode-option-desc">{MODE_DESCRIPTION.allowlist}</div>
                  </button>
                </div>

                {/* THE MODE FORK, stated as a consequence rather than a definition.
                    The two modes do not merely differ in emphasis — they INVERT what an identical
                    condition means. `data_classes noneOf [secret]` is a precondition for allowing in
                    allowlist mode, and a trigger for blocking in tighten-only. An operator who
                    switches mode with conditions already authored keeps every clause and reverses
                    every outcome, which is the most expensive mistake this screen can produce and
                    the one it never mentioned. Showing ONE clause read both ways is the shortest
                    thing that makes it un-missable. */}
                <div
                  data-testid="builder-mode-fork"
                  style={{
                    marginTop: 10,
                    padding: "10px 12px",
                    borderRadius: 10,
                    border: "1px solid var(--border)",
                    background: "var(--bg-void)",
                    fontSize: 12,
                    lineHeight: 1.6,
                    color: "var(--text-secondary)"
                  }}
                >
                  <div style={{ fontWeight: 600, color: "var(--text-primary)", marginBottom: 5 }}>
                    The two modes invert what a condition means
                  </div>
                  <div>
                    In <strong style={{ color: "var(--accent)" }}>{MODE_LABEL.allowlist}</strong>,{" "}
                    <span className="mono" style={{ color: "var(--text-primary)" }}>data_classes noneOf [secret]</span>{" "}
                    means <em>allow only if it carries no secret</em>.
                  </div>
                  <div style={{ marginTop: 3 }}>
                    In <strong style={{ color: "var(--escalate)" }}>{MODE_LABEL.rules}</strong>, the same clause means{" "}
                    <em>block when it carries no secret</em>.
                  </div>
                  <div style={{ marginTop: 5, color: "var(--text-muted)" }}>
                    {mode === "rules"
                      ? "In this mode a mistake is SILENT: a rule matching nothing never fires, and still looks like it enforces."
                      : "In this mode a mistake is LOUD: the call is denied, and the audit row names the rule that denied it."}
                  </div>
                </div>

                {mode === "rules" && (
                  <>
                    <div className="section-label" style={{ marginTop: 4, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <span>Rules</span>
                      <button type="button" data-testid="builder-add-rule" className="sb-link" style={{ fontSize: 11.5, color: "#2DDAB8" }} onClick={addRule}>
                        <Plus size={12} /> Add rule
                      </button>
                    </div>
                {rules.length === 0 && (
                  <div className="muted" style={{ fontSize: 12, padding: "8px 0" }}>
                    No rules yet — Add rule to start (defaults below apply until then).
                  </div>
                )}
                {rules.map((rule, idx) => (
                  <RuleCard
                    key={rule.id}
                    rule={rule}
                    index={idx}
                    tier={tier}
                    errors={errorsForRule(compiled.errors, idx)}
                    ruleIdTouched={!!ruleIdTouched[rule.id]}
                    knownTools={knownToolNames}
                    onChange={(next) => updateRule(idx, next)}
                    onRemove={() => removeRule(idx)}
                    onRuleIdTouched={() => setRuleIdTouched((t) => ({ ...t, [rule.id]: true }))}
                  />
                ))}

                <div className="section-label" style={{ marginTop: 12 }}>
                  Defaults
                </div>
                <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
                  <select
                    data-testid="builder-defaults-decision"
                    className="input"
                    style={{ fontSize: 12.5, padding: "4px 8px", width: 110 }}
                    value={defaults.decision}
                    onChange={(e) => setDefaults({ ...defaults, decision: e.target.value as BuilderDefaults["decision"] })}
                  >
                    <option value="allow">allow</option>
                    <option value="block">block</option>
                  </select>
                  <input
                    data-testid="builder-defaults-reason"
                    className="input"
                    style={{ fontSize: 12.5, padding: "4px 8px", flex: 1 }}
                    value={defaults.reason}
                    onChange={(e) => setDefaults({ ...defaults, reason: e.target.value })}
                  />
                </div>
              </>
            )}

            {mode === "allowlist" && (
              <div style={{ marginBottom: 16 }}>
                <div className="section-label">Allowed tools</div>
                <div className="panel-sub" style={{ fontSize: 11.5, marginBottom: 8 }}>
                  Every tool call for this class is BLOCKED by default — only the tools listed below are
                  allowed (and only when every enabled refinement below also holds).
                </div>
                <div data-testid="builder-allowlist-tools">
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <input
                      data-testid="builder-allowlist-tool-input"
                      className="input mono"
                      list="builder-known-tools"
                      placeholder="tool_name"
                      // flex:1 grows; minWidth:0 lets it shrink correctly in the row (an input's default
                      // min-width is its intrinsic size, which otherwise fights the sibling button).
                      style={{ fontSize: 12.5, padding: "4px 8px", flex: 1, minWidth: 0 }}
                      value={allowlistToolInput}
                      onChange={(e) => setAllowlistToolInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          e.preventDefault();
                          addAllowlistTool();
                        }
                      }}
                    />
                    {/* NOT .sb-link here: that class is width:100% (built for the sidebar) and, as a flex
                        sibling, it claimed the whole row and collapsed the input to ~0px. Size to content. */}
                    {/* Disabled on an empty field. It used to stay fully enabled and simply no-op —
                        `addAllowlistTool` returns early on a blank name — so clicking it did nothing at
                        all, with no message and no state change. That reads as "the Add button is
                        broken" rather than "there is nothing to add", which is exactly how it was
                        reported. A control that cannot act must not look actionable. */}
                    <button
                      type="button"
                      data-testid="builder-allowlist-tool-add"
                      onClick={addAllowlistTool}
                      disabled={allowlistToolInput.trim() === ""}
                      title={
                        allowlistToolInput.trim() === ""
                          ? "Type a tool name to add it to the allowlist"
                          : `Allow ${allowlistToolInput.trim()}`
                      }
                      style={{
                        flex: "none",
                        display: "inline-flex",
                        alignItems: "center",
                        gap: 5,
                        whiteSpace: "nowrap",
                        fontSize: 12.5,
                        padding: "6px 12px",
                        borderRadius: "var(--radius-md)",
                        border: "1px solid var(--border)",
                        background: "transparent",
                        color: allowlistToolInput.trim() === "" ? "var(--text-dim)" : "#2DDAB8",
                        opacity: allowlistToolInput.trim() === "" ? 0.55 : 1,
                        cursor: allowlistToolInput.trim() === "" ? "not-allowed" : "pointer"
                      }}
                    >
                      <Plus size={12} /> Add
                    </button>
                  </div>
                  {knownToolNames != null &&
                    allowlistToolInput.trim() !== "" &&
                    !knownToolNames.has(allowlistToolInput.trim().toLowerCase()) && (
                      <div
                        data-testid="builder-unknown-tool-warning"
                        role="status"
                        style={{ fontSize: 10.5, color: "var(--escalate)", marginTop: 4 }}
                      >
                        ⚠ "{allowlistToolInput.trim()}" is not in this namespace's tool registry — this entry
                        won't match until such a tool appears
                      </div>
                    )}
                  {/* The third state the old two-way check could not express. A tool with an approved
                      definition that simply has not been called yet is a NORMAL thing to allowlist —
                      deny-by-default requires authoring rules before the traffic exists — so saying
                      "no agent has called this" here would be technically true and completely
                      misleading. It is only worth a note, not a warning colour. */}
                  {knownToolNames != null &&
                    allowlistToolInput.trim() !== "" &&
                    declaredToolNames.has(allowlistToolInput.trim().toLowerCase()) && (
                      <div
                        data-testid="builder-declared-tool-note"
                        role="status"
                        style={{ fontSize: 10.5, color: "var(--text-dim)", marginTop: 4 }}
                      >
                        declared by an MCP server in this namespace
                        {schemaByTool.has(allowlistToolInput.trim().toLowerCase()) ? " — its arguments can be scoped" : ""}
                      </div>
                    )}
                  {/* THE NAMES THE DATALIST WOULD NOT SAY ANYTHING ABOUT. Withheld from the bare
                      suggestion list (an <option> is a string — no badge, no colour, and these are
                      pixel-identical to their ASCII twins), surfaced here where each one can be shown
                      masked, with its codepoints, next to the consequence of allowing it. Silence
                      would be the worse choice: the tool WAS observed, and pretending it does not
                      exist is the same class of lie as showing it unmarked. */}
                  {lookalikeToolSuggestions.length > 0 && (
                    <div data-testid="builder-lookalike-suggestions" style={{ marginTop: 6 }}>
                      <div style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
                        Observed in this namespace, withheld from autocomplete because the name is not
                        what it looks like:
                      </div>
                      <BuilderLookalikeNote
                        lookalikes={lookalikeToolSuggestions}
                        data-testid="builder-lookalike-suggestions-note"
                        trailer={
                          <>
                            Adding one grants <strong>exactly that name</strong> — it does not also grant
                            the plain-ASCII tool it imitates. Add that one separately if you meant both.
                          </>
                        }
                      />
                    </div>
                  )}
                  {/* THE STANDING BANNER. An unscoped grant is not a partial edit an operator will
                      get back to — it is a finished policy that grants a whole capability. Counting
                      them where the count cannot be scrolled past is what turns "I allowed six tools"
                      into "I have narrowed two of six". */}
                  {unscopedTools.length > 0 && (
                    <div
                      data-testid="builder-unscoped-banner"
                      role="status"
                      style={{
                        marginTop: 10,
                        padding: "10px 12px",
                        borderRadius: 10,
                        border: "1px solid #FFB02030",
                        background: "#FFB02015",
                        fontSize: 12,
                        lineHeight: 1.55,
                        color: "var(--text-secondary)"
                      }}
                    >
                      <strong style={{ color: "var(--escalate)" }}>
                        {unscopedTools.length} of {allowlistTools.length} allowed tool
                        {allowlistTools.length === 1 ? " is" : "s are"} unscoped
                      </strong>
                      <div style={{ marginTop: 3 }}>
                        A name is what your framework already grants. The control is the rest of the sentence —
                        &ldquo;<span className="mono">{unscopedTools[0]}</span>, but only to @acme.com&rdquo;.
                      </div>
                      <button
                        type="button"
                        className="linklike"
                        style={{ fontSize: 12, marginTop: 6 }}
                        data-testid="builder-unscoped-banner-cta"
                        onClick={() => setOpenGrantTool(unscopedTools[0])}
                      >
                        Narrow {unscopedTools[0]} →
                      </button>
                    </div>
                  )}

                  {/* ROWS, not chips. The scope affordance used to be a 10.5px grey `+ scope` link
                      inside a pill — the product's entire differentiator, rendered as the least
                      prominent thing on the screen. A row gives it two-thirds of the width and four
                      slots that are never all empty. */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 8, marginTop: 10 }}>
                    {allowlistTools.map((t) => {
                      const key = t.toLowerCase();
                      const paths = pathsByTool.get(key) ?? [];
                      // `null` is the badge's own word for "not in the registry"; it is not the same
                      // as the registry being unavailable, which `registryNull` renders as silence.
                      const provenance = declaredToolNames.has(key)
                        ? "mcp_declared"
                        : knownToolNames?.has(key)
                          ? "observed"
                          : null;
                      const trafficNote = trafficNoteFor(key);
                      // A GRANT is where a lookalike costs the most: the row below says "Observed",
                      // "Any arguments · unrestricted" and "Allows every call to <name>", and every
                      // one of those sentences is about a name the operator cannot distinguish from
                      // the real tool. The badge asserting the name was seen in real traffic is TRUE
                      // and makes it worse — it is the impostor's traffic. `null` for the ASCII case,
                      // which is almost every case, so the row stays clean.
                      const twin = lookalikeOf(t);
                      return (
                        <div
                          key={t}
                          data-testid={`builder-allowlist-tool-row-${t}`}
                          style={{
                            display: "flex",
                            gap: 12,
                            alignItems: "flex-start",
                            flexWrap: "wrap",
                            padding: "10px 12px",
                            borderRadius: 10,
                            border: "1px solid var(--border)",
                            background: "var(--bg-void)"
                          }}
                        >
                          <div style={{ flex: "1 1 180px", minWidth: 0 }}>
                            <div className="mono" style={{ fontSize: 12.5 }}>
                              {t}
                            </div>
                            <div style={{ marginTop: 4 }}>
                              <ProvenanceBadge source={provenance} registryNull={knownToolNames === null} />
                            </div>
                          </div>
                          <ScopeCell
                            tool={t}
                            constraints={allowlistGrants[t] ?? []}
                            facts={allowlistGrantFacts[t] ?? []}
                            addressableArgs={paths.filter((p) => p.addressable).map((p) => p.path)}
                            totalArgs={paths.length}
                            schemaAvailable={schemaByTool.has(key)}
                            expanded={openGrantTool === t}
                            onToggle={() => setOpenGrantTool((cur) => (cur === t ? null : t))}
                            newlyDenied={newlyDeniedFor(key)}
                            sampled={flipSampleIncomplete}
                            data-testid={`builder-scope-cell-${t}`}
                          />
                          <button
                            type="button"
                            data-testid={`builder-allowlist-tool-remove-${t}`}
                            className="icon-btn"
                            style={{ flex: "none", marginTop: 2 }}
                            title={`Remove ${t}`}
                            onClick={() => removeAllowlistTool(t)}
                          >
                            <X size={12} />
                          </button>
                          {/* WHAT THE DRY RUN COULD NOT SAY ABOUT THIS ROW, on the row that quotes from
                              it (last, so it takes its own full-width line under the cell rather than
                              displacing the remove control). The per-tool number is drawn from at most
                              8 named flips, so without this line "8 replayed calls would now be denied"
                              reads as this tool's total, and a tool the sample never reached reads as
                              cleared. STATED, not suppressed: "the dry-run has not measured this grant"
                              is itself the finding, and a silent row is indistinguishable from a clean
                              one. One source (`trafficNoteFor`) with the same inputs as the number
                              itself, so the sentence can never name a different gap than the one that
                              withheld the number. */}
                          {trafficNote && (
                            <div
                              data-testid={`builder-scope-sample-note-${t}`}
                              style={{ flex: "1 1 100%", fontSize: 11, lineHeight: 1.5, color: "var(--escalate)" }}
                            >
                              {trafficNote}
                            </div>
                          )}
                          {/* Full-width, under the row it qualifies. The consequence is the sheet's own
                              and not the shared LookalikeNote's — see `BuilderLookalikeNote` for the
                              compiled rego this sentence was checked against. Short version: this sheet
                              compiles in the browser, `ui/src/lib/skeleton.ts` does not fold cross-script
                              letters, so `allow_names`/`allow_skeletons` carry the Cyrillic literal and
                              the ASCII tool matches neither. The grant is one name wide, not two. */}
                          {twin && (
                            <div style={{ flex: "1 1 100%" }}>
                              <BuilderLookalikeNote
                                lookalikes={[twin]}
                                data-testid={`builder-lookalike-${t}`}
                                trailer={
                                  <>
                                    This entry grants <strong>exactly this name</strong>. The plain-ASCII
                                    tool it imitates is a different tool to the engine and is not granted
                                    here — the two names never collapse into one entry, because this
                                    policy&apos;s rego is compiled in the browser, which does not fold
                                    cross-script letters. Add the ASCII tool as its own entry if you meant
                                    both.
                                  </>
                                }
                              />
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  {openGrantTool !== null && allowlistTools.includes(openGrantTool) && (
                    <div
                      data-testid={`builder-grant-editor-${openGrantTool}`}
                      style={{
                        marginTop: 10,
                        border: "1px solid var(--border)",
                        borderRadius: 8,
                        padding: 10,
                        background: "var(--bg-elevated)"
                      }}
                    >
                      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                        {/* The editor's own title outranks the section headings inside it. At 12.5px
                            regular it did not, so "When http_get is called…" and "WHOLE CALL" and the
                            clause text were three levels of meaning at one level of emphasis. */}
                        <div style={{ fontSize: 13.5, fontWeight: 600, color: "var(--text-primary)" }}>
                          When <span className="mono" style={{ color: "var(--accent)" }}>{openGrantTool}</span> is
                          called, allow it only if:
                        </div>
                        <button
                          type="button"
                          className="icon-btn"
                          title="Close"
                          data-testid="builder-grant-editor-close"
                          onClick={() => setOpenGrantTool(null)}
                        >
                          <X size={12} />
                        </button>
                      </div>
                      <div style={{ fontSize: 11, lineHeight: 1.5, color: "var(--text-muted)", marginTop: 4 }}>
                        Every line must hold. A parameter that isn't supplied fails its line — so omitting an
                        argument can't be used to skip a constraint.
                      </div>
                      {/* The tool's own declared argument names, offered to the constraint field box.
                          Suggestions only — a constraint addresses `tool_params[<field>]` directly, so a
                          name the schema does not mention stays perfectly legal to type. */}
                      <datalist id={`builder-args-${openGrantTool}`}>
                        {flatArgNames(openGrantTool).map((a) => (
                          <option key={a} value={a} />
                        ))}
                      </datalist>

                      {(allowlistGrants[openGrantTool] ?? []).length > 0 && (
                        <ScopeSection
                          label="Argument"
                          hint={ARGUMENT_SCOPE_HINT}
                        />
                      )}
                      {(allowlistGrants[openGrantTool] ?? []).map((c, i) => (
                        <div
                          key={i}
                          data-testid={`builder-constraint-row-${openGrantTool}-${i}`}
                          style={CLAUSE_CARD}
                        >
                          <input
                            data-testid={`builder-constraint-field-${openGrantTool}-${i}`}
                            className="input mono"
                            placeholder="parameter"
                            aria-label="parameter name"
                            // Suggestions, not a constraint: a constraint addresses
                            // `input.tool_params[<field>]` directly, so any name remains legal — a schema
                            // can be stale or absent, and the tool may accept more than it declares.
                            list={`builder-args-${openGrantTool}`}
                            value={c.field}
                            onChange={(e) => updateConstraint(openGrantTool, i, { ...c, field: e.target.value })}
                            style={{ width: 120, fontSize: 11.5 }}
                          />
                          <select
                            data-testid={`builder-constraint-kind-${openGrantTool}-${i}`}
                            aria-label="constraint type"
                            value={c.kind}
                            onChange={(e) =>
                              updateConstraint(openGrantTool, i, {
                                ...blankConstraint(e.target.value as ConstraintKind),
                                field: c.field
                              })
                            }
                            style={{ fontSize: 11.5 }}
                          >
                            {CONSTRAINT_KINDS.map((k) => (
                              <option key={k} value={k}>
                                {CONSTRAINT_VERB[k]}
                              </option>
                            ))}
                          </select>
                          {CONSTRAINT_PLACEHOLDER[c.kind] !== "" && (
                            <input
                              data-testid={`builder-constraint-value-${openGrantTool}-${i}`}
                              className="input mono"
                              aria-label="constraint value"
                              placeholder={CONSTRAINT_PLACEHOLDER[c.kind]}
                              // The declared `enum` for THIS argument, when the tool published one and
                              // the operator is comparing by membership. A mistyped literal here is a
                              // restriction that silently never matches, so suggesting the legal values
                              // beats asking anyone to retype one — as a datalist, because a constraint
                              // value list is comma-separated and free text has to stay available.
                              list={
                                constraintEnumListId(c, openGrantTool)
                                  ? `builder-enum-${openGrantTool}-${c.field}`
                                  : undefined
                              }
                              value={constraintValueText(c)}
                              onChange={(e) => updateConstraint(openGrantTool, i, withConstraintValue(c, e.target.value))}
                              style={{ flex: 1, minWidth: 160, fontSize: 11.5 }}
                            />
                          )}
                          {constraintEnumListId(c, openGrantTool) && (
                            <datalist id={`builder-enum-${openGrantTool}-${c.field}`}>
                              {(constraintEnumListId(c, openGrantTool) ?? []).map((v) => (
                                <option key={v} value={v} />
                              ))}
                            </datalist>
                          )}
                          <button
                            type="button"
                            className="icon-btn"
                            data-testid={`builder-constraint-remove-${openGrantTool}-${i}`}
                            title="Remove this constraint"
                            onClick={() => removeConstraint(openGrantTool, i)}
                          >
                            <X size={11} />
                          </button>
                          <div style={{ width: "100%", fontSize: 10, color: "var(--text-dim)", paddingLeft: 2 }}>
                            {CONSTRAINT_HINT[c.kind]}
                            {/* Budget, from the ENCODING rather than the label. `hostIn` reads like set
                                membership and emits an anchored `regex.match`; an operator budgeting by
                                how a clause sounds gets it backwards. See regexCost.test.ts. */}
                            <span
                              data-testid={`builder-constraint-cost-${openGrantTool}-${i}`}
                              style={{ marginLeft: 6, color: constraintCostsRegexOp(c) ? "var(--escalate)" : "var(--text-faint)" }}
                            >
                              {constraintCostsRegexOp(c) ? "· 1 regex op" : "· set operator — free"}
                            </span>
                          </div>
                        </div>
                      ))}

                      {/* SCOPING FACTS — what the call CARRIES and where it GOES. Rendered in the same
                          panel as the per-field constraints because to an operator they are one idea:
                          "allow this tool, but only like this". Without these the panel offers only
                          per-argument rules, which plus a tool list is what the agent framework already
                          gives you — a capability list, not an intent. */}
                      {/* ONE pass, ORDERED by what each clause ADDRESSES, with the heading emitted at
                          each group boundary.

                          `param_paths.<path>` clauses live in the facts array — that is how the
                          compiler emits them — but they address ONE NAMED ARGUMENT, and every one was
                          rendering under a heading that said in so many words that they do not.
                          ARGUMENT vs WHOLE CALL is the vocabulary this panel exists to teach: an
                          argument clause fails when the caller omits that argument, a whole-call fact
                          holds wherever the value sits in the payload. Filing one under the other
                          teaches the distinction backwards.

                          Ordering rather than filtering into two passes keeps ONE copy of the row
                          markup, and `i` stays the clause's real index so `removeFact(tool, i)` still
                          removes the clause the operator clicked. NEGATED remains its own pass below,
                          for the reason it always was: a heading appearing wherever the first negated
                          clause happens to sit would group by accident rather than by meaning. */}
                      {(allowlistGrantFacts[openGrantTool] ?? [])
                        .map((f, i) => ({ f, i }))
                        .filter(({ f }) => f.type !== "not")
                        .sort((a, b) => Number(isWholeCallFact(a.f)) - Number(isWholeCallFact(b.f)))
                        .map(({ f, i }, ordinal, ordered) => {
                        // Re-narrow: `.filter()` drops the `not` variant at runtime, but TypeScript
                        // cannot see that through the chain and the row below reads `f.field`/`f.op`.
                        if (f.type === "not") return null;
                        const whole = isWholeCallFact(f);
                        const firstOfGroup = ordinal === 0 || isWholeCallFact(ordered[ordinal - 1].f) !== whole;
                        const kind = factKindOfSpec(f);
                        return (
                          <Fragment key={`fact-${i}`}>
                          {/* ONE heading per group across BOTH passes. Constraints and param_paths
                              facts are stored separately but address the same thing — one named
                              argument — and each pass emitted its own "Argument" heading with a
                              byte-identical hint. With both present the editor showed ARGUMENT
                              twice, which reads as two different kinds of argument clause rather
                              than as one group split by an internal storage detail. */}
                          {firstOfGroup && !(!whole && (allowlistGrants[openGrantTool] ?? []).length > 0) && (
                            <ScopeSection
                              label={whole ? "Whole call" : "Argument"}
                              hint={
                                whole
                                  ? "A fact the ENGINE derived about the call, not one named argument."
                                  : ARGUMENT_SCOPE_HINT
                              }
                            />
                          )}
                          <div data-testid={`builder-fact-row-${openGrantTool}-${i}`} style={CLAUSE_CARD}>
                            {/* The title must FOLLOW the group, not assert one of them. It was an
                                unguarded literal on every row, so a `param_paths.<arg>` clause —
                                filed under ARGUMENT precisely because it addresses one named
                                argument — carried a tooltip insisting it was a whole-call fact, and
                                the whole-call rows repeated their own visible hint verbatim.
                                A tooltip that contradicts the heading above it is worse than none:
                                the heading is the thing this panel exists to teach. */}
                            <span
                              style={CLAUSE_LABEL}
                              title={
                                whole
                                  ? undefined
                                  : `Addresses the ${f.field.replace(/^param_paths\./, "")} argument by name.`
                              }
                            >
                              {factFieldLabel(f.field)}
                            </span>
                            <select
                              data-testid={`builder-fact-op-${openGrantTool}-${i}`}
                              aria-label="scoping fact operator"
                              value={f.op}
                              onChange={(e) =>
                                // Carry the value across an op change wherever the two ops hold the same
                                // shape. Rebuilding blank every time discarded a list the operator had
                                // just typed for the sake of switching "must not include" to "must be
                                // within" — a change of MEANING, not of data.
                                updateFact(openGrantTool, i, retypedFact(f, kind, e.target.value))
                              }
                              style={{ fontSize: 11.5 }}
                            >
                              {factOpsFor(kind, f.field).map((op) => (
                                <option key={op} value={op}>
                                  {FACT_OP_VERB[op] ?? op}
                                </option>
                              ))}
                            </select>
                            {factEnumOptions(f, openGrantTool) ? (
                              <select
                                data-testid={`builder-fact-value-${openGrantTool}-${i}`}
                                className="input mono"
                                aria-label="scoping fact value"
                                value={factValueText(f)}
                                onChange={(e) => updateFact(openGrantTool, i, withFactValue(f, e.target.value))}
                                style={{ flex: 1, minWidth: 160, fontSize: 11.5 }}
                              >
                                <option value="">choose…</option>
                                {factEnumOptions(f, openGrantTool)?.map((v) => (
                                  <option key={v} value={v}>
                                    {v}
                                  </option>
                                ))}
                              </select>
                            ) : (
                              <input
                                data-testid={`builder-fact-value-${openGrantTool}-${i}`}
                                className="input mono"
                                aria-label="scoping fact value"
                                placeholder={kind === "numeric" || f.op === "maxCount" ? "number" : "comma-separated values"}
                                value={factValueText(f)}
                                onChange={(e) => updateFact(openGrantTool, i, withFactValue(f, e.target.value))}
                                style={{ flex: 1, minWidth: 160, fontSize: 11.5 }}
                              />
                            )}
                            <button
                              type="button"
                              className="icon-btn"
                              data-testid={`builder-fact-remove-${openGrantTool}-${i}`}
                              title="Remove this scoping fact"
                              onClick={() => removeFact(openGrantTool, i)}
                            >
                              <X size={11} />
                            </button>
                            <div style={{ width: "100%", fontSize: 10, color: "var(--text-dim)", paddingLeft: 2 }}>
                              {FACT_FIELD_HINT[f.field]}
                              <span
                                data-testid={`builder-fact-cost-${openGrantTool}-${i}`}
                                style={{ marginLeft: FACT_FIELD_HINT[f.field] ? 6 : 0, color: factCostsRegexOp(f) ? "var(--escalate)" : "var(--text-faint)" }}
                              >
                                {factCostsRegexOp(f) ? "· 1 regex op" : "· set operator — free"}
                              </span>
                            </div>
                          </div>
                          </Fragment>
                        );
                      })}


                      {/* NEGATED — a second pass, so the heading groups by MEANING rather than by
                          wherever the first negated fact happens to sit in authoring order. */}
                      {(allowlistGrantFacts[openGrantTool] ?? []).some((f) => f.type === "not") && (
                        <ScopeSection
                          label="Negated"
                          hint="Authored elsewhere and carried in. Compiles and enforces; not editable here."
                        />
                      )}
                      {(allowlistGrantFacts[openGrantTool] ?? []).map((f, i) => {
                        // A NOT-wrapped fact has no single field/op to edit, because the dropdown that
                        // authors facts only ever produces plain ones. It used to render NOTHING at all
                        // — while still compiling and still enforcing. So a grant could say "Narrowed ·
                        // 3 conditions" and show two rows, with the third invisible, un-removable, and
                        // live in production. Read-only is a limitation; invisible is a defect.
                        //
                        // `i` is the index in the FULL array, so `removeFact(tool, i)` still addresses
                        // this element. Filtering first would remove a different clause.
                        if (f.type !== "not") return null;
                        return (
                          <div
                            key={`neg-${i}`}
                            data-testid={`builder-fact-negated-${openGrantTool}-${i}`}
                            style={{
                              display: "flex",
                              gap: 8,
                              alignItems: "flex-start",
                              marginTop: 8,
                              padding: "7px 9px",
                              borderRadius: 8,
                              border: "1px solid var(--border)",
                              background: "var(--bg-void)"
                            }}
                          >
                            <span
                              className="pill"
                              style={{ flex: "none", background: "#7C5CFC15", color: "var(--audit)", borderColor: "#7C5CFC30" }}
                            >
                              NOT
                            </span>
                            <span style={{ flex: 1, minWidth: 0 }}>
                              <span className="mono" style={{ fontSize: 11.5, overflowWrap: "anywhere" }}>
                                {describeFact(f.inner)}
                              </span>
                              <span style={{ display: "block", fontSize: 10.5, color: "var(--text-dim)", marginTop: 2 }}>
                                Negated. Compiles and enforces. Not editable here — remove it and
                                re-author, or edit the policy source.
                              </span>
                            </span>
                            <button
                              type="button"
                              className="icon-btn"
                              data-testid={`builder-fact-remove-${openGrantTool}-${i}`}
                              title="Remove this negated scoping fact"
                              onClick={() => removeFact(openGrantTool, i)}
                            >
                              <X size={11} />
                            </button>
                          </div>
                        );
                      })}

                      <div style={{ display: "flex", gap: 6, marginTop: 10, alignItems: "center", flexWrap: "wrap" }}>
                        {/* ONE picker, not two selects. A `<select>` cannot show a disabled option's
                            REASON — the non-addressable arguments carried theirs in a `title` on a
                            disabled `<option>`, which no browser renders, so the operator saw a greyed
                            line and no way to learn why. It also cannot be searched, and it split this
                            tool's OWN arguments from the whole-call facts into two dropdowns that could
                            never be compared side by side — which is the one comparison that teaches
                            the difference between them. */}
                        <ConditionPicker
                          groups={pickerGroupsFor(openGrantTool)}
                          onPick={(groupKey, optionId) => {
                            if (groupKey === "args") {
                              // A `param_paths.<path>` field is not in the registry — the path is the
                              // tool's own argument — so it is always the scalar kind.
                              addFact(openGrantTool, `${PARAM_PATH_PREFIX}${optionId}`, "scalar");
                              return;
                            }
                            if (groupKey === "undeclared") {
                              // The escape hatch: a path the schema never declared. The row's own kind
                              // selector can change it — the picker chooses WHAT, the row chooses HOW.
                              addConstraint(openGrantTool, optionId as ConstraintKind);
                              return;
                            }
                            const spec = FACT_FIELDS.find((x) => x.field === optionId);
                            if (spec) addFact(openGrantTool, spec.field, spec.kind);
                          }}
                        />
                        {(allowlistGrants[openGrantTool] ?? []).length === 0 &&
                          (allowlistGrantFacts[openGrantTool] ?? []).length === 0 && (
                            <span style={{ fontSize: 10.5, color: "var(--text-dim)" }}>
                              Nothing scoped — <span className="mono">{openGrantTool}</span> is allowed with any
                              arguments, which is what the agent framework's tool binding already says.
                            </span>
                          )}
                      </div>
                    </div>
                  )}
                  {allowlistTools.length === 0 && (
                    <div
                      data-testid="builder-allowlist-empty-warning"
                      role="alert"
                      style={{
                        marginTop: 8,
                        fontSize: 11.5,
                        color: "var(--escalate)",
                        border: "1px solid var(--escalate)",
                        borderRadius: 6,
                        padding: "6px 8px"
                      }}
                    >
                      This denies every tool for the class
                    </div>
                  )}
                </div>

                <div className="section-label" style={{ marginTop: 14 }}>
                  Refinements
                </div>
                <div style={{ display: "flex", gap: 14, flexWrap: "wrap" }}>
                  {REFINEMENT_KEYS.map((key) => (
                    <label key={key} style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12.5 }}>
                      <input
                        type="checkbox"
                        data-testid={`builder-allowlist-refinement-${key}`}
                        checked={allowlistRefinements[key]}
                        onChange={(e) => setAllowlistRefinements((r) => ({ ...r, [key]: e.target.checked }))}
                      />
                      {REFINEMENT_LABEL[key]}
                    </label>
                  ))}
                </div>
              </div>
            )}
              </div>
            </div>
          </div>

          {/* RIGHT: live compiled rego + stats + errors + actions — narrower than the form on a wide
                viewport (see .vpb-rego-pane); the form is the work, the rego is reference. */}
          <div className="vpb-rego-pane" style={{ flex: "1 1 480px", minWidth: 0, display: "flex", flexDirection: "column", overflowY: "auto" }}>
            <div className="section-label" style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span>Compiled Rego (live, read-only)</span>
              <button
                type="button"
                data-testid="builder-editor-expand-toggle"
                className="icon-btn"
                aria-pressed={editorExpanded}
                data-expanded={editorExpanded}
                title={editorExpanded ? "Collapse editor" : "Expand editor"}
                style={{ width: 22, height: 22 }}
                onClick={() => setEditorExpanded((e) => !e)}
              >
                {editorExpanded ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
              </button>
            </div>
            <div className="editor" data-testid="builder-editor-container" data-expanded={editorExpanded} style={{ height: editorExpanded ? 560 : 260, marginBottom: 8 }}>
              <Editor
                defaultLanguage="rego"
                beforeMount={registerRego}
                theme="vs-dark"
                height={editorExpanded ? "560px" : "260px"}
                value={compiled.rego || "# Fix the errors below to generate rego"}
                options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12 }}
              />
            </div>

            <div
              data-testid="builder-stats"
              className="mono"
              style={{ display: "flex", gap: 14, fontSize: 11.5, color: "var(--text-muted)", marginBottom: 8 }}
            >
              <span style={{ color: compiled.stats.bytes > 65536 ? "var(--danger,#e5484d)" : undefined }}>
                {compiled.stats.bytes.toLocaleString()} / 65,536 bytes
              </span>
              <span style={{ color: compiled.stats.lines > 500 ? "var(--danger,#e5484d)" : undefined }}>
                {compiled.stats.lines} / 500 lines
              </span>
              <span style={{ color: compiled.stats.regexOps > 25 ? "var(--danger,#e5484d)" : undefined }}>
                {compiled.stats.regexOps} / 25 regex ops
              </span>
            </div>

            {hasErrors && (
              <div
                data-testid="builder-errors"
                role="alert"
                style={{
                  fontSize: 12,
                  color: "var(--danger,#e5484d)",
                  background: "#e5484d10",
                  border: "1px solid #e5484d30",
                  borderRadius: 8,
                  padding: "8px 10px",
                  marginBottom: 8,
                  maxHeight: 90,
                  overflowY: "auto"
                }}
              >
                {compiled.errors.map((e, i) => (
                  <div key={i}>{e.message}</div>
                ))}
              </div>
            )}

            {/* --- Step ③ — Check & enforce (dimmed until step ② has something). The compiled-rego
                preview + stats/errors ABOVE this are the persistent "what you're building" panel — an
                OUTPUT, not a step, so it stays un-numbered and never dims. */}
            <div className="vpb-step" data-testid="builder-step-3" data-step-state={step3State} style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
              <div className="vpb-step-header">
                <span className="vpb-step-badge">3</span>
                <span className="vpb-step-title">Check & enforce</span>
                <span className="vpb-step-chip" data-testid="builder-step-3-chip" data-done={saved}>
                  {saved ? "✓ Done" : "Needs input"}
                </span>
              </div>
              {step3State === "locked" && (
                <div className="vpb-step-hint">Add at least one rule (or choose allowlist mode) first.</div>
              )}

              <div className="vpb-step-body" style={{ display: "flex", flexDirection: "column", flex: 1, minHeight: 0 }}>
                {/* ALWAYS rendered (Phase 2f namespace honesty) — the operator sees exactly where Save
                    will write, even before either field is filled in. The plain-English sentence (UX
                    redesign) states MEANING per tier; the muted small-text line below it is the exact
                    WIRE key that will be POSTed (Phase 3: "agent-class" is the wire field name for every
                    tier — its VALUE is the real per-tier loader key, `loaderKeyFor(scope)`: `<class>` /
                    `namespace:<ns>` / `deployment:<name>`) — the honesty guarantee: the operator can
                    always see the exact truth of what gets written, never just a guess. */}
                <div
                  data-testid="builder-create-target"
                  style={{ marginBottom: 8 }}
                >
                  <div style={{ fontSize: 12.5, color: namespaceReady ? "var(--text-primary)" : "var(--escalate)" }}>
                    {scopeSentence({ scopeReady, namespaceReady, tier, agentClass, workloadName, targetNamespace })}
                  </div>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--text-muted)", marginTop: 3 }}>
                    creates {targetNamespace.trim() || "—"} / {scopeIdentifier(scope).trim() ? loaderKeyFor(scope) : "—"}
                  </div>
                </div>

                {/* Sticky: this row holds Run dry-run / Save & enforce and sits BELOW the rego editor in this
                    column. Expanding the editor used to push it out of a clipped pane with no way back. */}
                <div className="vpb-actions-sticky" style={{ display: "flex", gap: 8, marginBottom: 10 }}>
                  <KitButton
                    variant="outline"
                    icon={FlaskConical}
                    disabled={!canDryRun}
                    data-testid="builder-dryrun-btn"
                    // Same two blockers, same words as the VISIBLE reason on Save beside it (which is
                    // what the operator actually reads — `.btn:disabled { pointer-events: none }` means
                    // this `title` never surfaces while the button is disabled). It is kept in sync
                    // through the same `scopeIdentifierPrompt` so the two can never again disagree
                    // about which field is missing.
                    title={!namespaceReady ? "Pick a concrete target namespace first" : !scopeReady ? scopeIdentifierPrompt : undefined}
                    onClick={runDryRun}
                  >
                    {dryRunLoading ? "Dry-Running..." : "Run dry-run"}
                  </KitButton>
                  {/* The reason is VISIBLE TEXT, not a `title`.
                      `.btn:disabled { pointer-events: none }` means a disabled button never fires the
                      hover that would show its tooltip — so every reason living only in `title` was
                      unreachable at exactly the moment it was needed, and the operator was left with a
                      greyed primary button and nothing to act on. */}
                  <InlineDisabledReason reason={saveBlockedReason}>
                    <KitButton
                      variant="primary"
                      icon={Check}
                      disabled={!canSave}
                      data-testid="builder-save-btn"
                      onClick={saveAndEnforce}
                    >
                      {saving ? "Saving..." : "Save & enforce"}
                    </KitButton>
                  </InlineDisabledReason>
                  <KitButton variant="ghost" onClick={requestClose}>
                    Cancel
                  </KitButton>
                </div>

                <div style={{ overflowY: "auto", flex: 1, minHeight: 0 }}>
                  {dryRunResult != null && (
                <div data-testid="builder-dryrun-result" style={{ fontSize: 12.5, marginBottom: 10 }}>
                  <div style={{ fontWeight: 600, marginBottom: 6, display: "flex", alignItems: "center", gap: 8 }}>
                    Dry-Run Results
                    <span style={{ color: dryRunResult.valid ? "var(--success,#30a46c)" : "var(--danger,#e5484d)" }}>
                      {dryRunResult.valid ? "valid" : "invalid"}
                    </span>
                    {dryRunStale && (
                      <span style={{ fontSize: 10.5, color: "var(--escalate)", border: "1px solid var(--escalate)", borderRadius: 999, padding: "1px 8px" }}>
                        Stale · re-run
                      </span>
                    )}
                  </div>
                  {(dryRunResult.errors?.length ?? 0) > 0 && (
                    <div style={{ color: "var(--danger,#e5484d)", marginBottom: 6 }}>
                      {dryRunResult.errors!.map((e, i) => (
                        <div key={i}>{e}</div>
                      ))}
                    </div>
                  )}
                  <div style={{ color: "var(--text-secondary)" }}>
                    {/* `total_records_checked` is optional too, and `?? 0` printed "Replayed 0 recent
                        real calls" — a measurement stated for a run that never reported one — directly
                        beside the newly-blocked count this panel already refuses to invent. */}
                    {replayCountReported ? (
                      <>
                        Replayed {replayCount.toLocaleString()} recent real call{replayCount === 1 ? "" : "s"}
                      </>
                    ) : (
                      <span style={{ color: "var(--escalate)" }}>
                        The dry-run did not report how many recent calls it replayed
                      </span>
                    )}{" "}
                    ·{" "}
                    {/* An ABSENT count is not a count of zero. `?? 0` painted "0 newly blocked" in the
                        all-clear colour for a response that never reported the number — the headline
                        stating a safety result the run did not produce. */}
                    <strong style={{ color: !flipTotalReported ? "var(--escalate)" : flipTotal > 0 ? "var(--escalate)" : "var(--allow)" }}>
                      {flipTotalReported ? `${flipTotal} newly blocked` : "newly-blocked count not reported"}
                    </strong>
                  </div>
                  {(dryRunResult.newly_blocked_samples?.length ?? 0) > 0 && (
                    <>
                    {/* The chips are a SAMPLE — the server names at most 8 flips whatever the count
                        above says. Unlabelled, eight chips under "47 newly blocked" read as the whole
                        story, and the per-tool lines drawn from them read as totals. */}
                    <div data-testid="builder-dryrun-sample-label" style={{ fontSize: 11, marginTop: 6, color: flipSampleIncomplete ? "var(--escalate)" : "var(--text-muted)" }}>
                      {flipSampleCapped
                        ? flipTotalReported
                          ? `Sample — ${flipSampleScale} named below. Per-tool counts on the allowed-tool rows are lower bounds.`
                          : `Sample — ${flipSampleSize} newly-blocked call${flipSampleSize === 1 ? "" : "s"} named below, with no total reported. Per-tool counts on the allowed-tool rows are lower bounds.`
                        : replayCapped
                          ? `All ${flipSampleSize} newly-blocked call${flipSampleSize === 1 ? "" : "s"} the replay reached are named below — it stopped at its record cap, so calls beyond it were never evaluated.`
                          : `All ${flipSampleSize} newly-blocked call${flipSampleSize === 1 ? "" : "s"} named below.`}
                    </div>
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 }}>
                      {dryRunResult.newly_blocked_samples!.map((f, i) => (
                        <span
                          key={i}
                          className="mono"
                          style={{ fontSize: 11, padding: "2px 8px", borderRadius: 6, background: "#0e0e0e", border: "1px solid var(--border,#2a2a2a)", color: "var(--text-secondary)" }}
                        >
                          {f.tool_name} <span style={{ color: "var(--escalate)" }}>{f.was}→{f.now}</span> ({f.rule_id})
                        </span>
                      ))}
                    </div>
                    </>
                  )}
                  <div style={{ marginTop: 6, fontWeight: 600 }}>{dryRunResult.recommendation ?? "n/a"}</div>
                </div>
              )}

              {dryRunError != null && (
                <div
                  data-testid="builder-dryrun-error"
                  role="alert"
                  style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, color: "var(--block)", marginBottom: 10 }}
                >
                  <AlertCircle size={14} style={{ flex: "none" }} />
                  <span>{dryRunError}</span>
                </div>
              )}

              <ApplyResultPanel result={applyResult} onClose={() => setApplyResult(null)} />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
