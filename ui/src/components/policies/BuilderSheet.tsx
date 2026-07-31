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
import { AlertCircle, Check, FlaskConical, Maximize2, Minimize2, Plus, Trash2, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  apiSend,
  dryRunPolicy,
  fetchAllAgents,
  fetchAuditRecords,
  fetchClusterInfo,
  fetchTopBlocked,
  type DryRunReplay
} from "../../api/client";
import {
  compileGraph,
  loaderKeyFor,
  scopeIdentifier,
  type BuilderError
} from "../../lib/builderCompile";
import type {
  BuilderAllowlistRefinements,
  BuilderCondition,
  BuilderConditionNot,
  BuilderDecision,
  BuilderDefaults,
  BuilderDetector,
  BuilderGraph,
  BuilderKeywordTarget,
  BuilderMode,
  BuilderRule,
  BuilderScope
} from "../../lib/builderGraph";
import { CAPABILITY_SOURCE_ORDER, CAPABILITY_SOURCES, verbsForSource, type CapabilityVerb } from "../../lib/capabilitySources";
import { ApplyResultPanel, type ApplyResult } from "../common/ApplyResultPanel";
import { KitButton } from "../common/KitButton";

// --- Intent Allowlist mode (Phase 2c) --------------------------------------------------------------
const REFINEMENT_KEYS: (keyof BuilderAllowlistRefinements)[] = ["readonly", "egress", "scope", "rate"];
const REFINEMENT_LABEL: Record<keyof BuilderAllowlistRefinements, string> = {
  readonly: "Read-only",
  egress: "No external egress",
  scope: "Namespace-scoped",
  rate: "Rate-limit (advisory)"
};
const EMPTY_REFINEMENTS: BuilderAllowlistRefinements = { readonly: false, egress: false, scope: false, rate: false };
// Step ② mode chooser (UX redesign) — one-line explanation under each option so the difference between
// the two modes is legible without docs. Display-only; BuilderMode's wire values are unchanged.
const MODE_DESCRIPTION: Record<BuilderMode, string> = {
  rules: "Add blocks on top of what's already allowed. Everything not matched keeps its current outcome.",
  allowlist: "Deny everything for this scope except the tools you list."
};
const MODE_LABEL: Record<BuilderMode, string> = { rules: "Tighten-only rules", allowlist: "Intent allowlist" };

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
export const CONDITION_TYPES: Exclude<BuilderCondition["type"], "not">[] = [
  "detector",
  "keyword",
  "toolIn",
  "trustBelow",
  "sourceVerb",
  "paramRegex"
];

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

/** Slugify a reason string into a rego-safe rule_id token. Used to auto-fill rule_id from reason until
 *  the author edits rule_id directly (tracked per-rule via `ruleIdTouched`). */
export function slugifyRuleId(reason: string): string {
  const slug = reason
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return slug;
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
  paramRegex: "Param matches regex"
};

/** One-line hint shown near the type dropdown for whichever type is currently selected — the label
 *  above names the operator, this explains when it fires. */
export const CONDITION_TYPE_HINT: Record<(typeof CONDITION_TYPES)[number], string> = {
  detector: "Fires when a built-in content scanner flags the call — pick which detector below.",
  toolIn: "Fires when the tool name exactly matches one of the names listed below.",
  keyword: "Fires when any listed keyword appears in the tool name and/or its parameters.",
  trustBelow: "Fires when the calling agent's live trust score is below this threshold.",
  sourceVerb: "Fires on a CAPABILITY (e.g. any 'delete' on Postgres) without listing every tool name.",
  paramRegex: "Fires when a specific parameter's value matches the regex pattern below."
};

/** Groups the type dropdown into optgroups by category — purely a display grouping, the wire value
 *  and CONDITION_TYPES's flat validation universe are untouched. */
const CONDITION_TYPE_GROUPS: { label: string; types: (typeof CONDITION_TYPES)[number][] }[] = [
  { label: "Content", types: ["detector", "keyword", "paramRegex"] },
  { label: "Tool", types: ["toolIn", "sourceVerb"] },
  { label: "Trust", types: ["trustBelow"] }
];

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
                    <div key={t}>⚠ no agent has called "{t}" yet — this rule won't fire until one does</div>
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
  errors,
  ruleIdTouched,
  knownTools,
  onChange,
  onRemove,
  onRuleIdTouched
}: {
  rule: BuilderRule;
  index: number;
  errors: BuilderError[];
  ruleIdTouched: boolean;
  knownTools: Set<string> | null;
  onChange: (next: BuilderRule) => void;
  onRemove: () => void;
  onRuleIdTouched: () => void;
}) {
  const setRow = (ri: number, row: BuilderCondition[]) => {
    const conditions = rule.conditions.map((r, i) => (i === ri ? row : r));
    onChange({ ...rule, conditions });
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
              — {ruleIdTouched ? "custom" : "auto from reason"}
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
          const ruleId = ruleIdTouched ? rule.ruleId : slugifyRuleId(reason);
          onChange({ ...rule, reason, ruleId });
        }}
      />
        <div style={{ fontSize: 11.5, color: "var(--text-muted)", lineHeight: 1.5, marginBottom: 10 }}>
          The <strong>reason</strong> is the sentence an operator reads when this rule fires. The{" "}
          <strong>rule ID</strong> is the short identifier stamped on the decision and on every Audit Log row
          for it — keep it stable, because dashboards and exports group by it. It follows the reason until you
          edit it, then stays put so you can reword the reason freely.
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
  onSaved
}: {
  /** RAW global-selector value (Phase 2f: the caller no longer silently resolves "all" — pass it
   *  straight through). Only ever used here to seed `targetNamespace`'s initial value: when concrete,
   *  it pre-fills the target-namespace field; when "all"/"", that field starts empty and Save is gated
   *  until the operator picks a concrete namespace explicitly (see `namespaceReady`). */
  namespace: string;
  onClose: () => void;
  /** Fired after a successful Save & enforce (e.g. so the caller can refresh the policy list). */
  onSaved?: (result: { namespace: string; agentClass: string; version?: number }) => void;
}) {
  const [agentClass, setAgentClass] = useState("");
  const [rules, setRules] = useState<BuilderRule[]>([]);
  const [defaults, setDefaults] = useState<BuilderDefaults>({ decision: "allow", reason: "No builder rule matched" });
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

  // Tool-name autocomplete + unknown-tool warning (Phase 2f): `observedTools` is `null` until a
  // concrete target namespace is chosen AND the fetch resolves — while `null`, ConditionChip/allowlist
  // suppress the unknown-tool warning entirely (there's nothing trustworthy to compare against yet), so
  // the warning never fires against the WRONG namespace's traffic or before one is even picked.
  const [observedTools, setObservedTools] = useState<string[] | null>(null);

  useEffect(() => {
    let live = true;
    const ns = targetNamespace.trim();
    if (!isConcreteNamespace(ns)) {
      setObservedTools(null);
      return;
    }
    setObservedTools(null); // reset while (re)loading — avoid warning against a just-abandoned namespace's data
    Promise.all([
      fetchTopBlocked("30d", ns).catch(() => [] as Array<{ tool_name: string; count: number }>),
      fetchAuditRecords({ namespace: ns, limit: 500 }).catch(() => [] as Array<{ tool_name: string }>)
    ]).then(([topBlocked, audit]) => {
      if (!live) return;
      const names = new Set<string>();
      topBlocked.forEach((t) => t.tool_name && names.add(t.tool_name));
      audit.forEach((r) => r.tool_name && names.add(r.tool_name));
      setObservedTools([...names]);
    });
    return () => {
      live = false;
    };
  }, [targetNamespace]);

  // `null` propagates (suppress the warning) until we've actually looked something up; once looked up
  // (even to an empty result — a fresh namespace with zero traffic) every typed name is checked.
  const knownToolNames = useMemo<Set<string> | null>(() => {
    if (observedTools === null) return null;
    return new Set([...observedTools, ...ALL_CAPABILITY_FRAGMENTS].map((s) => s.toLowerCase()));
  }, [observedTools]);

  // Datalist suggestions (Phase 2f): observed-for-this-namespace tool names first-class, capability
  // fragments as a fallback vocabulary — shown regardless of whether a namespace is chosen yet (fragments
  // alone are still useful hints), sorted for a stable, scannable dropdown.
  const toolSuggestions = useMemo(
    () => [...new Set([...(observedTools ?? []), ...ALL_CAPABILITY_FRAGMENTS])].sort(),
    [observedTools]
  );

  // Intent Allowlist mode (Phase 2c) — kept as SEPARATE state from rules/defaults above (rather than
  // overwriting them on a mode switch) so toggling the mode preserves each mode's own in-progress state:
  // switching to allowlist and back to rules leaves the rule rail exactly as it was, and vice versa.
  const [mode, setMode] = useState<BuilderMode>("rules");
  const [allowlistTools, setAllowlistTools] = useState<string[]>([]);
  const [allowlistRefinements, setAllowlistRefinements] = useState<BuilderAllowlistRefinements>(EMPTY_REFINEMENTS);
  const [allowlistToolInput, setAllowlistToolInput] = useState("");
  const addAllowlistTool = () => {
    const t = allowlistToolInput.trim();
    if (t === "") return;
    setAllowlistTools((ts) => (ts.includes(t) ? ts : [...ts, t]));
    setAllowlistToolInput("");
  };
  const removeAllowlistTool = (t: string) => setAllowlistTools((ts) => ts.filter((x) => x !== t));

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
      ...(mode === "allowlist" ? { allowlist: { tools: allowlistTools, refinements: allowlistRefinements } } : {})
    }),
    [scope, rules, defaults, mode, allowlistTools, allowlistRefinements]
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
  const dryRunStale = dryRunRego !== null && dryRunRego !== compiled.rego;
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

                <datalist id="builder-known-tools">
                  {toolSuggestions.map((t) => (
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
                    <button
                      type="button"
                      data-testid="builder-allowlist-tool-add"
                      onClick={addAllowlistTool}
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
                        color: "#2DDAB8",
                        cursor: "pointer"
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
                        ⚠ no agent has called "{allowlistToolInput.trim()}" yet — this entry won't match until one does
                      </div>
                    )}
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 8 }}>
                    {allowlistTools.map((t) => (
                      <span
                        key={t}
                        data-testid={`builder-allowlist-tool-chip-${t}`}
                        className="mono"
                        style={{
                          display: "inline-flex",
                          alignItems: "center",
                          gap: 6,
                          fontSize: 11.5,
                          padding: "3px 8px",
                          borderRadius: 999,
                          background: "var(--bg-elevated)",
                          border: "1px solid var(--border)"
                        }}
                      >
                        {t}
                        <button
                          type="button"
                          data-testid={`builder-allowlist-tool-remove-${t}`}
                          className="icon-btn"
                          style={{ width: 14, height: 14 }}
                          title={`Remove ${t}`}
                          onClick={() => removeAllowlistTool(t)}
                        >
                          <X size={10} />
                        </button>
                      </span>
                    ))}
                  </div>
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
                    title={!namespaceReady ? "Pick a concrete target namespace first" : !scopeReady ? "Set an agent class first" : undefined}
                    onClick={runDryRun}
                  >
                    {dryRunLoading ? "Dry-Running..." : "Run dry-run"}
                  </KitButton>
                  <KitButton
                    variant="primary"
                    icon={Check}
                    disabled={!canSave}
                    data-testid="builder-save-btn"
                    title={
                      !namespaceReady
                        ? "Pick a concrete target namespace first — the global scope is All namespaces"
                        : !scopeReady
                        ? "Set an agent class first"
                        : hasErrors
                        ? "Fix compile errors first"
                        : dryRunResult?.valid !== true
                        ? "Run a valid dry-run of the current graph first"
                        : dryRunStale
                        ? "The graph changed since the last dry-run — re-run it"
                        : undefined
                    }
                    onClick={saveAndEnforce}
                  >
                    {saving ? "Saving..." : "Save & enforce"}
                  </KitButton>
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
                    Replayed {(dryRunResult.total_records_checked ?? 0).toLocaleString()} recent real call
                    {(dryRunResult.total_records_checked ?? 0) === 1 ? "" : "s"} ·{" "}
                    <strong style={{ color: (dryRunResult.newly_blocked ?? 0) > 0 ? "var(--escalate)" : "var(--allow)" }}>
                      {dryRunResult.newly_blocked ?? 0} newly blocked
                    </strong>
                  </div>
                  {(dryRunResult.newly_blocked_samples?.length ?? 0) > 0 && (
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
