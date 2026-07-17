import "../lib/monaco"; // SLIM-MONACO: bundle Monaco locally (no cdn.jsdelivr fetch) — must precede <Editor>
import Editor from "@monaco-editor/react";
import { registerRego } from "../lib/monaco-rego";
import { composerRego } from "../lib/composerRego";
import {
  AlertCircle,
  ArrowUpCircle,
  Check,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Copy,
  FileCode,
  FlaskConical,
  Info,
  Play,
  Plus,
  Radar,
  RotateCcw,
  Trash2,
  TriangleAlert,
  X
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  apiGet,
  apiSend,
  applyPolicy,
  deletePolicy,
  dismissIntentDraft,
  dryRunPolicy,
  fetchIntentDraft,
  fetchIntentDrafts,
  fetchSettings,
  gcIntentDrafts,
  type IntentDraftPage
} from "../api/client";
import { baseClassOfOverlay, isReservedScope, isRemediationOverlayClass, overlayDisplayLabel } from "../lib/reservedScope";
import { ApplyResultPanel, type ApplyResult } from "../components/common/ApplyResultPanel";
import { DecisionBadge, type Decision } from "../components/common/DecisionBadge";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { PolicyHierarchy } from "../components/PolicyHierarchy";
import { useApi, invalidateApiCache } from "../hooks/useApi";
import { timeAgo } from "../lib/d3-helpers";
import { fmtDateTime } from "../lib/format";
import { useApp } from "../store/AppContext";

type TargetType = "workload" | "class" | "namespace";

type Policy = {
  id?: string;
  target_type?: TargetType;
  target?: string;
  namespace?: string;
  agent_class?: string;
  current_version?: number;
  rego_length?: number;
  mode?: "block" | "audit" | "escalate";
  enforcement_mode?: "block" | "audit" | "escalate"; // M4: the real API field — `mode` was never populated
  matches?: number;
  last_applied?: string | null;  // FIX-2: last time a version was applied (ISO) — card shows "applied {ago}"
};

type PolicyDetail = {
  namespace?: string;
  agent_class?: string;
  rego_source?: string;
  version?: number;
};

type PolicyVersion = {
  version: number;
  saved_by?: string;
  saved_at: string;
  rego_source?: string; // MUT-VERSION: the version's own rego, for read-only historical inspection
};

type Deployment = {
  name: string;
  namespace: string;
  agent_class: string;
  replicas?: number;
};

type DryRunFlip = { tool_name?: string; was?: string; now?: string; rule_id?: string };
type DryRunResult = {
  total_records_checked?: number;
  would_block?: number;
  would_allow?: number;
  would_escalate?: number;
  // The decision FLIPS — currently-allowed calls this candidate would newly block (the number that matters).
  newly_blocked?: number;
  newly_allowed?: number;
  newly_blocked_samples?: DryRunFlip[];
  block_rate_pct?: number;
  truncated?: boolean;
  scope?: { namespace?: string; agent_class?: string | null };
  recommendation?: string;
};

// feat/attack-graph: a non-enforcing intent-policy DRAFT surfaced for review/hand-off.
// This surface is READ + hand-off ONLY — it never applies/creates. The operator applies
// via the EXISTING gated create/apply flow (PolicySheet → applyPolicy, F-40/F-51/R2 server-enforced).
type DraftSource = {
  source_framework?: string | null;
  source_control_id?: string | null;
  source_control_name?: string | null;
};

type IntentDraftSummary = DraftSource & {
  draft_id: string;
  ns: string;
  cls: string;
  // COMP-GEN-01: for a compliance-remediation draft, `cls` is the compound persistence overlay key
  // ("<class>__remediation__") — `affected_class` carries the real class for display.
  affected_class?: string | null;
  enabled: string[];
  covered_count: number;
  total: number;
  created_at: string;
  expires_at?: string;
};

type IntentDraftDetail = DraftSource & {
  draft_id: string;
  ns: string;
  cls: string;
  affected_class?: string | null;
  rego: string;
  enabled: string[];
  covered_count: number;
  total: number;
  enforcement: string;
};

// COMP-GEN-01: the class name to SHOW the operator for a draft row — the real affected class (never the
// compound "<class>__remediation__" persistence key) for a compliance-remediation draft, else `cls` unchanged.
function draftDisplayClass(d: { cls: string; affected_class?: string | null }): string {
  return d.affected_class || baseClassOfOverlay(d.cls);
}

// F2: human label for a generated draft's provenance — "OWASP LLM · LLM07 System Prompt Leakage" or,
// for a capability defense, "Source Capability · write/delete on Elasticsearch".
const FRAMEWORK_LABEL: Record<string, string> = { atlas: "MITRE ATLAS", owasp: "OWASP LLM", capability: "Source Capability" };
function draftSourceLabel(d: DraftSource): string | null {
  if (!d.source_control_id) return null;
  const fw = d.source_framework ? FRAMEWORK_LABEL[d.source_framework] ?? d.source_framework : "Compliance";
  // A capability draft's control_id is "source:verb" — the human name carries the readable form.
  if (d.source_framework === "capability") {
    return `from ${fw} · ${d.source_control_name ?? d.source_control_id}`;
  }
  return `from ${fw} · ${d.source_control_id}${d.source_control_name ? ` ${d.source_control_name}` : ""}`;
}

// ---- Part A: drafts triage-inbox helpers -----------------------------------------------------------------
// A3: mirror synthetic.py's naming so test/e2e drafts are default-hidden (server keeps them for the 24h test TTL).
const TEST_DRAFT_RE = /^(wave\d+e2e|e2e-intent|effecttest|smoke-|canary-|probe-|evtrace-|allowlist-probe|policy-tester|scorer)/i;
const isTestDraft = (cls: string): boolean => TEST_DRAFT_RE.test(cls);

// A1: which lifecycle source produced the draft — compliance gaps carry a control tag; everything else is the
// Attack-Graph intent builder (a "manual/other" bucket is reserved for future hand-authored drafts).
type DraftSourceKind = "attack-graph" | "compliance" | "capability" | "manual";
function draftSourceKind(d: DraftSource): DraftSourceKind {
  if (d.source_framework === "capability") return "capability";
  return d.source_control_id ? "compliance" : "attack-graph";
}
const SOURCE_GROUPS: Array<{ kind: DraftSourceKind; title: string; sub: string }> = [
  { kind: "capability", title: "From Source Capability", sub: "Least-privilege defenses for undefended source verbs" },
  { kind: "compliance", title: "From Compliance gaps", sub: "Remediation drafts tagged to a framework control" },
  { kind: "attack-graph", title: "From Attack Graph", sub: "Intended-behaviour allowlists from observed tool use" },
  { kind: "manual", title: "Manual / other", sub: "Hand-authored drafts" }
];

// A2: lifecycle status pill. Superseded = an enforcing policy already exists for the class (applying = change-to-
// live, not new). Stale = expiring within a day. Reviewed = the operator has opened it this session. Else New.
type DraftStatus = "New" | "Reviewed" | "Superseded" | "Stale";
const STATUS_STYLE: Record<DraftStatus, { bg: string; color: string }> = {
  New: { bg: "#0d2a1c", color: "#6ee7b7" },
  Reviewed: { bg: "#1c2733", color: "#8ab4f8" },
  Superseded: { bg: "#2a230d", color: "#f2d488" },
  Stale: { bg: "#2a1616", color: "#f0a3a3" }
};
function draftStatus(d: IntentDraftSummary, enforcingVersion: number | undefined, reviewed: boolean): DraftStatus {
  if (enforcingVersion !== undefined) return "Superseded";
  if (d.expires_at) {
    const t = Date.parse(d.expires_at);
    if (!Number.isNaN(t) && t - Date.now() < 24 * 3600 * 1000) return "Stale";
  }
  return reviewed ? "Reviewed" : "New";
}

const PRIORITY: Record<TargetType, { rank: number; label: string; color: string }> = {
  workload: { rank: 1, label: "highest", color: "#00e5a0" },
  class: { rank: 2, label: "medium", color: "#2ddab8" },
  namespace: { rank: 3, label: "lowest", color: "#a0a0a0" }
};

const TIERS: Array<{ type: TargetType; title: string; sub: string }> = [
  { type: "workload", title: "Workload Policies", sub: "Specific deployments · highest priority" },
  { type: "class", title: "Agent-Class Policies", sub: "Groups of agents by label · medium priority" },
  { type: "namespace", title: "Namespace Policies", sub: "Catch-all fallback · lowest priority" }
];

const MODE_DECISION: Record<NonNullable<Policy["mode"]>, Decision> = {
  block: "block",
  audit: "audit",
  escalate: "escalate"
};

/**
 * Defense-in-depth: the API now returns target_type, but default it to "class" when an
 * agent_class is set and the field is absent — so the catalog never drops a class policy
 * (the seeded default:customer-support) into "no policies configured".
 */
function withTargetType(list: Policy[]): Policy[] {
  return list.map((p) => ({
    ...p,
    target_type: p.target_type ?? (p.agent_class ? "class" : p.target_type)
  }));
}

function PriorityBars({ tier }: { tier: TargetType }) {
  const p = PRIORITY[tier];
  return (
    <span style={{ display: "inline-flex", gap: 3, alignItems: "flex-end", height: 14 }}>
      {[1, 2, 3].map((r) => (
        <i
          key={r}
          style={{
            width: 4,
            borderRadius: 1,
            height: [14, 11, 8][r - 1],
            background: p.rank === r ? p.color : "var(--text-muted)",
            display: "inline-block"
          }}
        />
      ))}
    </span>
  );
}

function PriorityBadge({ tier }: { tier: TargetType }) {
  const p = PRIORITY[tier];
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 8,
        marginTop: 14,
        paddingTop: 12,
        borderTop: "1px solid var(--border)",
        fontSize: 12
      }}
    >
      <PriorityBars tier={tier} />
      <span style={{ color: p.color, fontWeight: 600 }}>
        {tier === "class" ? "Agent-class" : tier === "workload" ? "Workload" : "Namespace"} policy
      </span>
      <span className="muted">· {p.label} priority</span>
    </div>
  );
}

function RadioPill({
  active,
  label,
  onClick,
  disabled = false,
  title
}: {
  active: boolean;
  label: string;
  onClick: () => void;
  disabled?: boolean;
  title?: string;
}) {
  return (
    <button
      className={`tab-kit${active ? " active" : ""}`}
      onClick={disabled ? undefined : onClick}
      disabled={disabled}
      title={title}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 7,
        textTransform: "capitalize",
        opacity: disabled ? 0.45 : 1,
        cursor: disabled ? "not-allowed" : "pointer"
      }}
    >
      <span
        style={{
          width: 12,
          height: 12,
          borderRadius: 99,
          border: `1.5px solid ${active ? "var(--accent)" : "var(--text-muted)"}`,
          position: "relative",
          display: "inline-block"
        }}
      >
        {active && (
          <span
            style={{ position: "absolute", inset: 2, borderRadius: 99, background: "var(--accent)" }}
          />
        )}
      </span>
      {label}
    </button>
  );
}

function PolicyTarget({
  policy,
  deployments,
  onAgentClassChange
}: {
  policy: Policy;
  deployments: Deployment[];
  // Q2: lift the typed class to the parent's `selected` so Apply/create target the manually-entered class.
  onAgentClassChange?: (cls: string) => void;
}) {
  const initial = policy.target_type ?? "class";
  const [mode, setMode] = useState<TargetType>(initial);
  // Q2: the class field is now CONTROLLED by the parent (`policy.agent_class`) — no local copy to drift.
  const agentClass = policy.agent_class ?? "";

  useEffect(() => {
    setMode(policy.target_type ?? "class");
  }, [policy]);

  const matches = deployments.filter((d) => d.agent_class === agentClass);

  return (
    <div>
      <div className="section-label">Target by</div>
      <div className="tabs-kit" style={{ marginBottom: 16 }}>
        <RadioPill active={mode === "class"} label="Agent Class" onClick={() => setMode("class")} />
        {/* MUT-WORKLOAD: the guided composer's keyword-block model matches on `input.agent.agent_class`,
            so it can only author AGENT-CLASS policies. Workload/namespace targets are real (the resolver
            + raw editor support them) but the guided rego would never match them — offering them here
            (with a dead Name input) produced a policy that silently didn't enforce. Gate them to the raw
            editor instead of shipping a lie. */}
        <RadioPill
          active={mode === "workload"}
          label="Workload"
          disabled
          title="Guided mode targets agent classes. Use 'New policy (raw rego)' to scope a policy to a workload."
          onClick={() => {}}
        />
        <RadioPill
          active={mode === "namespace"}
          label="Namespace"
          disabled
          title="Guided mode targets agent classes. Use 'New policy (raw rego)' to scope a policy to a namespace."
          onClick={() => {}}
        />
      </div>

      {mode === "class" && (
        <div>
          <div className="field-row">
            <label className="field-label">Agent Class · recommended</label>
            {/* Q2: a REAL free-text input — you can author a policy for ANY class name, including one with no running
                labeled deployment yet (the fake select-trigger dead-ended when nothing was auto-discovered). */}
            <input
              className="input"
              type="text"
              value={agentClass}
              onChange={(e) => onAgentClassChange?.(e.target.value.replace(/\s+/g, ""))}
              placeholder="e.g. customer-support"
              spellCheck={false}
              autoCapitalize="none"
              data-testid="composer-agent-class-input"
            />
          </div>
          <div className="panel-sub" style={{ marginBottom: 8 }}>
            Applies to all deployments labeled
          </div>
          <span
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: 12,
              color: "#00e5a0",
              background: "#00e5a012",
              border: "1px solid #00e5a028",
              borderRadius: 6,
              padding: "6px 10px",
              display: "inline-block"
            }}
          >
            norviq.io/agent-class={agentClass}
          </span>
          <div style={{ marginTop: 14 }}>
            <div
              className="muted"
              style={{ fontSize: 11, display: "flex", alignItems: "center", gap: 6 }}
            >
              <Radar size={13} /> Matching deployments · auto-discovered
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 10 }}>
              {matches.length === 0 ? (
                <span className="muted" style={{ fontSize: 12 }} data-testid="composer-no-deployments">
                  {agentClass
                    ? `No deployments labeled norviq.io/agent-class=${agentClass} yet — that's fine. Author the policy now; it enforces the moment an agent identifies as this class. Label a Deployment with norviq.io/agent-class=${agentClass} to auto-discover it here.`
                    : "Type an agent-class name above to target it — a running labeled deployment is not required to author a policy."}
                </span>
              ) : (
                matches.map((d) => (
                  <span
                    key={d.name}
                    style={{
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6,
                      fontFamily: "var(--font-mono)",
                      fontSize: 12,
                      background: "var(--bg-surface)",
                      border: "1px solid var(--border)",
                      borderRadius: 99,
                      padding: "4px 11px"
                    }}
                  >
                    <span
                      style={{
                        width: 6,
                        height: 6,
                        borderRadius: 99,
                        background: "#00e5a0",
                        boxShadow: "0 0 6px #00e5a0"
                      }}
                    />
                    {d.name}
                  </span>
                ))
              )}
            </div>
          </div>
          <PriorityBadge tier="class" />
        </div>
      )}

      {mode === "workload" && (
        <div>
          <div className="field-row">
            <label className="field-label">Kind</label>
            <div className="input select-trigger">
              <span>Deployment</span>
              <ChevronDown />
            </div>
          </div>
          <div className="field-row">
            <label className="field-label">Name</label>
            {/* Read-only context for an existing workload policy — the guided sheet no longer CREATES
                workload targets (see the gated radio), so this is never an authoring input. */}
            <div className="input select-trigger">
              <span>{policy.target ?? "—"}</span>
            </div>
          </div>
          <div className="field-row">
            <label className="field-label">Namespace</label>
            <div className="input select-trigger">
              <span>{policy.namespace ?? "—"}</span>
            </div>
          </div>
          <div
            style={{
              fontSize: 12,
              color: "var(--text-secondary)",
              display: "flex",
              alignItems: "center",
              gap: 7,
              marginTop: 4
            }}
          >
            <ArrowUpCircle size={14} style={{ color: "#2ddab8" }} />
            Overrides any agent-class policy for this workload
          </div>
          <PriorityBadge tier="workload" />
        </div>
      )}

      {mode === "namespace" && (
        <div>
          <div className="field-row">
            <label className="field-label">Namespace</label>
            <div className="input select-trigger">
              <span>{policy.namespace ?? "—"}</span>
              <ChevronDown />
            </div>
          </div>
          <div
            style={{
              display: "flex",
              gap: 10,
              alignItems: "flex-start",
              background: "#ffb02010",
              border: "1px solid #ffb02030",
              borderRadius: "var(--radius-md)",
              padding: "11px 13px",
              marginTop: 6
            }}
          >
            <TriangleAlert size={16} style={{ color: "#ffb020", flex: "none", marginTop: 1 }} />
            <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.5, color: "#ffcf7a" }}>
              Applies to <strong>ALL</strong> norviq-enabled workloads in this namespace. Use
              agent-class for precision.
            </p>
          </div>
          <PriorityBadge tier="namespace" />
        </div>
      )}
    </div>
  );
}

export function PolicySheet({
  policy,
  deployments,
  applyMode = "enforce",
  onClose,
  onApply,
  onAgentClassChange,
  onEditAsRawRego
}: {
  policy: Policy;
  deployments: Deployment[];
  applyMode?: "enforce" | "dry_run_only";
  onClose: () => void;
  // Q2: `create` carries a generated rego for a brand-new class (apply requires a pre-saved policy).
  onApply: (mode: Policy["mode"], create?: { rego: string }) => void;
  onAgentClassChange?: (cls: string) => void;
  // UX-CREATE bridge: hand the composer's GENERATED rego to the raw editor so a guided draft can graduate
  // into hand-authored rego without restarting. One-way (guided → raw); the two audiences stay distinct.
  onEditAsRawRego?: (seed: { namespace: string; agent_class: string; mode: NonNullable<Policy["mode"]>; rego: string }) => void;
}) {
  const [enforcement, setEnforcement] = useState<NonNullable<Policy["mode"]>>(policy.mode ?? policy.enforcement_mode ?? "block");
  const [paramsOpen, setParamsOpen] = useState(false);
  const [dryRun, setDryRun] = useState(false);
  const [reviewing, setReviewing] = useState(false); // F-50: confirm + diff step before the write
  const dryRunOnly = applyMode === "dry_run_only";
  // F-50: a brand-new policy has no prior version to overwrite; an existing one shows a diff of what changes.
  const isNew = policy.current_version == null;
  const currentMode = policy.mode ?? policy.enforcement_mode ?? "block";
  const enforcementChanged = !isNew && currentMode !== enforcement;
  // Block keywords ARE enforced: on Apply they generate the block policy via composerRego (below). The
  // former rate-limit / trust-threshold inputs were preview-only AND redundant with the namespace-scoped
  // controls in Target Settings / Settings, so they were removed rather than shipped as dead inputs.
  const [keywords, setKeywords] = useState("secret,token,password");
  const keywordList = keywords.split(",").map((k) => k.trim()).filter(Boolean);
  const yamlPreview = `apiVersion: norviq.io/v1
kind: NrvqPolicy
spec:
  targetType: ${policy.target_type ?? "class"}
  target: ${policy.target ?? policy.agent_class ?? ""}
  enforcement: ${enforcement}
  keywords: [${keywordList.join(", ")}]`;

  return (
    <>
      <div className="sheet-overlay" onClick={onClose} />
      <div className="sheet-kit">
        <div className="sheet-head">
          <div>
            <div className="sheet-title">Configure Policy</div>
            <div className="panel-sub mono" style={{ marginTop: 3 }}>
              {policy.target ?? policy.agent_class ?? "new"} · v{policy.current_version ?? 1}
            </div>
          </div>
          <button className="icon-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <PolicyTarget policy={policy} deployments={deployments} onAgentClassChange={onAgentClassChange} />

        <div className="section-label" style={{ marginTop: 20 }}>
          Enforcement Mode
        </div>
        <div className="tabs-kit" style={{ display: "flex", marginBottom: 6 }}>
          {(["block", "audit", "escalate"] as const).map((m) => (
            <RadioPill
              key={m}
              active={enforcement === m}
              label={m}
              onClick={() => setEnforcement(m)}
            />
          ))}
        </div>

        <div
          className="section-label collapse-head"
          style={{ marginTop: 18 }}
          onClick={() => setParamsOpen((v) => !v)}
        >
          <span>Block Keywords</span>
          {paramsOpen ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
        </div>
        {paramsOpen && (
          <div style={{ marginTop: 8 }}>
            <div className="field-row">
              <label className="field-label">Block keywords</label>
              <input className="input mono" value={keywords} onChange={(e) => setKeywords(e.target.value)} />
            </div>
            <div className="panel-sub" style={{ marginTop: 6, color: "var(--text-muted)" }}>
              Applied — these generate the block policy below. Rate limit and trust threshold are
              namespace-wide and live in Target Settings.
            </div>
          </div>
        )}

        <div className="section-label" style={{ marginTop: 18 }}>
          Generated YAML
        </div>
        <div className="editor" style={{ marginBottom: 10 }}>
          <div className="editor-head">
            <FileCode size={14} /> NrvqPolicy
            <span style={{ marginLeft: "auto", color: "var(--text-muted)" }}>read-only</span>
          </div>
          <div className="editor-body">
            <div className="editor-code" style={{ paddingLeft: 16 }}>
              <pre style={{ margin: 0, fontFamily: "var(--font-mono)" }}>{yamlPreview}</pre>
            </div>
          </div>
        </div>

        {dryRun && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              fontSize: 12.5,
              color: "#ffb020",
              background: "#ffb02010",
              border: "1px solid #ffb02030",
              borderRadius: "var(--radius-md)",
              padding: "9px 12px",
              marginBottom: 10
            }}
          >
            <Info size={14} /> Run a real dry-run from the editor’s <strong style={{ color: "#ffcf7a" }}>Dry-Run</strong>{" "}
            to evaluate this policy against recent traffic (this sheet shows the generated YAML only).
          </div>
        )}

        {/* F-51: a dry-run-only namespace disables Apply (the API also rejects it). */}
        {dryRunOnly && (
          <div
            style={{
              fontSize: 12.5, color: "#ffb020", background: "#ffb02010", border: "1px solid #ffb02030",
              borderRadius: "var(--radius-md)", padding: "9px 12px", marginBottom: 10
            }}
          >
            This namespace is <strong>dry-run-only</strong> — policy applies are disabled (server-enforced). Dry-Run is
            still available. An admin can re-enable enforcement in Settings → Apply Governance.
          </div>
        )}

        {/* F-50: review + confirm the change before the write — no silent one-click overwrite of a live policy. */}
        {reviewing && !dryRunOnly && (
          <div
            data-testid="apply-review"
            style={{
              fontSize: 12.5, border: "1px solid var(--border, #2a2a2a)", borderRadius: "var(--radius-md)",
              padding: "10px 12px", marginBottom: 10, background: "var(--bg-elevated, #161616)"
            }}
          >
            <div style={{ fontWeight: 600, marginBottom: 6 }}>
              {isNew ? "Apply new policy" : "Review changes before applying"}
            </div>
            {isNew ? (
              <div className="panel-sub">
                New policy for <code>{policy.target ?? policy.agent_class}</code> — no existing version to overwrite.
              </div>
            ) : (
              <div style={{ display: "grid", gridTemplateColumns: "auto 1fr", gap: "4px 12px" }}>
                <span className="panel-sub">Target</span>
                <span className="mono">{policy.target ?? policy.agent_class} (v{policy.current_version})</span>
                <span className="panel-sub">Enforcement</span>
                <span className="mono">
                  {enforcementChanged ? (
                    <>
                      <span style={{ color: "#ff3b5c", textDecoration: "line-through" }}>{currentMode}</span>{" → "}
                      <span style={{ color: "#00e5a0" }}>{enforcement}</span>
                    </>
                  ) : (
                    <span>{enforcement} (unchanged)</span>
                  )}
                </span>
              </div>
            )}
          </div>
        )}

        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          {reviewing && !dryRunOnly ? (
            <>
              <KitButton
                variant="primary"
                icon={Check}
                disabled={isNew && !(policy.agent_class ?? "").trim()}
                onClick={() =>
                  onApply(
                    enforcement,
                    // Q2: a brand-new manual class has no saved policy for `apply` to stamp — generate an
                    // enforcing keyword-block rego and CREATE it (create() enforces on the read path).
                    isNew
                      ? { rego: composerRego(policy.agent_class ?? policy.target ?? "", enforcement, keywordList) }
                      : undefined
                  )
                }
              >
                Confirm Apply
              </KitButton>
              <KitButton variant="ghost" onClick={() => setReviewing(false)}>
                Back
              </KitButton>
            </>
          ) : (
            <KitButton variant="primary" icon={Check} disabled={dryRunOnly} onClick={() => setReviewing(true)}>
              Apply
            </KitButton>
          )}
          <KitButton variant="outline" icon={Play} onClick={() => setDryRun(true)}>
            Dry-Run
          </KitButton>
          <KitButton variant="outline" icon={Copy} onClick={() => navigator.clipboard.writeText(yamlPreview)}>
            Copy YAML
          </KitButton>
          {/* UX-CREATE bridge: only for a brand-new guided draft (isNew) with a class to target — hands the
              generated rego to the raw editor. Hidden when editing an existing policy (nothing to graduate). */}
          {isNew && onEditAsRawRego && (
            <KitButton
              variant="outline"
              icon={FileCode}
              disabled={!(policy.agent_class || policy.target)}
              title="Open the generated rego in the raw editor to hand-tune it"
              onClick={() =>
                onEditAsRawRego({
                  namespace: policy.namespace ?? "default",
                  agent_class: policy.agent_class ?? policy.target ?? "",
                  mode: enforcement,
                  rego: composerRego(policy.agent_class ?? policy.target ?? "", enforcement, keywordList)
                })
              }
            >
              Edit as raw rego
            </KitButton>
          )}
          <KitButton variant="ghost" onClick={onClose}>
            Cancel
          </KitButton>
        </div>
      </div>
    </>
  );
}

// color-consistency #6 decision (b): DRY-RUN drafts use a NEUTRAL grey identity, not audit-purple. The
// audit-purple (--audit #7c5cfc) is reserved for genuine audit decisions + agent nodes; overloading it for a
// "draft/dry-run" status was off-palette. The FlaskConical icon + "DRY-RUN" text carry the meaning; the colour
// is neutral grey (the interactive "Review" affordance inside the panel uses the teal --accent).
const DRAFT_ACCENT = "#8a8a8a";
const FAINT = "#6e6e76"; // group-header label (portal-grey, per the palette law)

function DryRunBadge() {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        fontFamily: "var(--font-mono)",
        fontSize: 10.5,
        fontWeight: 700,
        letterSpacing: ".06em",
        textTransform: "uppercase",
        color: DRAFT_ACCENT,
        background: `${DRAFT_ACCENT}18`,
        border: `1px solid ${DRAFT_ACCENT}55`,
        borderRadius: 5,
        padding: "2px 7px"
      }}
    >
      <FlaskConical size={11} /> Dry-run
    </span>
  );
}

function Chip({ label }: { label: string }) {
  return (
    <span
      style={{
        fontFamily: "var(--font-mono)",
        fontSize: 11,
        color: "var(--text-secondary)",
        background: "var(--bg-surface)",
        border: "1px solid var(--border)",
        borderRadius: 99,
        padding: "2px 9px"
      }}
    >
      {label}
    </span>
  );
}

/**
 * feat/attack-graph — Intent DRAFTS surface.
 * READ + hand-off ONLY. Lists non-enforcing dry-run drafts and, for a deep-linked draft,
 * shows the generated rego read-only with a "Review & apply" that hands the draft into the
 * EXISTING gated create/apply flow (onReview). Nothing here applies or creates on its own.
 */
function IntentDraftsPanel({
  page,
  enforcingByClass,
  reviewedIds,
  filter,
  setFilter,
  showTest,
  setShowTest,
  onViewAll,
  onDismissOne,
  onClearExpired,
  loading,
  highlightId,
  detail,
  detailLoading,
  onRefresh,
  onDismiss,
  onReview,
  onSelect
}: {
  page: IntentDraftPage;
  enforcingByClass: Record<string, number>;
  reviewedIds: Set<string>;
  filter: DraftStatus | "All";
  setFilter: (f: DraftStatus | "All") => void;
  showTest: boolean;
  setShowTest: (v: boolean) => void;
  onViewAll: () => void;
  onDismissOne: (draftId: string) => void;
  onClearExpired: () => void;
  loading: boolean;
  highlightId: string | null;
  detail: IntentDraftDetail | null;
  detailLoading: boolean;
  onRefresh: () => void;
  onDismiss: () => void;
  onReview: (d: IntentDraftDetail) => void;
  onSelect: (draftId: string) => void;
}) {
  const highlightRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    // Scroll to the highlighted draft ONCE per id — align its TOP (not center), so when the tall rego
    // detail loads and the row grows, its header ("class · NEW") is never pushed up under the topbar.
    // scrollMarginTop on the row keeps it clear of the sticky chrome. (Re-firing on `detail` caused the
    // clipped-title bug: the second scroll centered a now-tall card, hiding its header.)
    if (highlightId && typeof highlightRef.current?.scrollIntoView === "function") {
      highlightRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [highlightId]);

  const all = page.drafts;
  const hiddenTestCount = all.filter((d) => isTestDraft(d.cls)).length;
  const statusOf = (d: IntentDraftSummary): DraftStatus =>
    draftStatus(d, enforcingByClass[`${d.ns}/${d.cls}`], reviewedIds.has(d.draft_id));
  const visible = all
    .filter((d) => showTest || !isTestDraft(d.cls))                        // A3: default-hide test drafts
    .filter((d) => filter === "All" || statusOf(d) === filter);           // A5: status filter
  // A1: group by lifecycle source (compliance gaps / attack graph / manual), newest-first within each.
  const groups = SOURCE_GROUPS.map((g) => ({
    ...g,
    items: visible.filter((d) => draftSourceKind(d) === g.kind)
  })).filter((g) => g.items.length > 0);
  const remaining = Math.max(0, page.total - page.returned);              // B6: undisplayed count

  const renderRow = (d: IntentDraftSummary) => {
    const isActive = d.draft_id === highlightId;
    const enforcingVersion = enforcingByClass[`${d.ns}/${d.cls}`];
    const status = statusOf(d);
    const st = STATUS_STYLE[status];
    return (
            <div
              key={d.draft_id}
              ref={isActive ? highlightRef : undefined}
              data-testid={`intent-draft-${d.draft_id}`}
              style={{
                border: `1px solid ${isActive ? DRAFT_ACCENT : "var(--border)"}`,
                borderRadius: "var(--radius-md)",
                padding: "12px 14px",
                background: isActive ? `${DRAFT_ACCENT}0e` : "var(--bg-elevated, #161616)",
                scrollMarginTop: 16  // keep the scrolled-to header clear of the topbar
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              {/* P1: the row header is a real button — click (or Enter/Space) opens the draft's review inline. */}
              <button
                type="button"
                onClick={() => onSelect(d.draft_id)}
                aria-expanded={isActive}
                data-testid={`intent-draft-open-${d.draft_id}`}
                style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap", flex: 1, background: "transparent", border: 0, padding: 0, margin: 0, cursor: "pointer", color: "inherit", font: "inherit", textAlign: "left" }}
              >
                <ChevronRight size={14} style={{ color: "var(--text-muted)", transform: isActive ? "rotate(90deg)" : "none", transition: "transform 0.15s", flex: "none" }} />
                {/* COMP-GEN-01: show the REAL affected class, never the "<class>__remediation__" persistence key. */}
                <span className="mono" style={{ fontWeight: 600 }} title={d.cls}>
                  {draftDisplayClass(d)}
                </span>
                <span className="mono muted" style={{ fontSize: 11.5 }}>
                  {d.ns}
                </span>
                {/* A2: lifecycle status pill */}
                <span data-testid={`intent-draft-status-${d.draft_id}`} style={{ fontSize: 9.5, fontWeight: 800, letterSpacing: "0.04em", padding: "2px 8px", borderRadius: 999, background: st.bg, color: st.color, textTransform: "uppercase" }}>
                  {status}
                </span>
                <div style={{ flex: 1 }} />
                <span className="muted" style={{ fontSize: 11.5 }}>
                  coverage {d.covered_count}/{d.total}
                </span>
                <span className="muted" style={{ fontSize: 11.5 }}>
                  {fmtDateTime(d.created_at)}
                </span>
                <span className="muted" style={{ fontSize: 11, color: "var(--accent, #00e5a0)" }}>{isActive ? "Hide" : "Review"}</span>
              </button>
              {/* B7: per-draft dismiss (non-enforcing only) */}
              <button className="icon-btn" aria-label={`Dismiss draft ${draftDisplayClass(d)}`} data-testid={`intent-draft-dismiss-${d.draft_id}`} onClick={() => onDismissOne(d.draft_id)} style={{ flex: "none" }}>
                <X size={14} />
              </button>
              </div>

              {/* A2: target linkage — new-policy vs change-to-live. COMP-GEN-01: a remediation draft applies
                  as an ADDITIVE overlay ON the real class, never a replacement of its base policy. */}
              <div data-testid={`intent-draft-target-${d.draft_id}`} style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 6 }}>
                {d.cls !== draftDisplayClass(d)
                  ? `would apply as a compliance overlay on agent-class ${draftDisplayClass(d)} — adds a block, never replaces its base policy`
                  : enforcingVersion !== undefined
                  ? `would apply to agent-class ${d.cls} — currently v${enforcingVersion} enforcing`
                  : `would apply to agent-class ${d.cls} — no live policy yet (new)`}
              </div>

              {/* F2: compliance provenance — traceable back to the originating framework + control. */}
              {draftSourceLabel(d) && (
                <div
                  data-testid={`intent-draft-source-${d.draft_id}`}
                  style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4, fontStyle: "italic" }}
                >
                  {draftSourceLabel(d)}
                </div>
              )}

              {d.enabled.length > 0 && (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
                  {d.enabled.map((c) => (
                    <Chip key={c} label={c} />
                  ))}
                </div>
              )}

              {isActive && (
                <div style={{ marginTop: 12 }}>
                  {detailLoading && (
                    <div className="muted" style={{ fontSize: 12 }}>
                      Loading draft…
                    </div>
                  )}
                  {detail && (
                    <>
                      {/* F2: provenance in the review header — traceable to the originating control. */}
                      {draftSourceLabel(detail) && (
                        <div
                          data-testid="intent-draft-source-header"
                          style={{ fontSize: 11.5, color: "var(--text-muted)", marginBottom: 8, fontStyle: "italic" }}
                        >
                          Remediation {draftSourceLabel(detail)}
                        </div>
                      )}
                      <div className="section-label" style={{ marginTop: 0 }}>
                        Generated Rego · read-only
                      </div>
                      <div className="editor" style={{ marginBottom: 10 }}>
                        <div className="editor-head">
                          <FileCode size={14} /> {draftDisplayClass(detail)}.rego
                          <span style={{ marginLeft: "auto", color: "var(--text-muted)" }}>
                            enforcement: {detail.enforcement}
                          </span>
                        </div>
                        <div className="editor-body">
                          <div className="editor-code" style={{ paddingLeft: 16 }}>
                            <pre
                              data-testid="intent-draft-rego"
                              className="mono"
                              style={{ margin: 0, maxHeight: 260, overflow: "auto", fontSize: 12 }}
                            >
                              {detail.rego}
                            </pre>
                          </div>
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        {/* Hands the draft into the EXISTING gated create/apply UI, pre-filled.
                            It does NOT apply — the operator confirms + applies there. */}
                        <KitButton
                          variant="primary"
                          icon={Check}
                          onClick={() => onReview(detail)}
                        >
                          Review &amp; apply
                        </KitButton>
                        <KitButton
                          variant="outline"
                          icon={Copy}
                          onClick={() => navigator.clipboard.writeText(detail.rego)}
                        >
                          Copy Rego
                        </KitButton>
                      </div>
                      <div
                        className="panel-sub"
                        style={{ marginTop: 8, color: "var(--text-muted)", display: "flex", gap: 6 }}
                      >
                        <Info size={13} style={{ flex: "none", marginTop: 1 }} />
                        <span>
                          "Review &amp; apply" only pre-fills the standard policy editor. Applying stays your
                          explicit action through the existing gated flow — this draft never enforces on its own.
                        </span>
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
    );
  };

  const FILTERS: Array<DraftStatus | "All"> = ["All", "New", "Reviewed", "Superseded", "Stale"];

  return (
    <Panel style={{ borderColor: `${DRAFT_ACCENT}44` }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
        <FlaskConical size={16} style={{ color: DRAFT_ACCENT }} />
        <div style={{ fontWeight: 600 }}>Intent drafts · dry-run (not enforcing)</div>
        <DryRunBadge />
        <div style={{ flex: 1 }} />
        <KitButton variant="ghost" size="sm" icon={Trash2} onClick={onClearExpired}>
          Clear expired
        </KitButton>
        <KitButton variant="ghost" size="sm" icon={RotateCcw} onClick={onRefresh}>
          Refresh
        </KitButton>
        <button className="icon-btn" aria-label="Dismiss intent drafts" onClick={onDismiss}>
          <X size={16} />
        </button>
      </div>
      {/* A4: subtitle reflects ALL real sources (Attack Graph + Compliance), not just the Attack Graph. */}
      <div className="panel-sub" style={{ marginBottom: 10 }}>
        Proposed policies from the Attack Graph and Compliance gaps — DRY-RUN DRAFTS, nothing here enforces. Review
        a draft and apply it explicitly through the standard policy flow.
      </div>

      {/* A5: status filter chips (newest-first order comes from the API). */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10, alignItems: "center" }}>
        {FILTERS.map((f) => (
          <button
            key={f}
            type="button"
            data-testid={`draft-filter-${f.toLowerCase()}`}
            onClick={() => setFilter(f)}
            style={{ fontSize: 11, fontWeight: 700, padding: "4px 11px", borderRadius: 999, cursor: "pointer",
              border: `1px solid ${filter === f ? DRAFT_ACCENT : "var(--border)"}`,
              background: filter === f ? `${DRAFT_ACCENT}1e` : "transparent",
              color: filter === f ? "var(--text)" : "var(--text-muted)" }}
          >
            {f}
          </button>
        ))}
        <div style={{ flex: 1 }} />
        {/* A3: default-hide test/e2e drafts with a reveal toggle. */}
        {hiddenTestCount > 0 && (
          <button
            type="button"
            data-testid="draft-toggle-test"
            onClick={() => setShowTest(!showTest)}
            style={{ fontSize: 11, color: "var(--text-muted)", background: "transparent", border: 0, cursor: "pointer", textDecoration: "underline" }}
          >
            {showTest ? `Hide ${hiddenTestCount} test draft${hiddenTestCount === 1 ? "" : "s"}` : `${hiddenTestCount} test draft${hiddenTestCount === 1 ? "" : "s"} hidden — Show`}
          </button>
        )}
      </div>

      {/* A1: grouped by lifecycle source. */}
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {groups.map((g) => (
          <div key={g.kind} data-testid={`draft-group-${g.kind}`}>
            <div style={{ fontSize: 10.5, fontWeight: 800, letterSpacing: "0.06em", textTransform: "uppercase", color: FAINT, marginBottom: 8 }}>
              {g.title} · {g.items.length}
            </div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: -4, marginBottom: 8 }}>{g.sub}</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {g.items.map(renderRow)}
            </div>
          </div>
        ))}
        {groups.length === 0 && (
          <div className="muted" style={{ fontSize: 12 }}>
            {loading ? "Loading drafts…" : filter === "All" ? "No pending drafts." : `No ${filter.toLowerCase()} drafts.`}
          </div>
        )}
      </div>

      {/* B6: bounded — the section shows a page, not the whole list; "view all" loads the rest. */}
      {remaining > 0 && (
        <div style={{ marginTop: 12, textAlign: "center" }}>
          <button
            type="button"
            data-testid="draft-view-all"
            onClick={onViewAll}
            style={{ fontSize: 12, color: "var(--accent, #00e5a0)", background: "transparent", border: 0, cursor: "pointer", fontWeight: 700 }}
          >
            {remaining} more · view all
          </button>
        </div>
      )}
    </Panel>
  );
}

// B-1: starter rego for a brand-new policy — a minimal, VALID block policy (the create validator requires a
// reachable block/escalate decision plus decision/rule_id/reason). The author edits it freely; it is not a
// template the way the composer's keyword-block generator is — the whole rego is hand-editable in Monaco.
const NEW_POLICY_REGO = `package norviq.custom

default decision = "allow"

rule_id = "custom_block_rule"
reason = "blocked by a custom policy"

# Author your rule below — this example blocks a destructive tool call. Edit freely.
decision = "block" {
    input.tool_name == "delete_database"
}
`;

export function PolicyCatalog() {
  const { namespace, posture } = useApp();
  // MUT-2: in Monitor mode the engine EVALUATES policies but does not block live traffic, so the
  // headline "ENFORCING" is a misrepresentation. Downgrade the badge to "MONITOR · would-block" so the
  // Catalog can't claim enforcement the namespace isn't doing. Only trust a definite monitor posture for
  // a concrete namespace (the "all" aggregate carries only the cluster default; per-ns overrides vary).
  const catalogMonitor = posture.mode === "audit" && namespace !== "all";
  const [searchParams, setSearchParams] = useSearchParams();
  const outlineTealButtonStyle = {
    background: "transparent",
    border: "1px solid #2DDAB8",
    color: "#2DDAB8"
  } as const;
  // Land on the editor so the seeded class policy opens with Monaco + Dry-Run immediately
  // (the Catalog tab remains a click away for the grouped tier view). C2-2: `?tab=catalog` (the "See how this
  // resolves →" link from Target Settings) opens the resolution hierarchy directly.
  const [tab, setTab] = useState<"catalog" | "editor" | "versions">(
    searchParams.get("tab") === "catalog" ? "catalog" : "editor"
  );
  const [selected, setSelected] = useState<Policy | null>(null);
  const [restoreV, setRestoreV] = useState<number | null>(null);
  const [viewV, setViewV] = useState<number | null>(null); // MUT-VERSION: version whose rego is expanded read-only
  const [activeFile, setActiveFile] = useState<string | null>(null);
  const [regoDraft, setRegoDraft] = useState("");
  const [editorStatus, setEditorStatus] = useState<"saved" | "unsaved" | `syntax:${number}`>("saved");
  const [dryRunResult, setDryRunResult] = useState<DryRunResult | null>(null);
  // MUT-DRYRUN: the exact rego a dry-run was computed against. If the buffer diverges afterward, the
  // stat block below is STALE next to the live "changes vs loaded" diff — we badge it instead of
  // silently showing outdated numbers as if they still described the current draft.
  const [dryRunRego, setDryRunRego] = useState<string | null>(null);
  const [dryRunLoading, setDryRunLoading] = useState(false);
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null);  // Stage 1: apply-result transparency
  // B-1: authoring a brand-new policy from raw rego for a chosen ns+class in the editor (null = editing existing).
  const [newPolicy, setNewPolicy] = useState<{ namespace: string; agent_class: string; mode: NonNullable<Policy["mode"]> } | null>(null);
  // B-2: the policy pending a confirmed delete (drives the confirm modal). Null = no delete in flight.
  const [deleteTarget, setDeleteTarget] = useState<Policy | null>(null);
  // FIX A: an existing (already-saved) policy's mode is read-only from `editorPolicy` — there was no way to
  // change JUST the enforcement mode from the editor. This holds the in-progress override for the currently
  // loaded existing policy; null = no override yet (falls back to the loaded policy's persisted mode).
  const [existingModeOverride, setExistingModeOverride] = useState<NonNullable<Policy["mode"]> | null>(null);

  const policies = useApi<Policy[]>(
    () => apiGet<Policy[]>(`/api/v1/policies?namespace=${encodeURIComponent(namespace)}`).then(withTargetType),
    [namespace],
    {
      cacheKey: `policy-catalog:${namespace}`,
      staleTimeMs: Number.MAX_SAFE_INTEGER
    }
  );
  // Live workloads observed for this namespace. Empty is a valid response (renders empty) — never a fake list.
  const deployments = useApi<Deployment[]>(
    () => apiGet<Deployment[]>(`/api/v1/deployments?namespace=${encodeURIComponent(namespace)}`),
    [namespace]
  );
  // F-51: a dry-run-only namespace disables Apply in the sheet (the API also rejects it — defence in depth).
  const settings = useApi(() => fetchSettings(namespace), [namespace], { cacheKey: `policy-settings:${namespace}`, staleTimeMs: 30_000 });
  const applyMode = settings.data?.apply_mode === "dry_run_only" ? "dry_run_only" : "enforce";

  // feat/attack-graph — Intent DRAFTS (READ + hand-off ONLY; never auto-enforces).
  const intentDraftId = searchParams.get("intent_draft");
  const [draftsDismissed, setDraftsDismissed] = useState(false);
  const [draftDetail, setDraftDetail] = useState<IntentDraftDetail | null>(null);
  const [draftDetailLoading, setDraftDetailLoading] = useState(false);
  // Part A/B triage state.
  const [draftFilter, setDraftFilter] = useState<DraftStatus | "All">("All");
  const [showTestDrafts, setShowTestDrafts] = useState<boolean>(() => localStorage.getItem("nrvq_show_test_drafts") === "1");
  const [showAllDrafts, setShowAllDrafts] = useState(false);  // B6: "view all" bumps the page limit
  const [reviewedDraftIds, setReviewedDraftIds] = useState<Set<string>>(new Set());
  // A6/B2: the draft being applied — carries ns+cls so the retire-on-save only fires for a save that
  // actually realises THIS draft (a later, unrelated save must never dismiss an abandoned draft).
  const [pendingDraft, setPendingDraft] = useState<{ id: string; ns: string; cls: string } | null>(null);
  const [justLoadedDraft, setJustLoadedDraft] = useState(false);  // show the "draft loaded → Create to apply" banner
  // Tear down the draft-apply flow whenever it's abandoned (cancel, start-new, pick another policy, edit-as-raw)
  // — else pendingDraft/justLoadedDraft leak onto an unrelated policy and a later save silently deletes the draft.
  const resetDraftFlow = () => { setPendingDraft(null); setJustLoadedDraft(false); };
  const editorPanelRef = useRef<HTMLDivElement>(null);  // scroll target so Review & apply lands on the editor
  const persistShowTest = (v: boolean) => { localStorage.setItem("nrvq_show_test_drafts", v ? "1" : "0"); setShowTestDrafts(v); };
  const drafts = useApi<IntentDraftPage>(
    () => fetchIntentDrafts(namespace, 0, showAllDrafts ? 500 : undefined),
    [namespace, showAllDrafts],
    { cacheKey: `intent-drafts:${namespace}:${showAllDrafts}`, staleTimeMs: 15_000 }
  );
  const emptyPage: IntentDraftPage = { drafts: [], total: 0, returned: 0, offset: 0, limit: 0 };
  const draftPage = drafts.data ?? emptyPage;
  // A2: enforcing version per agent-class, keyed by NAMESPACE/class — in the "all" view two namespaces can
  // share a class name, and keying by class alone made a draft's "Superseded" status / "currently v{n}"
  // linkage reflect a policy enforcing in a DIFFERENT namespace than the draft's.
  const enforcingByClass = ((): Record<string, number> => {
    const map: Record<string, number> = {};
    for (const p of policies.data ?? []) {
      const cls = p.agent_class;
      const ver = p.current_version;
      if (cls && typeof ver === "number") map[`${p.namespace}/${cls}`] = ver;
    }
    return map;
  })();
  const dismissOneDraft = async (draftId: string) => {
    try { await dismissIntentDraft(draftId); } catch { /* non-enforcing; ignore */ }
    drafts.refetch?.();
  };
  const clearExpiredDrafts = async () => {
    try { await gcIntentDrafts(namespace); } catch { /* best-effort */ }
    drafts.refetch?.();
  };

  // A deep-linked draft (?intent_draft=<id>) loads its full detail (incl. rego) for review.
  useEffect(() => {
    let cancelled = false;
    if (!intentDraftId) {
      setDraftDetail(null);
      return;
    }
    setDraftsDismissed(false);
    setDraftDetailLoading(true);
    // A deep-linked draft is REVIEWED by virtue of arriving here (mirrors clicking its row), so don't
    // leave it showing a "New" pill.
    setReviewedDraftIds((prev) => (prev.has(intentDraftId) ? prev : new Set(prev).add(intentDraftId)));
    // The list query is cached (15s), so a JUST-created draft (Attack Graph → apply → deep-link back within
    // the window) can be absent from the cached page and thus never rendered. If the current page doesn't
    // contain it, bust the cache + refetch so the hand-off never lands on an empty panel.
    if (!(drafts.data?.drafts ?? []).some((d) => d.draft_id === intentDraftId)) {
      invalidateApiCache("intent-drafts:");
      drafts.refetch?.();
    }
    fetchIntentDraft(intentDraftId)
      .then((d) => {
        if (!cancelled) setDraftDetail(d);
      })
      .catch(() => {
        if (!cancelled) setDraftDetail(null);
      })
      .finally(() => {
        if (!cancelled) setDraftDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intentDraftId, draftPage.total]);

  // "Review & apply": route the draft into the EXISTING gated create/apply UI, pre-filled.
  // This opens the standard PolicySheet + seeds the editor rego — it does NOT apply.
  const reviewDraft = (d: IntentDraftDetail) => {
    // STALE-1: a reviewed intent draft carries its OWN generated rego (d.rego). Route it into the raw
    // editor's NEW-POLICY flow — which authors exactly `regoDraft` at the draft's ns/class — NOT the
    // composer sheet (whose Confirm-Apply regenerates a generic keyword rego from its own local
    // keywordList, silently discarding the reviewed draft). saveEditorPolicy() then creates the policy
    // from the draft's actual rego and retires the draft (pendingDraftId) on success.
    setSelected(null);            // never open the generic composer sheet for a reviewed draft
    setActiveFile(null);
    // COMP-GEN-01: for a compliance-remediation draft, `d.cls` is ALREADY the compound overlay persistence
    // key ("<real class>__remediation__") the backend generated the draft at — saving here therefore lands
    // on the additive overlay scope, never the real class's own (ns, class) key, so Create can never replace
    // that class's existing comprehensive policy. `draftDisplayClass(d)` is used wherever this is SHOWN to
    // the operator so the raw compound key never appears as the visible "agent class".
    setNewPolicy({ namespace: d.ns, agent_class: d.cls, mode: "block" });
    setRegoDraft(d.rego);
    setEditorStatus("unsaved");
    setDryRunResult(null);
    setPendingDraft({ id: d.draft_id, ns: d.ns, cls: d.cls });  // retire it only on a save that realises IT
    setTab("editor");
    // The editor lives ABOVE the drafts panel the user clicked from, so a silent tab-switch read as
    // "nothing happened". Scroll the loaded editor into view + flag a guidance banner (cleared on the
    // next Create/Cancel) so the next action — Create to apply — is unmistakable.
    setJustLoadedDraft(true);
    setTimeout(() => editorPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 60);
  };

  const clearIntentDraftParam = () => {
    const next = new URLSearchParams(searchParams);
    next.delete("intent_draft");
    setSearchParams(next, { replace: true });
  };

  // P1: clicking a draft row opens its review (rego + coverage + apply) by setting the intent_draft param —
  // the SAME machinery a deep-link uses (detail fetch + inline expansion). Clicking the open row collapses it.
  const selectIntentDraft = (draftId: string) => {
    // A2: opening a draft marks it Reviewed (this session).
    if (intentDraftId !== draftId) setReviewedDraftIds((prev) => new Set(prev).add(draftId));
    const next = new URLSearchParams(searchParams);
    if (intentDraftId === draftId) next.delete("intent_draft");
    else next.set("intent_draft", draftId);
    setSearchParams(next, { replace: true });
  };

  const editorPolicy = useMemo(() => {
    const list = policies.data ?? [];
    if (activeFile) return list.find((p) => (p.target ?? p.agent_class) === activeFile);
    return list.find((p) => p.target_type === "class") ?? list[0];
  }, [policies.data, activeFile]);

  const detail = useApi<PolicyDetail>(
    () =>
      editorPolicy?.namespace && editorPolicy?.agent_class
        ? apiGet(
            `/api/v1/policies/${encodeURIComponent(editorPolicy.namespace)}/${encodeURIComponent(
              editorPolicy.agent_class
            )}?namespace=${encodeURIComponent(namespace)}`
          )
        : Promise.resolve({ rego_source: "" }),
    [editorPolicy?.namespace, editorPolicy?.agent_class, namespace]
  );

  const versions = useApi<PolicyVersion[]>(
    () =>
      editorPolicy?.namespace && editorPolicy?.agent_class
        ? apiGet(
            `/api/v1/policies/${encodeURIComponent(editorPolicy.namespace)}/${encodeURIComponent(
              editorPolicy.agent_class
            )}/versions?namespace=${encodeURIComponent(namespace)}`
          )
        : Promise.resolve([]),
    [editorPolicy?.namespace, editorPolicy?.agent_class, namespace]
  );

  const refreshPolicies = async () => {
    // C2-5: a policy create/apply/delete changes the resolved stack — bust the hierarchy caches so the Catalog
    // hierarchy (and the `hier-classes:` list) reflect it with no reload.
    // STALE-5: also bust `policy-catalog:` — the active-policies list is cached with an effectively-infinite
    // TTL, and setData() below only updates React state (never the module cache). Without this, a remount
    // (navigate away + back) served the pre-mutation list, resurrecting deleted policies / hiding new ones.
    for (const p of ["effective:", "hier-classes:", "policy-catalog:"]) invalidateApiCache(p);
    try {
      const next = withTargetType(await apiGet<Policy[]>(`/api/v1/policies?namespace=${encodeURIComponent(namespace)}`));
      policies.setData(next);
    } catch {
      // ignore
    }
  };

  // B-1: enter raw-rego new-policy mode in the editor — the author picks ns+class and edits the whole rego.
  const startNewPolicy = () => {
    setTab("editor");
    setActiveFile(null);
    setSelected(null);
    resetDraftFlow();  // starting a fresh raw policy abandons any in-flight draft apply
    setNewPolicy({ namespace: namespace === "all" ? "default" : namespace, agent_class: "", mode: "block" });
    setRegoDraft(NEW_POLICY_REGO);
    setEditorStatus("unsaved");
    setDryRunResult(null);
    setApplyResult(null);
  };

  const cancelNewPolicy = () => {
    setNewPolicy(null);
    setEditorStatus("saved");
    setDryRunResult(null);
    resetDraftFlow();
  };

  // MUT-ROLLBACK: restore a prior version. Previously this swallowed errors (catch{//ignore}) and never
  // refetched — the editor buffer, "current" badge, versions table and catalog card all kept showing the
  // pre-restore state with zero feedback either way. Now it surfaces an ApplyResult (success/failure) like
  // every other mutation on this page and reconciles policies + versions + the editor detail.
  const confirmRestoreVersion = async () => {
    const ns = editorPolicy?.namespace;
    const ac = editorPolicy?.agent_class;
    const target = restoreV;
    if (!ns || !ac || target == null) {
      setRestoreV(null);
      return;
    }
    try {
      const res = await apiSend<{ version?: number }>(
        `/api/v1/policies/${encodeURIComponent(ns)}/${encodeURIComponent(ac)}/rollback`,
        "POST",
        { target_version: target }
      );
      // Reconcile everything the rollback changed: the catalog list, the version history, and the loaded
      // editor buffer/detail (its effect re-seeds regoDraft off the fresh detail).
      await refreshPolicies();
      await versions.refetch();
      await detail.refetch();
      const newVer = res?.version;
      setApplyResult({
        kind: "local",
        title: `Restored ${ns}/${ac} to v${target}`,
        ok: true,
        outcome: `Version ${target} was re-applied as ${newVer ? `v${newVer}` : "a new version"} and loaded into this cluster's policy engine — enforcing "${editorPolicy?.mode ?? editorPolicy?.enforcement_mode ?? "block"}". Effective on the next tool call; the editor and Active-policies card now show the restored rego.`,
        manifest: { namespace: ns, agent_class: ac, enforcement_mode: editorPolicy?.mode ?? editorPolicy?.enforcement_mode ?? "block" },
        // FIX B: don't just trust the 200 — poll for the restored version to actually be the one loaded.
        expectedVersion: newVer
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const codeMatch = msg.match(/NRVQ-[A-Z0-9-]+/);
      setApplyResult({
        kind: "local",
        title: `Could not restore ${ns}/${ac} to v${target}`,
        ok: false,
        outcome: msg,
        code: codeMatch ? codeMatch[0] : undefined,
        manifest: { namespace: ns, agent_class: ac, enforcement_mode: editorPolicy?.mode ?? editorPolicy?.enforcement_mode ?? "block" }
      });
    } finally {
      setRestoreV(null);
    }
  };

  // B-2: run the confirmed delete — removes the policy across every layer, then reconciles the editor + list.
  const confirmDeletePolicy = async () => {
    if (!deleteTarget?.namespace || !deleteTarget?.agent_class) {
      setDeleteTarget(null);
      return;
    }
    const ns = deleteTarget.namespace;
    const ac = deleteTarget.agent_class;
    const ver = deleteTarget.current_version;
    // COMP-GEN-01/POLICY-RESERVED-01: a remediation overlay is an operator-authored reserved scope — the
    // server refuses a raw delete of it (422) and requires the explicit confirm_managed admin-gated revert,
    // exactly like `__guardrail__`. Deleting it only removes the overlay row; the base class policy is untouched.
    const overlay = isRemediationOverlayClass(ac);
    const displayClass = overlayDisplayLabel(ac);
    try {
      await deletePolicy(ns, ac, overlay);
      await refreshPolicies();
      if ((activeFile ?? editorPolicy?.agent_class) === ac) setActiveFile(null);  // deleted the loaded policy
      setApplyResult({
        kind: "local",
        title: `Deleted ${ns}/${displayClass}${ver ? ` · v${ver}` : ""}`,
        ok: true,
        outcome: overlay
          ? `Compliance remediation overlay for "${displayClass}" reverted from namespace "${ns}". The class's own base policy is untouched and keeps enforcing exactly as before.`
          : `Policy for "${ac}" removed from namespace "${ns}" across every layer (engine, cache, database, version history). "${ac}" now falls back to the namespace baseline / default (fail-closed if none). Durable across an api restart.`,
        manifest: { namespace: ns, agent_class: ac, enforcement_mode: deleteTarget.mode ?? "block" }
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const codeMatch = msg.match(/NRVQ-[A-Z0-9-]+/);
      setApplyResult({
        kind: "local",
        title: `Could not delete ${ns}/${displayClass}`,
        ok: false,
        outcome: msg,
        code: codeMatch ? codeMatch[0] : undefined,
        manifest: { namespace: ns, agent_class: ac, enforcement_mode: deleteTarget.mode ?? "block" }
      });
    } finally {
      setDeleteTarget(null);
    }
  };

  const onApply = async (mode: Policy["mode"], create?: { rego: string }) => {
    if (!selected) return;
    const ns = selected.namespace ?? namespace;
    const ac = selected.agent_class ?? "";
    // Q2: a brand-new manual class has no saved policy for `apply` to stamp — CREATE it first with the
    // composer-generated enforcing rego. create() loads into the read path, so it enforces immediately.
    if (create) {
      // "all" is the union VIEW, not a real namespace: a policy stored under "all:<class>" only matches an
      // agent whose identity namespace is literally "all" (no real agent has that), so it would never enforce.
      // Resolve to the concrete base namespace so the new class policy actually governs real tool calls.
      const createNs = ns === "all" ? "default" : ns;
      try {
        const res = await apiSend<{ version?: number }>("/api/v1/policies", "POST", {
          namespace: createNs,
          agent_class: ac,
          rego_source: create.rego,
          enforcement_mode: mode ?? "block"
        });
        await refreshPolicies();
        setActiveFile(ac);
        const ver = res?.version;
        setApplyResult({
          kind: "local",
          title: `Created ${createNs}/${ac}${ver ? ` · v${ver}` : ""}`,
          ok: true,
          outcome: `Policy authored for agent class "${ac}" (no labeled deployment required) in namespace "${createNs}" and loaded into this cluster's policy engine — enforcing "${mode ?? "block"}". Effective on the next tool call for this class; it appears in the editor and the Active-policies card.`,
          manifest: { namespace: createNs, agent_class: ac, enforcement_mode: mode ?? "block" },
          // FIX B: verify the version actually converged before badging this ENFORCING.
          expectedVersion: ver,
          expectedMode: mode ?? "block"
        });
      } catch (e) {
        const msg = String(e).replace(/^Error:\s*/, "");
        const codeMatch = msg.match(/NRVQ-[A-Z]+-\d+/);
        setApplyResult({
          kind: "local",
          title: "Create rejected",
          ok: false,
          outcome: msg,
          code: codeMatch ? codeMatch[0] : undefined,
          manifest: { namespace: createNs, agent_class: ac, enforcement_mode: mode ?? "block" }
        });
      } finally {
        setSelected(null);
      }
      return;
    }
    try {
      const targetType = selected.target_type === "class" ? "agent_class" : selected.target_type ?? "agent_class";
      const res = await applyPolicy(ns, ac, {
        target_type: targetType,
        target_namespace: ns,
        target_name: selected.target,
        target_kind: selected.target_type === "workload" ? "Deployment" : undefined,
        enforcement_mode: mode ?? "block"
      });
      await refreshPolicies();
      // A6/B2: the applied draft is now enforcing → retire it — ONLY when this apply is for the SAME
      // ns/class the draft targets (guards against an unrelated policy's apply deleting an abandoned draft).
      if (pendingDraft && ns === pendingDraft.ns && ac === pendingDraft.cls) {
        await dismissIntentDraft(pendingDraft.id).catch(() => {});
        resetDraftFlow();
        clearIntentDraftParam();
        drafts.refetch();
      }
      // C1: explicit success confirmation — name the applied version so the operator always gets feedback (not a
      // silent close). The card also re-stamps "applied {ago}" via the backend mark_applied + refreshPolicies.
      const ver = (res as { version?: number }).version;
      setApplyResult({
        kind: "local",
        title: `Applied ${ns}/${ac}${ver ? ` · v${ver}` : ""}`,
        ok: true,
        outcome: `Loaded into this cluster's policy engine — enforcement "${res.enforcement_mode ?? mode}"${ver ? ` (version ${ver} now enforcing → the draft moved to enforcing)` : ""}. Effective immediately on the next tool call; the Active-policies card shows "applied just now".`,
        manifest: { namespace: ns, agent_class: ac, enforcement_mode: res.enforcement_mode ?? mode ?? "block" },
        // FIX B: apply's 200 can lie (FIX A) — verify the version AND the persisted mode actually converged.
        expectedVersion: ver,
        expectedMode: res.enforcement_mode ?? mode ?? "block"
      });
    } catch (e) {
      const msg = String(e).replace(/^Error:\s*/, "");
      const codeMatch = msg.match(/NRVQ-[A-Z]+-\d+/);
      setApplyResult({
        kind: "local",
        title: "Apply rejected",
        ok: false,
        outcome: msg,
        code: codeMatch ? codeMatch[0] : undefined,
        manifest: { namespace: ns, agent_class: ac, enforcement_mode: mode ?? "block" }
      });
    } finally {
      setSelected(null);
    }
  };

  const editorFiles = (policies.data ?? []).filter((p) => p.target_type === "class");
  const activePolicyName = activeFile ?? editorFiles[0]?.target ?? editorFiles[0]?.agent_class ?? null;

  // MUT-1: the STABLE identity of the loaded policy. The buffer-reset effect below keyed on
  // `editorPolicy?.id` (the policies API returns no id → always undefined) plus the raw rego string —
  // so switching between two policies with BYTE-IDENTICAL source (all the seeded classes share one
  // canonical rego) never re-fired the reset, and policy A's unsaved edits silently became the buffer
  // for policy B (one Save from overwriting a live enforcing policy). Keying on ns/class guarantees a
  // reset on every switch regardless of source equality.
  const editorIdentity =
    editorPolicy?.namespace && editorPolicy?.agent_class
      ? `${editorPolicy.namespace}/${editorPolicy.agent_class}`
      : null;

  useEffect(() => {
    // In new-policy mode the draft is the author's raw rego (seeded to NEW_POLICY_REGO on entry) — never
    // overwrite it with the (unrelated) loaded policy's source.
    if (newPolicy) return;
    setRegoDraft(detail.data?.rego_source ?? "");
    setEditorStatus("saved");
    setDryRunResult(null);
  }, [editorIdentity, detail.data?.rego_source, newPolicy]);

  // MUT-1: switching the loaded policy while the buffer has unsaved edits would discard them silently
  // (or, with the reset bug, carry them onto the next policy). Guard every file switch: if the buffer is
  // dirty and the switch targets a DIFFERENT policy, confirm first. Returns true if the switch may proceed.
  const confirmDiscardIfDirty = (nextName: string | null): boolean => {
    if (editorStatus !== "unsaved") return true;
    if (nextName !== null && nextName === activePolicyName) return true; // same file — no switch
    return window.confirm(
      "You have unsaved changes to this policy. Switch anyway and discard them?"
    );
  };

  // MUT-1 (tab close): confirmDiscardIfDirty only guards in-app switches — closing/reloading the tab with
  // unsaved edits would still lose them silently. Registered only while the buffer is dirty; removed on save/unmount.
  useEffect(() => {
    if (editorStatus !== "unsaved") return;
    const onBeforeUnload = (e: BeforeUnloadEvent) => {
      e.preventDefault();
      e.returnValue = "";
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, [editorStatus]);

  // B-1: the ns/class/mode the editor is authoring against — the new-policy scope when creating, else the loaded
  // policy. saveEditorPolicy + runDryRun both read this so create and edit share one code path.
  const editorTarget = newPolicy
    ? newPolicy
    : editorPolicy?.namespace && editorPolicy?.agent_class
    ? {
        namespace: editorPolicy.namespace,
        agent_class: editorPolicy.agent_class,
        // FIX A: prefer the in-progress override (user changed the Enforcement dropdown) over the
        // persisted mode, so saveEditorPolicy actually submits the changed mode instead of re-echoing
        // the stale one — this is the bug: the mode select existed only for `newPolicy`, so an existing
        // policy's mode could never be changed from the editor.
        mode: existingModeOverride ?? editorPolicy.mode ?? editorPolicy.enforcement_mode ?? "block"
      }
    : null;

  // FIX A: reset the mode override whenever the loaded existing policy changes (switch files, reload after
  // save) so a stale override from a PREVIOUS policy never leaks onto the next one.
  useEffect(() => {
    setExistingModeOverride(null);
  }, [editorPolicy?.namespace, editorPolicy?.agent_class]);

  const saveEditorPolicy = async () => {
    if (!editorTarget?.namespace || !editorTarget?.agent_class) return;
    // Never author into a reserved/managed scope (the server rejects create for pack scopes; keep the UI honest).
    if (isReservedScope(editorTarget.agent_class, editorTarget.namespace)) return;
    try {
      const res = await apiSend<{ version?: number }>("/api/v1/policies", "POST", {
        namespace: editorTarget.namespace,
        agent_class: editorTarget.agent_class,
        rego_source: regoDraft,
        enforcement_mode: editorTarget.mode ?? "block"
      });
      setEditorStatus("saved");
      await refreshPolicies();
      // STALE-1: this save realised a reviewed intent draft — retire it now that its rego is enforcing —
      // ONLY when the save targets the SAME ns/class as the loaded draft (a later save of an unrelated
      // policy must never delete an abandoned draft).
      if (pendingDraft && editorTarget?.namespace === pendingDraft.ns && editorTarget?.agent_class === pendingDraft.cls) {
        await dismissIntentDraft(pendingDraft.id).catch(() => {});
        resetDraftFlow();
        clearIntentDraftParam();
        drafts.refetch();
      }
      if (newPolicy) {
        // B-1: created a brand-new class — leave new-policy mode and open the freshly-created policy in the editor.
        setActiveFile(newPolicy.agent_class);
        setNewPolicy(null);
        setJustLoadedDraft(false);
        // COMP-GEN-01: `editorTarget.agent_class` may be the compound "<class>__remediation__" overlay key —
        // show the real class + "compliance overlay" tag to the operator; the raw key stays in `manifest`.
        const displayClass = overlayDisplayLabel(editorTarget.agent_class);
        setApplyResult({
          kind: "local",
          title: `Created ${editorTarget.namespace}/${displayClass}${res?.version ? ` · v${res.version}` : ""}`,
          ok: true,
          outcome: isRemediationOverlayClass(editorTarget.agent_class)
            ? `Compliance remediation overlay authored for "${displayClass}" in namespace "${editorTarget.namespace}" and loaded into this cluster's policy engine — enforcing "${editorTarget.mode ?? "block"}". It ADDS a block on top of the class's existing policy (never replaces it); effective on the next tool call for this class.`
            : `New policy authored for "${editorTarget.agent_class}" in namespace "${editorTarget.namespace}" and loaded into this cluster's policy engine — enforcing "${editorTarget.mode ?? "block"}". Effective on the next tool call for this class; it appears in the editor and the Active-policies card.`,
          manifest: { namespace: editorTarget.namespace, agent_class: editorTarget.agent_class, enforcement_mode: editorTarget.mode ?? "block" },
          // FIX B: verify the created/mode-changed version actually converged before badging ENFORCING.
          expectedVersion: res?.version,
          expectedMode: editorTarget.mode ?? "block"
        });
      } else {
        // FIX-3: an existing-policy Save (e.g. the editor's "Enforcement -> audit" flow, Bug #2's own repro)
        // previously fell straight through here with only the small "Saved ✓" badge above — no verify-poll,
        // so the operator got no Bug #4-style convergence feedback on the exact save path that motivated it.
        // Show the same local ApplyResultPanel + verify-poll as the create/apply paths.
        const displayClass = overlayDisplayLabel(editorTarget.agent_class);
        setApplyResult({
          kind: "local",
          title: `Saved ${editorTarget.namespace}/${displayClass}${res?.version ? ` · v${res.version}` : ""}`,
          ok: true,
          outcome: `Policy updated for "${editorTarget.agent_class}" in namespace "${editorTarget.namespace}" and loaded into this cluster's policy engine — enforcing "${editorTarget.mode ?? "block"}". Effective on the next tool call for this class.`,
          manifest: { namespace: editorTarget.namespace, agent_class: editorTarget.agent_class, enforcement_mode: editorTarget.mode ?? "block" },
          expectedVersion: res?.version,
          expectedMode: editorTarget.mode ?? "block"
        });
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const codeMatch = msg.match(/NRVQ-[A-Z0-9-]+/);
      setApplyResult({
        kind: "local",
        title: `Could not create ${editorTarget.namespace}/${overlayDisplayLabel(editorTarget.agent_class)}`,
        ok: false,
        outcome: msg,
        code: codeMatch ? codeMatch[0] : undefined,
        manifest: { namespace: editorTarget.namespace, agent_class: editorTarget.agent_class, enforcement_mode: editorTarget.mode ?? "block" }
      });
    }
  };

  const runDryRun = async () => {
    if (!editorTarget?.namespace || !editorTarget?.agent_class) return;
    setDryRunLoading(true);
    try {
      const ran = regoDraft || detail.data?.rego_source || "";
      const result = await dryRunPolicy({
        namespace: editorTarget.namespace,
        agent_class: editorTarget.agent_class,
        rego_source: ran
      });
      setDryRunResult(result);
      setDryRunRego(ran);
    } catch {
      setDryRunResult({
        total_records_checked: 0,
        would_block: 0,
        would_allow: 0,
        block_rate_pct: 0,
        recommendation: "Unable to evaluate right now"
      });
    } finally {
      setDryRunLoading(false);
    }
  };

  // Stage 1: a real current-vs-new diff for Dry-Run — what the edit actually changes vs the loaded policy.
  const regoDiff = useMemo(() => {
    // A brand-new policy has no current source — diff against empty so the review shows the whole rego as added.
    const cur = (newPolicy ? "" : detail.data?.rego_source ?? "").split("\n");
    const next = (regoDraft ?? "").split("\n");
    if (cur.join("\n") === next.join("\n")) return null;
    const curSet = new Set(cur);
    const nextSet = new Set(next);
    const removed = cur.filter((l) => !nextSet.has(l)).map((text) => ({ sign: "-", text }));
    const added = next.filter((l) => !curSet.has(l)).map((text) => ({ sign: "+", text }));
    return [...removed, ...added];
  }, [detail.data?.rego_source, regoDraft, newPolicy]);

  return (
    <div className="page-enter">
      <PageHead
        title="Policy Catalog"
        subtitle={`Showing: ${namespace}`}
        actions={
          <KitButton
            variant="ghost"
            icon={Plus}
            style={outlineTealButtonStyle}
            // UX-CREATE: two create paths, now self-evidently distinct. This is the GUIDED composer
            // (target + toggles → generated rego); the sidebar "raw rego" entry is for authors. A
            // one-way bridge ("Edit as raw rego") lets the guided path graduate into the raw editor.
            title="Guided: pick a target and toggles; Norviq generates the rego for you"
            onMouseEnter={(e) => (e.currentTarget.style.background = "#2DDAB815")}
            onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            onClick={() =>
              setSelected({
                target_type: "class",
                target: "",
                agent_class: "",
                // Q2: no `current_version` → the sheet treats this as a NEW policy (isNew) and the manual
                // class is created (not a stamp of a non-existent saved policy).
                mode: "block"
              })
            }
          >
            New Policy (guided)
          </KitButton>
        }
      />

      {/* Stage 1: apply-result transparency — the exact resource configured + honest outcome (policy-store + engine load). */}
      <ApplyResultPanel result={applyResult} onClose={() => setApplyResult(null)} />

      {/* feat/attack-graph — non-enforcing intent drafts (hidden when empty; READ + hand-off only). */}
      {!draftsDismissed && draftPage.total > 0 && (
        <div style={{ marginBottom: 16 }}>
          <IntentDraftsPanel
            page={draftPage}
            enforcingByClass={enforcingByClass}
            reviewedIds={reviewedDraftIds}
            filter={draftFilter}
            setFilter={setDraftFilter}
            showTest={showTestDrafts}
            setShowTest={persistShowTest}
            onViewAll={() => setShowAllDrafts(true)}
            onDismissOne={dismissOneDraft}
            onClearExpired={clearExpiredDrafts}
            loading={drafts.loading}
            highlightId={intentDraftId}
            detail={draftDetail}
            detailLoading={draftDetailLoading}
            onRefresh={() => drafts.refetch()}
            onDismiss={() => {
              setDraftsDismissed(true);
              clearIntentDraftParam();
            }}
            onReview={reviewDraft}
            onSelect={selectIntentDraft}
          />
        </div>
      )}

      <div className="stack">
        {/* F-61: "Policy Coverage by Category" lives on Overview only (was duplicated here). */}
        <div className="tabs-kit" style={{ alignSelf: "flex-start" }}>
          {(["catalog", "editor", "versions"] as const).map((t) => (
            <button
              key={t}
              className={`tab-kit${tab === t ? " active" : ""}`}
              onClick={() => setTab(t)}
            >
              {t[0].toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>

        {tab === "catalog" && (
          <div className="stack">
            {/* C2-1/C2-2: the resolution HIERARCHY is the headline of the catalog view — the ordered layer stack the
                evaluator actually resolves for a class (folded in from Target Settings). The grouped "Active
                policies" list stays below it as the flat inventory + delete surface. */}
            <PolicyHierarchy namespace={namespace} />
            {/* Fix 7: label enforcing policies distinctly from the dry-run "Intent drafts" panel above. */}
            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              <div
                style={{
                  display: "flex",
                  width: "100%",
                  alignItems: "center",
                  gap: 8,
                  fontWeight: 600,
                  fontSize: 14,
                  color: "var(--text-primary)"
                }}
              >
                Active policies
                {/* Quiet border-only status chip, anchored top-RIGHT of the section (was a loud filled pill
                    glued to the title). The Monitor detail lives in the caption below + the header pill. */}
                <span
                  data-testid="active-policies-mode"
                  style={{
                    marginLeft: "auto",
                    display: "inline-flex",
                    alignItems: "center",
                    gap: 6,
                    fontSize: 11,
                    fontWeight: 600,
                    letterSpacing: ".04em",
                    padding: "2px 9px",
                    borderRadius: 999,
                    color: catalogMonitor ? "var(--escalate)" : "var(--text-secondary)",
                    border: `1px solid ${catalogMonitor ? "rgba(255,176,32,0.35)" : "var(--border)"}`,
                    background: "transparent"
                  }}
                >
                  <span aria-hidden="true" style={{ width: 6, height: 6, borderRadius: "50%", background: catalogMonitor ? "var(--escalate)" : "var(--success, #30a46c)" }} />
                  {catalogMonitor ? "Monitor · would-block" : "Enforcing"}
                </span>
              </div>
              <div className="muted" style={{ fontSize: 12.5 }}>
                {catalogMonitor
                  ? `Loaded into the policy engine and EVALUATED, but ${namespace} is in Monitor mode — matches are logged as would-block, live traffic is not blocked. Distinct from the dry-run drafts above.`
                  : "Loaded into this cluster's policy engine — grouped by workload, agent-class and namespace tier. Distinct from the dry-run drafts above."}
              </div>
            </div>
            {TIERS.map((tier) => {
              const items = (policies.data ?? []).filter((p) => p.target_type === tier.type);
              return (
                <Panel
                  key={tier.type}
                  title={tier.title}
                  sub={tier.sub}
                  action={<PriorityBars tier={tier.type} />}
                >
                  {items.length === 0 ? (
                    <div className="muted" style={{ fontSize: 13, padding: "12px 0" }}>
                      No {tier.type} policies configured.
                    </div>
                  ) : (
                    <div className="grid-kit g3">
                      {items.map((p) => (
                        <div key={p.id ?? `${p.namespace}-${p.agent_class}`} style={{ position: "relative" }}>
                          <button
                            className="policy-item"
                            style={{ width: "100%" }}
                            onClick={() => {
                              const nextName = p.target ?? p.agent_class ?? null;
                              if (!confirmDiscardIfDirty(nextName)) return;
                              setNewPolicy(null);
                              resetDraftFlow();  // opening an existing policy abandons any in-flight draft apply
                              setActiveFile(nextName);
                              setTab("editor");
                            }}
                          >
                            <div
                              style={{
                                display: "flex",
                                justifyContent: "space-between",
                                alignItems: "center",
                                gap: 8
                              }}
                            >
                              <span className="policy-name mono" style={{ display: "flex", alignItems: "center", gap: 6 }} title={p.target ?? p.agent_class ?? undefined}>
                                {/* FIX-2: health dot — a listed policy IS loaded in this cluster's engine & enforcing. */}
                                <span
                                  aria-label="Loaded & enforcing"
                                  title="Loaded in the policy engine & enforcing"
                                  style={{
                                    width: 7, height: 7, borderRadius: "50%", flex: "none",
                                    background: "var(--good, #2ecc71)", boxShadow: "0 0 0 2px var(--good-dim, #2ecc7126)"
                                  }}
                                />
                                {/* COMP-GEN-01: a "<class>__remediation__" row is a distinct, ADDITIVE overlay
                                    on that class — shown as "<class> · compliance overlay" so the base class
                                    row (unaffected) and the overlay row are both visible, but never confused. */}
                                {overlayDisplayLabel(p.target ?? p.agent_class) || "—"}
                              </span>
                              {(p.mode ?? p.enforcement_mode) && <DecisionBadge decision={MODE_DECISION[(p.mode ?? p.enforcement_mode)!]} />}
                            </div>
                            <div className="policy-meta">
                              v{p.current_version ?? 1} ·{" "}
                              {(p.rego_length ?? 0).toLocaleString()} chars ·{" "}
                              {p.matches ?? 0} match{p.matches === 1 ? "" : "es"}
                              {p.last_applied ? <> · applied {timeAgo(p.last_applied)}</> : null}
                            </div>
                          </button>
                          {/* B-2: per-row delete — never offered for reserved/managed scopes (baseline/pack/guardrail). */}
                          {!isReservedScope(p.agent_class, p.namespace) && (
                            <button
                              type="button"
                              className="icon-btn"
                              data-testid={`catalog-delete-${p.agent_class ?? p.target ?? "policy"}`}
                              aria-label={`Delete policy ${p.agent_class ?? p.target ?? ""}`}
                              title="Delete policy"
                              onClick={(e) => { e.stopPropagation(); setDeleteTarget(p); }}
                              style={{ position: "absolute", top: 8, right: 8, color: "#ff6b81" }}
                            >
                              <Trash2 size={14} />
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              );
            })}
          </div>
        )}

        {tab === "editor" && (
          <Panel pad>
            <div ref={editorPanelRef} />
            {/* Draft-loaded guidance: makes the outcome of "Review & apply" unmistakable — which draft
                is loaded and that the NEXT action (Create) is what applies it. Cleared on Create/Cancel. */}
            {justLoadedDraft && pendingDraft && newPolicy && (
              <div
                data-testid="draft-loaded-banner"
                style={{ display: "flex", alignItems: "flex-start", gap: 10, marginBottom: 12, padding: "11px 14px", borderRadius: 10, background: "rgba(45,218,184,0.08)", border: "1px solid #2DDAB855" }}
              >
                <Check size={16} style={{ flex: "none", color: "#2DDAB8", marginTop: 1 }} />
                <div style={{ fontSize: 12.5, lineHeight: 1.5, color: "var(--text)" }}>
                  Draft loaded into the editor for{" "}
                  <strong style={{ color: "#2DDAB8" }} title={newPolicy.agent_class}>
                    {newPolicy.namespace}/{overlayDisplayLabel(newPolicy.agent_class)}
                  </strong>
                  .{" "}
                  {isRemediationOverlayClass(newPolicy.agent_class) && (
                    <>This ADDS a block on top of the class's existing policy — it never replaces it. </>
                  )}
                  Review the Rego below, then click <strong>Create</strong> to apply it as an enforcing policy — or <strong>Dry-Run</strong> to preview first. Nothing enforces until you Create.
                </div>
                <button type="button" onClick={() => setJustLoadedDraft(false)} aria-label="Dismiss" style={{ marginLeft: "auto", flex: "none", background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", fontSize: 16, lineHeight: 1 }}>×</button>
              </div>
            )}
            <div
              style={{
                display: "flex",
                gap: 0,
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-md)",
                overflow: "hidden"
              }}
            >
              <div
                style={{
                  width: 220,
                  flex: "none",
                  background: "var(--bg-surface)",
                  borderRight: "1px solid var(--border)",
                  padding: 8
                }}
              >
                <div className="section-label" style={{ padding: "4px 8px" }}>
                  Policies
                </div>
                {/* B-1: author a brand-new policy from raw rego for a chosen ns+class (distinct from the header
                    composer, which only generates templated keyword-block rego). */}
                <button
                  type="button"
                  data-testid="editor-new-policy"
                  className={`sb-link${newPolicy ? " active" : ""}`}
                  onClick={startNewPolicy}
                  title="Author OPA/Rego directly in the editor — for advanced policies the guided composer can't express"
                  style={{ fontSize: 12.5, color: "#2DDAB8" }}
                >
                  <Plus size={14} />
                  <span style={{ fontSize: 12 }}>New policy (raw rego)</span>
                </button>
                {editorFiles.length === 0 && !newPolicy && (
                  <div className="muted" style={{ fontSize: 12, padding: 8 }}>
                    No class policies
                  </div>
                )}
                {editorFiles.map((p) => {
                  const name = p.target ?? p.agent_class ?? "policy";
                  const isActive = !newPolicy && activePolicyName === name;
                  return (
                    <button
                      key={p.id ?? name}
                      role="row"
                      className={`sb-link${isActive ? " active" : ""}`}
                      onClick={() => { if (!confirmDiscardIfDirty(name)) return; setNewPolicy(null); resetDraftFlow(); setActiveFile(name); }}
                      style={{ fontSize: 12.5 }}
                    >
                      <FileCode size={14} />
                      <span className="mono" style={{ fontSize: 12 }}>
                        {name}.rego
                      </span>
                    </button>
                  );
                })}
              </div>
              <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
                {newPolicy && (
                  // B-1: new-policy scope selector — the author types the namespace + agent class + enforcement mode
                  // the raw rego below will be created for (POST /api/v1/policies).
                  <div
                    data-testid="new-policy-fields"
                    style={{
                      display: "flex", alignItems: "flex-end", gap: 10, flexWrap: "wrap",
                      padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-surface)"
                    }}
                  >
                    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--text-muted)" }}>
                      Namespace
                      <input
                        data-testid="new-policy-namespace"
                        className="input"
                        value={newPolicy.namespace}
                        onChange={(e) => setNewPolicy({ ...newPolicy, namespace: e.target.value.trim() })}
                        style={{ fontSize: 12.5, minWidth: 140 }}
                      />
                    </label>
                    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--text-muted)" }}>
                      Agent class
                      <input
                        data-testid="new-policy-class"
                        className="input"
                        placeholder="e.g. finance-agent"
                        value={newPolicy.agent_class}
                        onChange={(e) => setNewPolicy({ ...newPolicy, agent_class: e.target.value.trim() })}
                        style={{ fontSize: 12.5, minWidth: 180 }}
                      />
                    </label>
                    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--text-muted)" }}>
                      Enforcement
                      <select
                        data-testid="new-policy-mode"
                        className="input"
                        value={newPolicy.mode}
                        onChange={(e) => setNewPolicy({ ...newPolicy, mode: e.target.value as NonNullable<Policy["mode"]> })}
                        style={{ fontSize: 12.5 }}
                      >
                        <option value="block">block</option>
                        <option value="audit">audit</option>
                        <option value="escalate">escalate</option>
                      </select>
                    </label>
                    {isReservedScope(newPolicy.agent_class, newPolicy.namespace) && (
                      <span data-testid="new-policy-reserved-warn" style={{ fontSize: 11.5, color: "#ff3b5c", alignSelf: "center" }}>
                        <TriangleAlert size={13} style={{ verticalAlign: "-2px" }} /> Reserved scope — pick a different class.
                      </span>
                    )}
                    <div style={{ flex: 1 }} />
                    <KitButton variant="ghost" size="sm" icon={X} onClick={cancelNewPolicy}>Cancel</KitButton>
                  </div>
                )}
                {/* FIX A: an EXISTING loaded policy's mode was read-only (no onChange anywhere), so "Save" could
                    never change enforcement mode — the editor's "Enforcement -> audit" change was silently
                    dropped. Mirrors the new-policy Enforcement select above, bound to editorTarget via
                    existingModeOverride so saveEditorPolicy (which already POSTs editorTarget.mode) submits it. */}
                {!newPolicy && editorPolicy && (
                  <div
                    data-testid="existing-policy-fields"
                    style={{
                      display: "flex", alignItems: "flex-end", gap: 10, flexWrap: "wrap",
                      padding: "10px 14px", borderBottom: "1px solid var(--border)", background: "var(--bg-surface)"
                    }}
                  >
                    <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 11, color: "var(--text-muted)" }}>
                      Enforcement
                      <select
                        data-testid="editor-existing-mode"
                        className="input"
                        value={editorTarget?.mode ?? "block"}
                        onChange={(e) => {
                          setExistingModeOverride(e.target.value as NonNullable<Policy["mode"]>);
                          setEditorStatus("unsaved");
                        }}
                        style={{ fontSize: 12.5 }}
                      >
                        <option value="block">block</option>
                        <option value="audit">audit</option>
                        <option value="escalate">escalate</option>
                      </select>
                    </label>
                  </div>
                )}
                <div className="editor" style={{ borderRadius: 0, border: "none", height: 400 }}>
                  <div className="editor-head">
                    <FileCode size={14} />{" "}
                    {newPolicy
                      ? `${newPolicy.namespace || "namespace"}/${newPolicy.agent_class || "new-policy"}.rego`
                      : /* MUT-1: on first load activeFile is null but a policy IS loaded (editorFiles[0]) —
                           show its real name, not a generic "policy.rego" that disagrees with the highlighted
                           sidebar row. activePolicyName resolves the same fallback the sidebar uses. */
                        (activePolicyName ?? "policy") + ".rego"}
                    <span style={{ marginLeft: "auto", color: "var(--text-muted)" }}>Rego · OPA</span>
                  </div>
                  <Editor
                    defaultLanguage="rego"
                    beforeMount={registerRego}
                    theme="vs-dark"
                    height="350px"
                    value={regoDraft || "# Select a policy from the list"}
                    onChange={(value) => {
                      setRegoDraft(value ?? "");
                      setEditorStatus("unsaved");
                    }}
                    onValidate={(markers) => {
                      if (markers.length > 0) {
                        setEditorStatus(`syntax:${markers[0].startLineNumber}`);
                      } else {
                        setEditorStatus("unsaved");
                      }
                    }}
                    options={{ minimap: { enabled: false }, fontSize: 12.5 }}
                  />
                </div>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    padding: "10px 14px",
                    borderTop: "1px solid var(--border)",
                    background: "var(--bg-surface)"
                  }}
                >
                  <span
                    style={{
                      color:
                        editorStatus === "saved"
                          ? "#00e5a0"
                          : editorStatus.startsWith("syntax:")
                          ? "#ff3b5c"
                          : "#ffb020",
                      fontSize: 12.5,
                      display: "inline-flex",
                      alignItems: "center",
                      gap: 6
                    }}
                  >
                    {editorStatus === "saved" && (
                      <>
                        <Check size={14} /> Saved ✓
                      </>
                    )}
                    {editorStatus === "unsaved" && (
                      <>
                        <Info size={14} /> Unsaved changes
                      </>
                    )}
                    {editorStatus.startsWith("syntax:") && (
                      <>
                        <AlertCircle size={14} /> Syntax error on line {editorStatus.split(":")[1]}
                      </>
                    )}
                  </span>
                  <div style={{ flex: 1 }} />
                  {/* B-2: delete the loaded existing policy (never a reserved scope, never during new-policy mode). */}
                  {!newPolicy && editorPolicy && !isReservedScope(editorPolicy.agent_class, editorPolicy.namespace) && (
                    <KitButton
                      variant="destructive"
                      size="sm"
                      icon={Trash2}
                      data-testid="editor-delete-policy"
                      onClick={() => setDeleteTarget(editorPolicy)}
                    >
                      Delete
                    </KitButton>
                  )}
                  <KitButton
                    // A freshly-loaded draft's Create IS the apply action — make it the visually PRIMARY
                    // button so the flow doesn't dead-end on a quiet ghost control.
                    variant={justLoadedDraft ? "primary" : "ghost"}
                    size="sm"
                    icon={Check}
                    data-testid="editor-save-policy"
                    style={justLoadedDraft ? undefined : outlineTealButtonStyle}
                    onMouseEnter={justLoadedDraft ? undefined : (e) => (e.currentTarget.style.background = "#2DDAB815")}
                    onMouseLeave={justLoadedDraft ? undefined : (e) => (e.currentTarget.style.background = "transparent")}
                    disabled={!!newPolicy && (!newPolicy.namespace || !newPolicy.agent_class || isReservedScope(newPolicy.agent_class, newPolicy.namespace))}
                    onClick={saveEditorPolicy}
                  >
                    {newPolicy ? (justLoadedDraft ? "Create & apply" : "Create") : "Save"}
                  </KitButton>
                  <KitButton variant="outline" size="sm" icon={Play} onClick={runDryRun}>
                    {dryRunLoading ? "Dry-Running..." : "Dry-Run"}
                  </KitButton>
                  {!newPolicy && (
                    <KitButton
                      variant="outline"
                      size="sm"
                      icon={Check}
                      onClick={() => {
                        if (editorPolicy) setSelected(editorPolicy);
                      }}
                    >
                      Apply
                    </KitButton>
                  )}
                </div>
                {dryRunResult != null && (
                  <div
                    style={{
                      padding: "10px 14px",
                      borderTop: "1px solid var(--border)",
                      fontSize: 12.5
                    }}
                  >
                    <div style={{ fontWeight: 600, marginBottom: 6, display: "flex", alignItems: "center", gap: 8 }}>
                      Dry-Run Results
                      {/* MUT-DRYRUN: the buffer changed since these numbers were computed — they no longer
                          describe the current draft. Badge it (don't silently show stale stats). */}
                      {dryRunRego != null && regoDraft !== dryRunRego && (
                        <span
                          data-testid="dryrun-stale"
                          style={{
                            fontSize: 10.5,
                            fontWeight: 700,
                            letterSpacing: ".04em",
                            textTransform: "uppercase",
                            color: "var(--escalate)",
                            border: "1px solid var(--escalate)",
                            borderRadius: 999,
                            padding: "1px 8px"
                          }}
                        >
                          Stale · re-run
                        </span>
                      )}
                    </div>
                    {regoDiff && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ color: "var(--text-muted)", fontSize: 11, textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 4 }}>
                          Changes vs the loaded policy
                        </div>
                        <pre
                          className="mono"
                          style={{ margin: 0, maxHeight: 140, overflow: "auto", background: "#0e0e0e", border: "1px solid var(--border,#2a2a2a)", borderRadius: 6, padding: "8px 10px", fontSize: 11.5 }}
                        >
                          {regoDiff.map((d, i) => (
                            <div key={i} style={{ color: d.sign === "+" ? "var(--success,#30a46c)" : "var(--danger,#e5484d)" }}>
                              {d.sign} {d.text}
                            </div>
                          ))}
                        </pre>
                      </div>
                    )}
                    {/* DRYRUN-REPLAY: lead with the DECISION FLIP — currently-allowed calls this candidate
                        would NEWLY block (what actually tells you if applying breaks real traffic), not the
                        old 'global historical block rate'. */}
                    {(() => {
                      const checked = dryRunResult.total_records_checked ?? 0;
                      const newly = dryRunResult.newly_blocked ?? 0;
                      const flipColor = newly > 0 ? "var(--escalate)" : "var(--allow)";
                      return (
                        <>
                          <div style={{ display: "flex", alignItems: "baseline", gap: 8, marginBottom: 4 }}>
                            <span style={{ fontSize: 20, fontWeight: 700, color: flipColor, fontVariantNumeric: "tabular-nums" }}>{newly}</span>
                            <span style={{ color: "var(--text-secondary)" }}>
                              currently-allowed call{newly === 1 ? "" : "s"} would be <strong style={{ color: flipColor }}>newly blocked</strong>
                              {checked > 0 ? ` · of ${checked.toLocaleString()} replayed` : ""}
                            </span>
                          </div>
                          {(dryRunResult.newly_allowed ?? 0) > 0 && (
                            <div style={{ color: "var(--text-muted)", fontSize: 11.5 }}>
                              {dryRunResult.newly_allowed} previously-blocked call(s) would now be allowed
                            </div>
                          )}
                          {(dryRunResult.newly_blocked_samples?.length ?? 0) > 0 && (
                            <div style={{ marginTop: 8 }}>
                              <div style={{ color: "var(--text-muted)", fontSize: 11, textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 4 }}>
                                Newly-blocked calls (sample)
                              </div>
                              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                                {dryRunResult.newly_blocked_samples!.map((f, i) => (
                                  <span key={i} className="mono" style={{ fontSize: 11, padding: "2px 8px", borderRadius: 6, background: "#0e0e0e", border: "1px solid var(--border,#2a2a2a)", color: "var(--text-secondary)" }}>
                                    {f.tool_name} <span style={{ color: "var(--escalate)" }}>{f.was}→{f.now}</span>
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                          <div style={{ marginTop: 8, color: "var(--text-muted)", fontSize: 11.5 }}>
                            Replayed {checked.toLocaleString()} recent real call{checked === 1 ? "" : "s"}
                            {dryRunResult.scope?.agent_class ? ` for ${dryRunResult.scope.agent_class}` : ""}
                            {dryRunResult.truncated ? ` (capped at ${(dryRunResult.total_records_checked ?? 0).toLocaleString()})` : ""}
                            {" · "}would block {dryRunResult.would_block ?? 0}, allow {dryRunResult.would_allow ?? 0}
                            {(dryRunResult.would_escalate ?? 0) > 0 ? `, escalate ${dryRunResult.would_escalate}` : ""}.
                          </div>
                          <div style={{ marginTop: 6, fontWeight: 600 }}>{dryRunResult.recommendation ?? "n/a"}</div>
                        </>
                      );
                    })()}
                  </div>
                )}
              </div>
            </div>
          </Panel>
        )}

        {tab === "versions" && (
          <Panel
            title="Version History"
            sub={`${editorPolicy?.target ?? editorPolicy?.agent_class ?? "—"} · ${
              editorPolicy?.target_type ?? "class"
            }`}
            style={{ paddingBottom: 6 }}
          >
            <div style={{ overflowX: "auto" }}>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Version</th>
                    <th>Saved By</th>
                    <th>Saved At</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {(() => {
                    const vlist = versions.data ?? [];
                    // P6: the ACTIVE/enforcing version is the highest one (history is oldest→newest), not the
                    // first row — put CURRENT there so it matches the Catalog card + apply panel (e.g. v8, not v1).
                    const activeVersion = vlist.reduce((mx, v) => Math.max(mx, v.version), 0);
                    return vlist.flatMap((v) => {
                      const isCurrent = v.version === activeVersion;
                      const isViewing = viewV === v.version;
                      const rows = [
                    <tr key={v.version} style={{ cursor: "default" }}>
                      <td>
                        <span className="mono">v{v.version}</span>
                        {isCurrent && (
                          <span
                            className="pill"
                            style={{ marginLeft: 8, color: "#00e5a0", borderColor: "#00e5a040" }}
                          >
                            current
                          </span>
                        )}
                      </td>
                      <td className="mono muted">{v.saved_by ?? "system"}</td>
                      <td className="muted">{fmtDateTime(v.saved_at)}</td>
                      <td>
                        <div style={{ display: "flex", gap: 8 }}>
                          {/* MUT-VERSION: "View rego" reveals THIS version's actual source read-only (the
                              old "Load in Editor" loaded the current policy for every row — it lied). The
                              current row also offers a real "Load in Editor" (it IS the current policy). */}
                          <KitButton
                            variant="outline"
                            size="sm"
                            icon={FileCode}
                            data-testid={`version-view-${v.version}`}
                            onClick={() => setViewV(isViewing ? null : v.version)}
                          >
                            {isViewing ? "Hide rego" : "View rego"}
                          </KitButton>
                          {isCurrent && (
                            <KitButton
                              variant="outline"
                              size="sm"
                              icon={FileCode}
                              onClick={() => {
                                setTab("editor");
                                setActiveFile(editorPolicy?.target ?? editorPolicy?.agent_class ?? null);
                              }}
                            >
                              Load in Editor
                            </KitButton>
                          )}
                          {!isCurrent && (
                            <KitButton
                              variant="outline"
                              size="sm"
                              icon={RotateCcw}
                              onClick={() => setRestoreV(v.version)}
                            >
                              Restore
                            </KitButton>
                          )}
                        </div>
                      </td>
                    </tr>
                      ];
                      if (isViewing) {
                        rows.push(
                          <tr key={`${v.version}-rego`} data-testid={`version-rego-${v.version}`}>
                            <td colSpan={4} style={{ padding: 0 }}>
                              <pre
                                className="mono"
                                style={{
                                  margin: 0,
                                  padding: "12px 14px",
                                  background: "var(--bg-void)",
                                  borderTop: "1px solid var(--border)",
                                  fontSize: 12,
                                  lineHeight: 1.5,
                                  color: "var(--text-secondary)",
                                  whiteSpace: "pre-wrap",
                                  overflowX: "auto"
                                }}
                              >
                                {v.rego_source ?? "(rego not available for this version)"}
                              </pre>
                            </td>
                          </tr>
                        );
                      }
                      return rows;
                    });
                  })()}
                </tbody>
              </table>
              {(versions.data ?? []).length === 0 && (
                <div className="muted" style={{ fontSize: 13, padding: "16px 14px" }}>
                  No version history available.
                </div>
              )}
            </div>
          </Panel>
        )}
      </div>

      {selected && (
        <PolicySheet
          policy={selected}
          deployments={deployments.data ?? []}
          applyMode={applyMode}
          onClose={() => setSelected(null)}
          onApply={onApply}
          onAgentClassChange={(cls) =>
            setSelected((s) => (s ? { ...s, agent_class: cls, target: cls } : s))
          }
          onEditAsRawRego={(seed) => {
            // Close the composer, open the raw editor seeded with the generated rego + the composer's
            // scope. Marked unsaved so the author knows nothing has enforced yet (same as startNewPolicy).
            setSelected(null);
            setTab("editor");
            setActiveFile(null);
            resetDraftFlow();  // editing a composer-generated rego is a fresh authoring flow, not a draft apply
            setNewPolicy({ namespace: seed.namespace, agent_class: seed.agent_class, mode: seed.mode });
            setRegoDraft(seed.rego);
            setEditorStatus("unsaved");
            setDryRunResult(null);
            setApplyResult(null);
          }}
        />
      )}

      {deleteTarget != null && (
        <>
          <div className="sheet-overlay" onClick={() => setDeleteTarget(null)} />
          <div className="confirm-modal" data-testid="delete-policy-modal">
            <div className="sheet-title">
              Delete {deleteTarget.namespace}/{overlayDisplayLabel(deleteTarget.agent_class ?? deleteTarget.target)} · v{deleteTarget.current_version ?? 1}?
            </div>
            {/* Everything in /policies is loaded & enforcing, so deleting always changes the enforced state. */}
            <div
              data-testid="delete-policy-warning"
              style={{
                display: "flex", gap: 8, alignItems: "flex-start",
                margin: "12px 0 6px", padding: "10px 12px", borderRadius: "var(--radius-sm)",
                background: "#ff3b5c14", border: "1px solid #ff3b5c40", color: "#ffb0bd", fontSize: 12.5, lineHeight: 1.5
              }}
            >
              <TriangleAlert size={16} style={{ flex: "none", marginTop: 1, color: "#ff6b81" }} />
              {isRemediationOverlayClass(deleteTarget.agent_class) ? (
                <span>
                  This <strong>compliance remediation overlay</strong> is currently enforcing. Deleting it removes{" "}
                  <span className="mono">{overlayDisplayLabel(deleteTarget.agent_class)}</span>'s added block —{" "}
                  <strong>the class's own base policy is untouched</strong> and keeps enforcing exactly as before.
                  This cannot be undone and is durable across an api restart.
                </span>
              ) : (
                <span>
                  This policy is <strong>currently enforcing</strong>. Deleting it removes{" "}
                  <span className="mono">{deleteTarget.agent_class ?? deleteTarget.target}</span> from every layer
                  (engine, cache, database, version history) and flips the class back to the namespace baseline /
                  default — <strong>fail-closed (block) if no baseline exists</strong>. This cannot be undone and is
                  durable across an api restart.
                </span>
              )}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, marginTop: 14 }}>
              <KitButton variant="ghost" onClick={() => setDeleteTarget(null)}>
                Cancel
              </KitButton>
              <KitButton variant="destructive" icon={Trash2} data-testid="delete-policy-confirm" onClick={confirmDeletePolicy}>
                Delete policy
              </KitButton>
            </div>
          </div>
        </>
      )}

      {restoreV != null && (
        <>
          <div className="sheet-overlay" onClick={() => setRestoreV(null)} />
          <div className="confirm-modal">
            <div className="sheet-title">Restore version v{restoreV}?</div>
            <p
              style={{
                fontSize: 13,
                color: "var(--text-secondary)",
                lineHeight: 1.5,
                margin: "10px 0 18px"
              }}
            >
              This rolls the active policy back to v{restoreV}. The current version is preserved in
              history.
            </p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <KitButton variant="ghost" onClick={() => setRestoreV(null)}>
                Cancel
              </KitButton>
              <KitButton
                variant="primary"
                icon={RotateCcw}
                onClick={() => void confirmRestoreVersion()}
              >
                Confirm Restore
              </KitButton>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
