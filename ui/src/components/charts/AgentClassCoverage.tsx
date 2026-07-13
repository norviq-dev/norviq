// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// AGENT-CLASS coverage bars for the Overview — the dimension "Policy Coverage by Category" can't show.
// The category chart is horizontal (rule_ids per risk sector); a per-class positive-security policy
// (report-gen's default-deny allowlist) is keyed on the CLASS and governs the whole class. This renders
// one bar per applied agent-class policy; the bar reads "governed", coloured by whether it has PROVEN
// blocking (green) vs loaded-not-yet-proven (grey). Hover reveals exactly WHAT is enforced — the intended
// allowlist, the refinement toggles, the admin-promoted (learned) verbs, the mode, and 30d efficacy.

import { useState } from "react";
import { Panel } from "../common/Panel";
import type { AgentClassPolicy } from "../../api/client";

const REFINEMENT_LABEL: Record<string, string> = {
  readonly: "Read-only", egress: "No external egress", scope: "Namespace-scoped", rate: "Rate-limited",
};
const KIND_LABEL: Record<string, string> = { intent: "Positive-security (default-deny)", capability: "Capability defense", custom: "Custom rego" };

const COLLAPSED_LIMIT = 6; // cap the resting height; the rest fold behind a "+N more" toggle

export function AgentClassCoverage({ policies, namespaceMode, bare = false }: { policies: AgentClassPolicy[]; namespaceMode?: string; bare?: boolean }) {
  const [hover, setHover] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  if (!policies.length) return null;
  const monitor = namespaceMode === "audit";

  // SCALE: a namespace can govern many classes — an unbounded list would blow out the card. Show the
  // first COLLAPSED_LIMIT (backend already sorts most-relevant first: proven, then A→Z) and fold the rest
  // behind a "+N more" toggle. Kept as an expander (not a fixed-height scroll) so the absolute-positioned
  // hover tooltips never clip against an overflow:auto edge.
  const visible = expanded ? policies : policies.slice(0, COLLAPSED_LIMIT);
  const overflow = policies.length - visible.length;

  // Clean, color-first rows that MATCH the risk-category bars: a left label + a full-width bar whose
  // COLOUR carries the state (green = proven-blocking, grey = loaded-not-proven), no verbose text badge.
  // Everything else (what's enforced, efficacy) lives in the hover so the resting card stays quiet.
  const rows = (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {visible.map((p) => {
        const color = p.effective ? "#00E5A0" : "#5f6b7a";
        return (
          <div
            key={p.cls}
            data-testid="agent-class-cov-row"
            onMouseEnter={() => setHover(p.cls)}
            onMouseLeave={() => setHover((h) => (h === p.cls ? null : h))}
            style={{ position: "relative", display: "flex", alignItems: "center", gap: 12, cursor: "default" }}
          >
            <span style={{ flex: "none", width: 130, fontSize: 12, color: "var(--text-secondary)", fontFamily: "ui-monospace, monospace", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", textAlign: "right" }}>{p.cls}</span>
            <div style={{ flex: 1, height: 13, borderRadius: 4, background: "rgba(255,255,255,0.05)", overflow: "hidden" }}>
              {/* Default-deny governs 100% of the class; colour = proven vs loaded, dimmed under Monitor. */}
              <div style={{ width: "100%", height: "100%", borderRadius: 4, background: color, opacity: p.enforcing ? 1 : 0.55 }} />
            </div>

            {hover === p.cls && (
              <div
                role="tooltip"
                style={{ position: "absolute", zIndex: 20, top: "100%", left: 142, marginTop: 4, minWidth: 260, maxWidth: 340, padding: "11px 13px", background: "#252525", border: "1px solid #3a3a3a", borderRadius: 10, boxShadow: "0 18px 40px -14px rgba(0,0,0,0.85)", fontSize: 11.5, lineHeight: 1.55, color: "#e8edf5" }}
              >
                <div style={{ fontWeight: 700, marginBottom: 4 }}>{p.cls} · {KIND_LABEL[p.kind] ?? p.kind}</div>
                <Row label="Intended tools">
                  {p.allow_tools.length ? p.allow_tools.join(", ") : (p.kind === "intent" ? "none — denies every tool for the class" : "—")}
                </Row>
                <Row label="Refinements">
                  {p.refinements.length ? p.refinements.map((r) => REFINEMENT_LABEL[r] ?? r).join(", ") : "none"}
                </Row>
                {p.learned_verbs.length > 0 && (
                  <Row label="Learned verbs">{p.learned_verbs.join(", ")}</Row>
                )}
                <Row label="Mode">
                  {p.enforcement_mode}{!p.enforcing && monitor ? " (namespace in Monitor — logs, not enforced)" : ""} · priority {p.priority}
                </Row>
                <Row label="Last 30d">
                  <span style={{ color: "#34d399" }}>{p.blocked}</span> blocked
                  {p.would_block > 0 ? <> · <span style={{ color: "#f5b544" }}>{p.would_block}</span> would-block</> : null}
                  {" "}· {p.observed} governed calls
                </Row>
                {!p.effective && (
                  <div style={{ marginTop: 6, color: "#a0a0a0" }}>Loaded but no traffic has proven it blocking yet.</div>
                )}
              </div>
            )}
          </div>
        );
      })}
      {(overflow > 0 || expanded) && policies.length > COLLAPSED_LIMIT && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          style={{ alignSelf: "flex-start", marginTop: 2, background: "transparent", border: "none", color: "var(--text-muted)", fontFamily: "inherit", fontSize: 11.5, cursor: "pointer", padding: "2px 0" }}
        >
          {expanded ? "Show fewer" : (
            <>
              <span style={{ color: "var(--accent)", fontWeight: 700 }}>+{overflow}</span> more class{overflow === 1 ? "" : "es"} →
            </>
          )}
        </button>
      )}
    </div>
  );

  // Bare mode: the parent "Policy Coverage" card supplies the section label + the one shared legend.
  if (bare) return rows;
  return (
    <Panel title="Policy Coverage by Agent Class">
      {rows}
    </Panel>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", gap: 8, marginTop: 3 }}>
      <span style={{ flex: "none", width: 88, color: "#a0a0a0" }}>{label}</span>
      <span style={{ minWidth: 0, overflowWrap: "anywhere" }}>{children}</span>
    </div>
  );
}

export default AgentClassCoverage;
