// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Attack Graph ranked path list: the PRIMARY nav. Rows come pre-sorted
// worst-first from the server (exploitable → unsimulated → blocked, severity tiebreak) — we keep that
// order stable. Each row: severity chip + src→tgt + status chip + hops/blast/MITRE. Clicking a row
// selects the path (drives the canvas + inspector).

import { SEVERITY_COLORS, STATUS_META } from "./constants";
import type { PathStatus, ThreatPath } from "./types";

/** Classification-lifecycle stage of the path's chokepoint tool — one glanceable chip per card:
 *  "✓ delete · learned" (admin-promoted) / "delete" (registry) / "observing 10/12" (evidence accruing)
 *  / "unclassified" (nothing proven yet). Derived from the hop the backend already resolved. */
function lifecycleChip(p: ThreatPath): { text: string; color: string; border: string; title: string } | null {
  const st = p.steps.find((s) => s.kind === "tool" && s.to === p.tool) ?? p.steps.find((s) => s.kind === "tool");
  if (!st) return null;
  if (st.op) {
    if (st.op_src === "learned") {
      return { text: `✓ ${st.op} · learned`, color: "#6ee7b7", border: "#1f4635", title: `Verb promoted by an admin from observed evidence — ${st.op_risk ?? "?"} risk.` };
    }
    const c = SEVERITY_COLORS[st.op_risk ?? "low"];
    return { text: st.op, color: c, border: c + "55", title: `${st.op} operation (name classifier) · ${st.op_risk ?? "low"} risk.` };
  }
  if (st.inferred_verb) {
    return { text: `observing ${st.inferred_count}/${st.observed_calls}`, color: "#ffcf82", border: "#4a3a1a", title: `Under observation — params suggest "${st.inferred_verb}" (${st.inferred_count} of ${st.observed_calls} evidenced calls). Promote it from the intent builder or Tool verbs panel.` };
  }
  return { text: "unclassified", color: "#a0a0a0", border: "#2a2a2a", title: "Operation unknown — under observation until its calls reveal a verb. Review before allowing." };
}

interface Props {
  paths: ThreatPath[];
  selectedId?: string;
  /** REAL status per path (sim result or baseline) — a what-if never changes this. */
  statusOf: (p: ThreatPath) => PathStatus;
  /** Path ids that currently carry a HYPOTHETICAL what-if block — badged distinctly. */
  whatIfIds?: Set<string>;
  onSelect: (path: ThreatPath) => void;
}

export function AttackPathList({ paths, selectedId, statusOf, whatIfIds, onSelect }: Props) {
  // Open-ended: the list grows with the path count — the PAGE scrolls, never an inner scrollbar.
  return (
    // A rounded card that holds the ranked list; the page scrolls (no inner scrollbar).
    <div style={{ flex: "0 1 244px", minWidth: 214, background: "var(--bg-graph-card)", border: "1px solid var(--graph-border)", borderRadius: 14, overflow: "hidden" }}>
      <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.05em", color: "#6e6e6e", textTransform: "uppercase", padding: "14px 16px 8px" }}>
        Attack paths · worst first
      </div>
      {paths.map((p) => {
        const active = p.id === selectedId;
        const sm = STATUS_META[statusOf(p)];
        const whatIf = whatIfIds?.has(p.id) ?? false;
        const sev = SEVERITY_COLORS[p.sev];
        return (
          <button
            key={p.id}
            type="button"
            onClick={() => onSelect(p)}
            aria-pressed={active}
            style={{
              display: "block", width: "100%", textAlign: "left", padding: "13px 16px", borderBottom: "1px solid var(--graph-border-soft)",
              borderLeft: 0, borderRight: 0, borderTop: 0, cursor: "pointer", fontFamily: "inherit",
              background: active ? "#232323" : "transparent", boxShadow: active ? "inset 3px 0 0 #c084fc" : "none"
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 7 }}>
              <span style={{ fontSize: 9.5, fontWeight: 800, padding: "2px 8px", borderRadius: 999, textTransform: "uppercase", letterSpacing: "0.04em", background: sev + "22", color: sev }}>
                {p.sev}
              </span>
              <span style={{ marginLeft: "auto", fontSize: 9.5, fontWeight: 800, padding: "2px 8px", borderRadius: 999, background: sm.bg, color: sm.color }}>
                {sm.label}
              </span>
              {/* A defense is APPLIED for this chokepoint even though the audit-derived status may still
                  read exploitable (no post-apply traffic yet). Teal "defended" chip nudges to Simulate. */}
              {p.governed_by && statusOf(p) === "exploitable" && (
                <span
                  data-testid="path-governed-chip"
                  title={`An applied ${p.governed_by} policy denies '${p.tool}' for this class. This status is from past traffic — Simulate to confirm the defense neutralizes it now.`}
                  style={{ fontSize: 9.5, fontWeight: 800, padding: "1px 7px", borderRadius: 999, border: "1px solid #1f4635", color: "#6ee7b7", background: "rgba(45,218,184,0.06)", textTransform: "uppercase", letterSpacing: "0.04em" }}
                >
                  defended
                </span>
              )}
              {/* A hypothetical block is a DISTINCT, dashed amber chip — never the solid green
                  BLOCKED chip a real block earns. */}
              {whatIf && (
                <span
                  data-testid="path-whatif-chip"
                  style={{ fontSize: 9.5, fontWeight: 800, padding: "1px 7px", borderRadius: 999, border: "1px dashed var(--escalate)", color: "var(--escalate)", background: "transparent", textTransform: "uppercase", letterSpacing: "0.04em" }}
                >
                  what-if
                </span>
              )}
            </div>
            <div style={{ fontSize: 13, fontWeight: 650, lineHeight: 1.4, wordBreak: "break-word" }}>
              <span style={{ color: "#e8edf5" }}>{p.src}</span>
              <span style={{ color: "#5b6577", padding: "0 3px" }}>→</span>
              <span style={{ color: "#ff8fa3" }}>{p.tgt}</span>
            </div>
            <div style={{ fontSize: 11, color: "#8a8a8a", marginTop: 6, display: "flex", flexWrap: "wrap", alignItems: "center", gap: "4px 12px" }}>
              <span>{p.hops} hops</span>
              <span style={{ color: "#d08a99" }}>blast {p.blast}</span>
              <span style={{ fontFamily: "ui-monospace, monospace" }}>{p.mitre.split(" ·")[0]}</span>
              {(() => {
                const lc = lifecycleChip(p);
                return lc ? (
                  <span
                    data-testid="path-lifecycle-chip"
                    title={lc.title}
                    style={{ fontSize: 9, fontWeight: 700, padding: "1px 7px", borderRadius: 999, border: `1px solid ${lc.border}`, color: lc.color, textTransform: "uppercase", letterSpacing: "0.04em" }}
                  >
                    {lc.text}
                  </span>
                ) : null;
              })()}
            </div>
          </button>
        );
      })}
    </div>
  );
}
