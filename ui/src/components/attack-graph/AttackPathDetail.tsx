// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Attack Graph inspector (design_handoff_attackgraph): severity, MITRE, ns/class chips, hops, min-trust,
// blast radius, chokepoint tool, the step-by-step kill chain with decision dots + per-hop what-if block
// toggle, the recommended fix (scope, not remove) with "Define intended behaviour", the live verdict, a
// "Simulate" action (REAL /evaluate per step — labeled PREVIEW), and — when a what-if is active — a
// "Draft blocking policy" button. Sits in the right column; a `side` prop lets the page flip it (matching
// AssetNodeDetail) though the design keeps it right by default.

import { useNavigate } from "react-router-dom";
import { SEVERITY_COLORS, STEP_DECISION_COLORS } from "./constants";
import type { PathStatus, ThreatPath } from "./types";

// `monitor` = the path IS covered by a policy but the namespace is in Monitor mode (evaluated, not
// enforced) — a would-block, NOT a policy gap. Rendered distinctly from a real enforced block or a gap.
export type SimResult = { blocked: boolean; label: string; monitor?: boolean } | null;

interface Props {
  path: ThreatPath;
  /** REAL status (sim result or baseline). A what-if does NOT change this — it is surfaced via
   *  whatIfIndex + the amber hypothetical verdict below (MUT-4). */
  status: PathStatus;
  /** Which hop is what-if blocked on this path (-1 = none). */
  whatIfIndex: number;
  simResult: SimResult;
  simulating: boolean;
  drafted: boolean;
  /** AG-DRAFT-01: the persisted draft's deep-link (/policies/catalog?intent_draft=<id>), once created. */
  draftLink?: string;
  /** AG-DRAFT-01: a draft-creation error to surface (never a fake success). */
  draftError?: string;
  onToggleWhatIf: (index: number) => void;
  onDefineIntent: () => void;
  onSimulate: () => void;
  onDraft: () => void;
}

const card: React.CSSProperties = { padding: "11px 12px", background: "var(--bg-graph-card)", border: "1px solid var(--graph-border-soft)", borderRadius: 10 };
// "Define {class}'s intended behaviour" — the class name is dynamic, so the label can wrap to 2 lines.
// GROW with the content (minHeight, not a fixed height) and top-align the icon so wrapped text never
// spills past the button border. flex-start on the cross axis keeps the icon on the first line.
const defineBtn: React.CSSProperties = {
  marginTop: 10, width: "100%", minHeight: 34, padding: "8px 12px", display: "flex", alignItems: "flex-start",
  justifyContent: "center", gap: 7, border: "1px solid #2ddab8", borderRadius: 8, background: "rgba(45,218,184,0.14)",
  color: "#2ddab8", fontFamily: "inherit", fontSize: 12, fontWeight: 700, lineHeight: 1.35, textAlign: "center", cursor: "pointer"
};
const chip: React.CSSProperties = {
  display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, color: "#b8c2d6",
  background: "var(--bg-graph-card)", border: "1px solid var(--graph-border-soft)", borderRadius: 999, padding: "4px 10px"
};

export function AttackPathDetail({
  path, status, whatIfIndex, simResult, simulating, drafted, draftLink, draftError,
  onToggleWhatIf, onDefineIntent, onSimulate, onDraft
}: Props) {
  const navigate = useNavigate();
  const sev = SEVERITY_COLORS[path.sev];
  const naturalBlock = path.steps.some((st) => st.dec === "block");
  const trustColor = path.trust >= 0.8 ? "#34d399" : path.trust >= 0.6 ? "#fbbf24" : "#ff8fa3";
  // MUT-4: an active what-if gets its OWN amber verdict — it must never borrow the green "blocked"
  // styling of a real block. It is a hypothetical, and the copy says so ("WOULD flip to blocked").
  const verdictStyle =
    whatIfIndex >= 0 ? { bg: "rgba(58,42,10,0.6)", color: "var(--escalate)", icon: "◑" }
    : status === "blocked" ? { bg: "rgba(13,42,28,0.6)", color: "#6ee7b7", icon: "✓" }
    : status === "exploitable" ? { bg: "rgba(42,15,22,0.6)", color: "#ff8fa3", icon: "⚠" }
    : { bg: "rgba(38,38,38,0.6)", color: "#9aa4b2", icon: "○" };  /* A6: navy→neutral grey */
  const verdict = whatIfIndex >= 0
    ? `What-if (hypothetical): blocking ${path.steps[whatIfIndex].to} at step ${whatIfIndex + 1} WOULD neutralize this path — it would flip to blocked. Nothing is enforced until you apply a policy.`
    : path.verdict;
  const showFix = !!path.fix && !naturalBlock;

  return (
    <div
      role="complementary"
      aria-label="Attack path inspector"
      style={{
        // A rounded card holding the inspector; the page scrolls (no inner scrollbar).
        flex: "0 0 288px", background: "var(--bg-graph-card)", border: "1px solid var(--graph-border)", borderRadius: 14,
        display: "flex", flexDirection: "column", animation: "agSlide 0.22s ease both", overflow: "hidden"
      }}
    >
      <div style={{ padding: "16px 16px 14px", borderBottom: "1px solid var(--graph-border-soft)" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.1em", color: "#8a8a8a", textTransform: "uppercase" }}>Attack path</div>
          <span style={{ fontSize: 9.5, fontWeight: 800, padding: "2px 9px", borderRadius: 999, textTransform: "uppercase", letterSpacing: "0.04em", background: sev + "22", color: sev }}>{path.sev}</span>
        </div>
        <div style={{ fontSize: 15, fontWeight: 700, marginTop: 7, lineHeight: 1.3, wordBreak: "break-word" }}>
          {path.src} <span style={{ color: "#5b6577" }}>→</span> <span style={{ color: "#ff8fa3" }}>{path.tgt}</span>
        </div>
        <div style={{ marginTop: 9 }}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 10.5, color: "#2ddab8", border: "1px solid #2a2a2a", background: "#232323", borderRadius: 6, padding: "3px 8px", fontFamily: "ui-monospace, monospace" }}>
            MITRE {path.mitre}
          </span>
        </div>
      </div>

      <div style={{ padding: 16, flex: 1 }}>
        {/* A defense is APPLIED for this chokepoint, but the status is derived from PAST traffic and can
            lag a fresh apply. Tell the operator their policy is in place + point at Simulate to confirm. */}
        {path.governed_by && status === "exploitable" && whatIfIndex < 0 && (
          <div
            data-testid="path-defended-note"
            style={{ display: "flex", alignItems: "flex-start", gap: 8, marginBottom: 12, padding: "10px 12px", borderRadius: 10, background: "rgba(45,218,184,0.07)", border: "1px solid #1f4635" }}
          >
            <span style={{ flex: "none", marginTop: 1, color: "#6ee7b7" }}>🛡</span>
            <div style={{ fontSize: 11.5, lineHeight: 1.5, color: "#cfe8dd" }}>
              An applied <b style={{ color: "#6ee7b7" }}>{path.governed_by}</b> policy already denies <b style={{ fontFamily: "ui-monospace, monospace" }}>{path.tool}</b> for this class. This status reflects <i>past</i> traffic — <b>Simulate</b> to confirm the defense neutralizes it now.
            </div>
          </div>
        )}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginBottom: 8 }}>
          <div style={card}>
            <div style={{ fontSize: 10.5, color: "#8a8a8a", textTransform: "uppercase", letterSpacing: "0.04em" }}>Hops</div>
            <div style={{ fontSize: 15, fontWeight: 700, marginTop: 6, fontVariantNumeric: "tabular-nums" }}>{path.hops}</div>
          </div>
          <div style={card}>
            <div style={{ fontSize: 10.5, color: "#8a8a8a", textTransform: "uppercase", letterSpacing: "0.04em" }}>Min trust</div>
            <div style={{ fontSize: 15, fontWeight: 700, marginTop: 6, color: trustColor, fontVariantNumeric: "tabular-nums" }}>{path.trust.toFixed(2)}</div>
          </div>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 13, padding: "12px 14px", marginBottom: 16, background: "linear-gradient(180deg, rgba(255,59,92,0.07), rgba(255,59,92,0.02))", border: "1px solid #2a1820", borderRadius: 11 }}>
          <div style={{ fontSize: 28, fontWeight: 700, lineHeight: 1, letterSpacing: "-0.02em", color: "#ff7088", fontVariantNumeric: "tabular-nums" }}>{path.blast}</div>
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", color: "#ff7088", textTransform: "uppercase" }}>Blast radius</div>
            <div style={{ fontSize: 11.5, color: "#a0a0a0", marginTop: 2, lineHeight: 1.35 }}>assets reachable if this target is compromised</div>
          </div>
        </div>

        <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 16 }}>
          <span style={chip}><span style={{ color: "#8a8a8a" }}>ns</span>{path.ns}</span>
          <span style={chip}><span style={{ color: "#8a8a8a" }}>class</span>{path.cls}</span>
          {path.tool && <span style={chip}><span style={{ color: "#8a8a8a" }}>chokepoint</span>{path.tool}</span>}
        </div>

        {showFix && (
          <div style={{ marginBottom: 14, padding: "11px 12px", background: "rgba(45,218,184,0.07)", border: "1px solid #2a2a2a", borderRadius: 10 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 10.5, fontWeight: 700, letterSpacing: "0.06em", color: "#2ddab8" }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5.7.7 1.3 1.5 1.5 2.5" /><path d="M9 18h6" /><path d="M10 22h4" /></svg>
              RECOMMENDED FIX
            </div>
            <div style={{ fontSize: 11.5, color: "#b8c2d6", marginTop: 6, lineHeight: 1.5 }}>{path.fix}</div>
            <button
              type="button" onClick={onDefineIntent}
              style={defineBtn}
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none", marginTop: 1 }}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></svg>
              <span>Define {path.cls}&apos;s intended behaviour</span>
            </button>
          </div>
        )}

        {/* Positive-security intent is available for EVERY path, not only the not-yet-blocked ones: for an
            already-blocked path it turns a specific block rule into a durable default-deny for the class. */}
        {!showFix && (
          <div style={{ marginBottom: 14, padding: "11px 12px", background: "rgba(45,218,184,0.05)", border: "1px solid #241d3f", borderRadius: 10 }}>
            <div style={{ fontSize: 11.5, color: "#8fa0bd", lineHeight: 1.5 }}>
              {status === "blocked"
                ? `Blocked today by a specific rule. Define ${path.cls}'s intended behaviour to make the block durable (default-deny for the class).`
                : `Define ${path.cls}'s intended behaviour — allow only intended calls, deny everything else.`}
            </div>
            <button
              type="button" onClick={onDefineIntent}
              style={defineBtn}
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none", marginTop: 1 }}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></svg>
              <span>Define {path.cls}&apos;s intended behaviour</span>
            </button>
          </div>
        )}

        {/* Simulate: run each step as a REAL /evaluate call — labeled PREVIEW (nothing enforces). */}
        <button
          type="button" onClick={onSimulate} disabled={simulating}
          style={{ width: "100%", height: 32, marginBottom: 14, display: "flex", alignItems: "center", justifyContent: "center", gap: 7, border: "1px solid var(--graph-border)", borderRadius: 8, background: "var(--bg-graph-card)", color: "#2ddab8", fontFamily: "inherit", fontSize: 12, fontWeight: 700, cursor: simulating ? "default" : "pointer" }}
        >
          <svg width="12" height="12" viewBox="0 0 24 24"><path d="M6 3l14 9-14 9V3z" fill="currentColor" /></svg>
          {simulating ? "Simulating…" : "Simulate (preview)"}
        </button>
        {simResult && (() => {
          // Three visual states: enforced block (green), Monitor would-block (amber — covered but not
          // enforcing), genuine gap (red). Monitor is NEVER shown as a red "gap".
          const tone = simResult.monitor
            ? { bg: "rgba(42,32,10,0.5)", fg: "var(--escalate)", bd: "#4a3a10" }
            : simResult.blocked
            ? { bg: "rgba(13,42,28,0.5)", fg: "#6ee7b7", bd: "#1f4635" }
            : { bg: "rgba(42,15,22,0.5)", fg: "#ff8fa3", bd: "#3a1420" };
          return (
            <div
              role="status"
              style={{ marginTop: -6, marginBottom: 14, padding: "8px 11px", borderRadius: 8, fontSize: 11.5, fontWeight: 600, background: tone.bg, color: tone.fg, border: `1px solid ${tone.bd}` }}
            >
              PREVIEW · {simResult.label}
            </div>
          );
        })()}

        <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.04em", color: "#8a8a8a", textTransform: "uppercase", marginBottom: 10 }}>Step-by-step</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          {path.steps.map((st, i) => {
            const eff = whatIfIndex === i ? "block" : st.dec;
            const dot = STEP_DECISION_COLORS[eff];
            const decision = eff === "block"
              ? (whatIfIndex === i ? "What-if blocked" : "Blocked · " + st.deny + " denied")
              : eff === "would_block"
                ? "Monitor · " + (st.would_block ?? 0) + " would-block (logged, not enforced)" + (st.allow > 0 ? " · " + st.allow + " allowed" : "")
              : st.dec === "mixed" ? "Partial · " + st.deny + " denied / " + st.allow + " allowed"
              : "Allowed · " + st.allow + " calls";
            const togActive = whatIfIndex === i;
            return (
              <div key={i} style={{ display: "flex", gap: 11, alignItems: "flex-start" }}>
                <div style={{ display: "flex", flexDirection: "column", alignItems: "center", alignSelf: "stretch" }}>
                  <span style={{ width: 22, height: 22, flex: "none", borderRadius: "50%", border: `1.5px solid ${dot}`, color: dot, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 700 }}>{i + 1}</span>
                  <span style={{ flex: 1, width: 1.5, background: i === path.steps.length - 1 ? "transparent" : "var(--graph-border-soft)" }} />
                </div>
                <div style={{ flex: 1, minWidth: 0, paddingBottom: 14 }}>
                  <div style={{ fontSize: 12.5, color: "#d3dae6", lineHeight: 1.45, wordBreak: "break-word" }}>
                    <b style={{ color: "#e8edf5" }}>{st.from}</b> {st.verb} <b style={{ color: "#e8edf5" }}>{st.to}</b>
                    {/* CAP-2 + lifecycle: the ACTUAL operation on the hop, coloured by its verb risk — a
                        destructive DELETE hop reads differently from a benign READ. On a TOOL hop the
                        classifier lifecycle shows through: "✓" when the verb was admin-promoted (learned),
                        or the observation state ("observing · delete 12/14") while the verb is unproven. */}
                    {st.op ? (
                      <span
                        title={`${st.op} operation on ${st.to} — ${st.op_risk ?? "unknown"} risk${st.op_src === "learned" ? " · verb promoted from observed evidence" : ""}`}
                        style={{
                          marginLeft: 8, padding: "1px 7px", borderRadius: 5, fontSize: 10, fontWeight: 800,
                          letterSpacing: "0.05em", textTransform: "uppercase", verticalAlign: "middle",
                          color: SEVERITY_COLORS[st.op_risk ?? "low"],
                          border: `1px solid ${SEVERITY_COLORS[st.op_risk ?? "low"]}`,
                          background: "transparent"
                        }}
                      >
                        {st.op}{st.op_src === "learned" ? " ✓" : ""}
                      </span>
                    ) : st.kind === "tool" && st.inferred_verb ? (
                      <span
                        title={`Unclassified by name — under observation. Observed params suggest "${st.inferred_verb}" (${st.inferred_count} of ${st.observed_calls} evidenced calls). Promote it from the intent builder.`}
                        style={{
                          marginLeft: 8, padding: "1px 7px", borderRadius: 5, fontSize: 10, fontWeight: 700,
                          letterSpacing: "0.04em", textTransform: "uppercase", verticalAlign: "middle",
                          color: "#ffcf82", border: "1px solid #4a3a1a", background: "transparent"
                        }}
                      >
                        observing · {st.inferred_verb} {st.inferred_count}/{st.observed_calls}
                      </span>
                    ) : null}
                  </div>
                  <div style={{ fontSize: 11, fontWeight: 600, color: dot, marginTop: 4, lineHeight: 1.3 }}>{decision}</div>
                  {st.dec !== "block" && (
                    <button
                      type="button" onClick={() => onToggleWhatIf(i)}
                      style={{ marginTop: 7, display: "inline-flex", alignItems: "center", gap: 6, height: 24, padding: "0 10px", borderRadius: 7, background: togActive ? "#3a1420" : "var(--bg-graph-card)", border: `1px solid ${togActive ? "#FF3B5C" : "var(--graph-border)"}`, color: togActive ? "#ff9fb0" : "#a0a0a0", fontFamily: "inherit", fontSize: 11, fontWeight: 600, cursor: "pointer" }}
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><circle cx="12" cy="12" r="9" /><path d="m5.6 5.6 12.8 12.8" /></svg>
                      {togActive ? "Undo what-if block" : "Block this step (what-if)"}
                    </button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ padding: "12px 16px", borderTop: "1px solid var(--graph-border-soft)", background: verdictStyle.bg }}>
        <div style={{ display: "flex", alignItems: "flex-start", gap: 9, fontSize: 12, fontWeight: 600, color: verdictStyle.color, lineHeight: 1.4 }}>
          <span style={{ flex: "none", marginTop: 1 }}>{verdictStyle.icon}</span>
          <span style={{ minWidth: 0, overflowWrap: "anywhere" }}>{verdict}</span>
        </div>
        {whatIfIndex >= 0 && (
          <>
            <button
              type="button"
              // AG-DRAFT-01: once the draft persists, the confirmation deep-links to it in Policy Catalog (no fake label).
              onClick={() => (drafted && draftLink ? navigate(draftLink) : onDraft())}
              disabled={drafted && !draftLink}
              data-testid="ag-draft-button"
              title={drafted && draftLink ? "Open the dry-run draft in Policy Catalog" : undefined}
              style={{ marginTop: 10, width: "100%", height: 30, display: "flex", alignItems: "center", justifyContent: "center", gap: 7, borderRadius: 8, border: drafted ? "1px solid #1f4635" : "1px solid transparent", background: drafted ? "transparent" : "linear-gradient(180deg, #2ddab8, #22c4a4)", color: drafted ? "#6ee7b7" : "#0d0d0d", fontFamily: "inherit", fontSize: 12, fontWeight: 700, cursor: drafted && !draftLink ? "default" : "pointer", textDecoration: drafted && draftLink ? "underline" : "none" }}
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" /></svg>
              {drafted ? "✓ Draft created · open dry-run in Policies →" : "Draft blocking policy"}
            </button>
            {draftError && <div role="alert" style={{ marginTop: 6, fontSize: 11, color: "#ff8fa3" }}>{draftError}</div>}
          </>
        )}
      </div>
    </div>
  );
}
