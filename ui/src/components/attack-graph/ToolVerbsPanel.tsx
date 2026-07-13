// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Tool verbs panel — the MANAGEMENT home for the tool-classification lifecycle (observe → infer →
// promote). Two sections:
//   OBSERVING: every still-unclassified tool with param evidence — the verb histogram, the inferred
//   suggestion, and per-verb promote buttons (the admin's choice always wins over the inference).
//   LEARNED: every promoted override — verb + risk, who promoted it, when, the evidence that justified
//   it, and a Demote action back to observation.
// Read-only for viewers; promote/demote are admin actions (backend-enforced, buttons hidden otherwise).

import { useCallback, useEffect, useState } from "react";
import {
  demoteToolVerb,
  fetchToolVerbs,
  promoteToolVerb,
  type ToolVerbCandidate,
  type ToolVerbOverride,
} from "../../api/client";
import { SEVERITY_COLORS } from "./constants";

interface Props {
  ns: string;
  isAdmin: boolean;
  onClose: () => void;
  /** Fired after any promote/demote so the page can refresh path stage tags. */
  onChanged: () => void;
}

const VERBS = ["read", "write", "send", "delete"] as const;
const VERB_RISK: Record<string, string> = { read: "low", write: "high", send: "high", delete: "critical" };

export function ToolVerbsPanel({ ns, isAdmin, onClose, onChanged }: Props) {
  const [overrides, setOverrides] = useState<ToolVerbOverride[]>([]);
  const [candidates, setCandidates] = useState<ToolVerbCandidate[]>([]);
  const [scope, setScope] = useState<string>(ns);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    fetchToolVerbs(ns)
      .then((r) => {
        setOverrides(r.overrides ?? []);
        setCandidates(r.candidates ?? []);
        setScope(ns && ns !== "all" ? ns : (r.namespaces?.[0] ?? ns));
        setError("");
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Could not load tool verbs"))
      .finally(() => setLoading(false));
  }, [ns]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const promote = async (tool: string, verb: string, targetNs?: string) => {
    if (busy) return;
    setBusy(tool);
    setError("");
    try {
      await promoteToolVerb({ ns: targetNs ?? scope, tool_name: tool, verb });
      load();
      onChanged();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Promotion failed");
    } finally {
      setBusy(null);
    }
  };

  const demote = async (o: ToolVerbOverride) => {
    if (busy) return;
    setBusy(o.tool_name);
    setError("");
    try {
      await demoteToolVerb(o.namespace, o.tool_name);
      load();
      onChanged();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Demotion failed");
    } finally {
      setBusy(null);
    }
  };

  const riskColor = (r: string | null | undefined) => SEVERITY_COLORS[(r ?? "low") as keyof typeof SEVERITY_COLORS] ?? "#6e6e6e";

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 80, display: "flex", alignItems: "center", justifyContent: "center", padding: 24, background: "rgba(6,7,10,0.72)", backdropFilter: "blur(3px)" }}>
      <div onClick={onClose} style={{ position: "absolute", inset: 0 }} aria-hidden="true" />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Tool verbs · classification lifecycle"
        style={{ position: "relative", zIndex: 1, width: 640, maxWidth: "100%", maxHeight: "86vh", display: "flex", flexDirection: "column", background: "linear-gradient(180deg, var(--bg-graph-card), var(--bg-graph-panel))", border: "1px solid var(--graph-border)", borderRadius: 16, overflow: "hidden", boxShadow: "0 40px 90px -30px rgba(0,0,0,0.85)" }}
      >
        <div style={{ padding: "20px 22px 14px", borderBottom: "1px solid var(--graph-border-soft)" }}>
          <div style={{ fontSize: 10.5, fontWeight: 800, letterSpacing: "0.14em", color: "#2ddab8" }}>TOOL CLASSIFICATION · LIFECYCLE</div>
          <div style={{ fontSize: 18, fontWeight: 700, marginTop: 5 }}>
            Tool verbs · <span style={{ fontFamily: "ui-monospace, monospace", color: "#2ddab8" }}>{ns || "all"}</span>
          </div>
          <div style={{ fontSize: 12, color: "#a0a0a0", marginTop: 5, lineHeight: 1.5 }}>
            <b style={{ color: "#ffcf82" }}>Observe</b> — an unclassified tool's calls are logged; params reveal its verb as evidence.{" "}
            <b style={{ color: "#ffcf82" }}>Infer</b> — the evidence suggests a verb.{" "}
            <b style={{ color: "#6ee7b7" }}>Promote</b> — an admin confirms (or overrides) the verb; it then classifies the tool everywhere. Demote returns it to observation.
          </div>
        </div>

        <div style={{ flex: 1, overflowY: "auto", padding: "16px 22px 20px", display: "flex", flexDirection: "column", gap: 18 }}>
          {error && <div role="alert" style={{ fontSize: 12, color: "#ff8fa3" }}>{error}</div>}
          {loading ? (
            <div style={{ fontSize: 12, color: "#a0a0a0" }}>Loading tool classifications…</div>
          ) : (
            <>
              {/* ── OBSERVING candidates ─────────────────────────────────────────── */}
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", color: "#ffcf82", textTransform: "uppercase", marginBottom: 8 }}>
                  Observing · {candidates.length} candidate{candidates.length === 1 ? "" : "s"}
                </div>
                {candidates.length === 0 ? (
                  <div style={{ fontSize: 12, color: "#a0a0a0", lineHeight: 1.5 }}>
                    No tools under observation with evidence. An unclassified tool appears here once its observed
                    params reveal what it does (a SQL body, a destination field).
                  </div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {candidates.map((c) => {
                      const total = Math.max(1, c.calls);
                      return (
                        <div key={c.tool_name} data-testid="toolverb-candidate" style={{ padding: "11px 13px", borderRadius: 10, background: "var(--bg-graph-card)", border: "1px solid #4a3a1a" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                            <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12.5, fontWeight: 650, color: "#e8edf5", overflowWrap: "anywhere" }}>{c.tool_name}</span>
                            <span style={{ fontSize: 10, fontWeight: 700, padding: "1px 7px", borderRadius: 999, background: "#3a2410", color: "#ffcf82", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                              observing · {c.calls} evidenced call{c.calls === 1 ? "" : "s"}
                            </span>
                            {c.inferred_verb && (
                              <span style={{ fontSize: 10, color: "#a0a0a0" }}>
                                suggests <b style={{ color: riskColor(c.suggested_risk) }}>{c.inferred_verb}</b> · {c.suggested_risk} risk
                              </span>
                            )}
                          </div>
                          {/* evidence histogram — one bar per verb seen in params */}
                          <div style={{ marginTop: 8, display: "flex", flexDirection: "column", gap: 4 }}>
                            {Object.entries(c.verbs).sort((a, b) => b[1] - a[1]).map(([v, n]) => (
                              <div key={v} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                                <span style={{ width: 44, fontSize: 10.5, fontWeight: 700, color: riskColor(VERB_RISK[v]), textTransform: "uppercase" }}>{v}</span>
                                <div style={{ flex: 1, height: 6, borderRadius: 999, background: "#1c1c1c", overflow: "hidden" }}>
                                  <div style={{ width: `${Math.round((n / total) * 100)}%`, height: "100%", borderRadius: 999, background: riskColor(VERB_RISK[v]) }} />
                                </div>
                                <span style={{ width: 42, fontSize: 10.5, color: "#8a8a8a", fontVariantNumeric: "tabular-nums", textAlign: "right" }}>{n}/{c.calls}</span>
                              </div>
                            ))}
                          </div>
                          {isAdmin && (
                            <div style={{ marginTop: 10, display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                              <span style={{ fontSize: 10, color: "#6e6e6e", fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em" }}>Promote as</span>
                              {VERBS.map((v) => {
                                const inferred = v === c.inferred_verb;
                                return (
                                  <button
                                    key={v}
                                    type="button"
                                    disabled={busy === c.tool_name}
                                    onClick={() => void promote(c.tool_name, v)}
                                    title={inferred ? `Promote as "${v}" — matches the observed evidence.` : `Admin override: promote as "${v}" even though the evidence suggests ${c.inferred_verb ?? "nothing"}.`}
                                    style={{ height: 22, padding: "0 10px", border: `1px solid ${inferred ? "#2ddab8" : "var(--graph-border)"}`, borderRadius: 999, background: inferred ? "rgba(45,218,184,0.1)" : "transparent", color: inferred ? "#2ddab8" : "#b8c2d6", fontFamily: "inherit", fontSize: 10.5, fontWeight: 700, cursor: busy === c.tool_name ? "wait" : "pointer" }}
                                  >
                                    {v}{inferred ? " ✓" : ""}
                                  </button>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* ── LEARNED overrides ────────────────────────────────────────────── */}
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", color: "#6ee7b7", textTransform: "uppercase", marginBottom: 8 }}>
                  Learned · {overrides.length} promoted verb{overrides.length === 1 ? "" : "s"}
                </div>
                {overrides.length === 0 ? (
                  <div style={{ fontSize: 12, color: "#a0a0a0", lineHeight: 1.5 }}>No promoted verbs yet — promote a candidate above and it moves here with its audit trail.</div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                    {overrides.map((o) => {
                      const ev = o.evidence ?? {};
                      const verbs = ev.verbs ?? {};
                      const evText = Object.keys(verbs).length
                        ? `${ev.calls ?? 0} calls · ` + Object.entries(verbs).sort((a, b) => b[1] - a[1]).map(([v, n]) => `${v} ${n}`).join(" · ")
                        : "promoted without observed evidence";
                      return (
                        <div key={`${o.namespace}/${o.tool_name}`} data-testid="toolverb-override" style={{ padding: "11px 13px", borderRadius: 10, background: "var(--bg-graph-card)", border: "1px solid #1f4635" }}>
                          <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                            <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12.5, fontWeight: 650, color: "#e8edf5", overflowWrap: "anywhere" }}>{o.tool_name}</span>
                            <span style={{ fontSize: 10, fontWeight: 800, padding: "1px 7px", borderRadius: 999, border: `1px solid ${riskColor(o.risk)}55`, color: riskColor(o.risk), textTransform: "uppercase", letterSpacing: "0.04em" }}>{o.verb}</span>
                            <span style={{ fontSize: 10, fontWeight: 700, padding: "1px 7px", borderRadius: 999, background: "#12332a", color: "#6ee7b7", textTransform: "uppercase", letterSpacing: "0.04em" }}>✓ learned</span>
                            {isAdmin && (
                              <button
                                type="button"
                                disabled={busy === o.tool_name}
                                onClick={() => void demote(o)}
                                title={`Demote ${o.tool_name} back to observation — removes the learned verb; evidence keeps accruing.`}
                                style={{ marginLeft: "auto", height: 22, padding: "0 10px", border: "1px solid var(--graph-border)", borderRadius: 999, background: "transparent", color: "#a0a0a0", fontFamily: "inherit", fontSize: 10.5, fontWeight: 700, cursor: busy === o.tool_name ? "wait" : "pointer" }}
                              >
                                {busy === o.tool_name ? "…" : "Demote"}
                              </button>
                            )}
                          </div>
                          <div style={{ marginTop: 5, fontSize: 10.5, color: "#8a8a8a", lineHeight: 1.5 }}>
                            {o.namespace} · promoted by <b style={{ color: "#b8c2d6" }}>{o.promoted_by || "—"}</b>
                            {o.created_at ? ` · ${new Date(o.created_at).toLocaleString()}` : ""} · evidence: {evText}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        <div style={{ padding: "12px 22px", borderTop: "1px solid var(--graph-border-soft)", display: "flex", justifyContent: "flex-end" }}>
          <button type="button" onClick={onClose} style={{ height: 32, padding: "0 16px", border: "1px solid var(--graph-border)", borderRadius: 9, background: "transparent", color: "#a0a0a0", fontFamily: "inherit", fontSize: 12.5, fontWeight: 600, cursor: "pointer" }}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

export default ToolVerbsPanel;
