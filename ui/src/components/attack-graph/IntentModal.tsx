// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Attack Graph intent modal (design_handoff_attackgraph): a usage-driven ALLOWLIST BUILDER.
// role="dialog" aria-modal, Esc closes, Tab focus-trap, autofocus the first control.
//
// On open (and whenever the active class changes in global mode) we call fetchIntentSuggest(ns,cls) and
// render the class's OBSERVED tools as a CHECKLIST — each checkbox = "this tool is intended". `normal`
// tools default CHECKED; `chokepoint`/`egress` tools default UNCHECKED (opt-in). Attack-abused chokepoints
// get an amber "⚠ reached {target} via {name} — intended?" treatment; egress tools get a red "egress" chip.
// BELOW the checklist the four intent toggles (Read-only / Namespace-scoped / Rate-limit / No egress) act
// as coarse REFINEMENTS of the allowed set. On any checkbox/toggle change we debounce (~220ms) then call
// fetchIntentCoverage({ns,cls,allow_tools,intent}) and render covered_count/total + the residual list + the
// returned Rego (which now lists the checked tools). "Apply intent policy" → createIntentDraft(...) with the
// checked tools + covered path_ids, then a "Draft created · dry-run in Policies" deep-link. Everything is
// PREVIEW — nothing enforces on its own.

import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { createIntentDraft, demoteToolVerb, fetchIntentCoverage, fetchIntentSuggest, fetchMe, promoteToolVerb } from "../../api/client";
import { useApi } from "../../hooks/useApi";
import { INTENT_CONTROLS, SEVERITY_COLORS } from "./constants";
import type { IntentCoverage, IntentDraft, IntentSuggestTool, IntentToggles, ThreatPath } from "./types";

interface Props {
  ns: string;
  cls: string;
  tool: string;
  /** All visible paths — used to label the residual ids + the "granted to" line. */
  paths: ThreatPath[];
  onClose: () => void;
  /** GLOBAL mode: a common intent builder spanning ALL paths, grouped by class (class selector shown,
   *  coverage is n/total over ALL paths, not just this chokepoint). */
  global?: boolean;
  /** Distinct agent classes across all paths (global mode) with their path counts. */
  classOptions?: Array<{ cls: string; count: number }>;
  /** Fired after a verb promote/demote so the page can refresh path stage tags + hop chips. */
  onLifecycleChange?: () => void;
}

const EMPTY: IntentToggles = { readonly: false, scope: false, rate: false, egress: false };

/** DENY-ALL default (positive security): the allowlist opens EMPTY — every tool starts unchecked, and the
 *  operator explicitly checks the intended safe tools. Never pre-allow a destructive/chokepoint/egress tool. */
function defaultChecked(_t: IntentSuggestTool): boolean {
  return false;
}

export function IntentModal({ ns, cls, tool, paths, onClose, global, classOptions, onLifecycleChange }: Props) {
  const navigate = useNavigate();
  const modalRef = useRef<HTMLDivElement>(null);
  const [intent, setIntent] = useState<IntentToggles>(EMPTY);
  const [coverage, setCoverage] = useState<IntentCoverage | null>(null);
  const [applying, setApplying] = useState(false);
  const [draft, setDraft] = useState<IntentDraft | null>(null);
  const [error, setError] = useState("");
  // Global mode picks the class (grouped-by-class); per-path mode is pinned to the selected path's class.
  const [selCls, setSelCls] = useState(cls);
  const [clsMenu, setClsMenu] = useState(false);
  const activeCls = global ? selCls : cls;

  // Allowlist builder: the class's OBSERVED tools + the per-tool "intended" checkbox state (by name).
  const [tools, setTools] = useState<IntentSuggestTool[]>([]);
  const [checked, setChecked] = useState<Record<string, boolean>>({});
  const [loadingTools, setLoadingTools] = useState(true);
  // Verb-promotion lifecycle: admin can PROMOTE a still-unclassified tool to the verb its observed
  // params suggest — reloadKey re-fetches the suggest list so the row flips to a classified chip.
  const me = useApi(() => fetchMe(), []);
  const isAdmin = me.data?.role === "admin";
  const [promoting, setPromoting] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);
  // The concrete namespace behind the suggest scope — promotion must name ONE namespace even when the
  // modal was opened with ns="all" (the backend echoes the resolved scope in the response).
  const [suggestNs, setSuggestNs] = useState("");

  // Admin OVERRIDE surface: promote as the inferred verb OR any other (the admin's call always wins),
  // and demote a learned verb back to observing. verbMenu tracks which row's verb-picker is open.
  const [verbMenu, setVerbMenu] = useState<string | null>(null);

  const promote = async (t: IntentSuggestTool, verb?: string) => {
    const chosen = verb ?? t.inferred_verb;
    const promoNs = ns && ns !== "all" ? ns : suggestNs;
    if (!chosen || !promoNs || promoting) return;
    setPromoting(t.name);
    setVerbMenu(null);
    setError("");
    try {
      await promoteToolVerb({ ns: promoNs, tool_name: t.name, verb: chosen });
      setReloadKey((k) => k + 1); // re-fetch: the row flips to a classified (learned) verb chip
      onLifecycleChange?.();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Promotion failed");
    } finally {
      setPromoting(null);
    }
  };

  const demote = async (t: IntentSuggestTool) => {
    const promoNs = ns && ns !== "all" ? ns : suggestNs;
    if (!promoNs || promoting) return;
    setPromoting(t.name);
    setError("");
    try {
      await demoteToolVerb(promoNs, t.name);
      setReloadKey((k) => k + 1); // re-fetch: the row returns to the observing state
      onLifecycleChange?.();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Demotion failed");
    } finally {
      setPromoting(null);
    }
  };

  const enabledCount = INTENT_CONTROLS.filter((c) => intent[c.key]).length;
  const checkedTools = useMemo(() => tools.filter((t) => checked[t.name]).map((t) => t.name), [tools, checked]);
  const canApply = checkedTools.length > 0 || enabledCount > 0;
  // Allowlisting a MUTATING tool (delete/write/send — registry-classified OR admin-promoted) grants a
  // destructive capability. Unless Read-only/No-egress is on to refine it out, the operator is silently
  // permitting exactly the verb they classified — surface it so the promoted "delete" is visible + actionable.
  const destructiveChecked = useMemo(
    () => tools.filter((t) => checked[t.name] && (t.op === "delete" || t.op === "write" || t.op === "send")),
    [tools, checked]
  );
  const unrefinedDestructive = destructiveChecked.filter(
    (t) => !((t.op === "delete" || t.op === "write") && intent.readonly) && !(t.op === "send" && (intent.egress || intent.readonly))
  );
  // CONTRADICTORY-POLICY WARNING (distinct from the destructive-allowlist warning above, which
  // deliberately excludes this case): a CHECKED egress tool together with "No external egress" produces a
  // self-contradictory generated policy — the tool is in the allowlist yet the refinement toggle ALWAYS
  // blocks it (proven via opa eval: in_allowlist:true, decision:"block"). This surfaces the contradiction
  // instead of silently letting the allowlist entry have no effect.
  // FIX-2: the backend's `is_egress` (generate_intent_rego, norviq/api/threat_intent.py) only blocks a
  // send-classified tool when it's EGRESS_TOOLS-lexicon-tagged (tag==="egress") OR an admin-PROMOTED verb
  // (op_src==="learned"). A registry-only send classification (op_src==="registry", e.g. forward_ticket) is
  // NOT blocked — it resolves to ALLOW — so warning on it told the operator to uncheck a correct, working
  // entry. Gate the op==="send" branch on op_src==="learned" so only tools the backend actually blocks
  // trigger this warning.
  const egressConflict = useMemo(
    () => tools.filter((t) => checked[t.name] && (t.tag === "egress" || (t.op === "send" && t.op_src === "learned")) && intent.egress),
    [tools, checked, intent.egress]
  );

  // Autofocus the first control + set up Esc / focus-trap (a11y — kept from the handoff).
  useEffect(() => {
    const t = window.setTimeout(() => {
      const b = modalRef.current?.querySelector<HTMLElement>("button:not([disabled]), input:not([disabled])");
      b?.focus();
    }, 0);
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { onClose(); return; }
      if (e.key === "Tab" && modalRef.current) {
        const f = modalRef.current.querySelectorAll<HTMLElement>('button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])');
        if (!f.length) return;
        const first = f[0], last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
        else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
        else if (!modalRef.current.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => { window.clearTimeout(t); window.removeEventListener("keydown", onKey); };
  }, [onClose]);

  // Load the OBSERVED tool surface for the active class → seed the checklist (normal=checked, choke/egress=off).
  useEffect(() => {
    let alive = true;
    setLoadingTools(true);
    setCoverage(null);
    fetchIntentSuggest(ns, activeCls)
      .then((s) => {
        if (!alive) return;
        const observed = s.tools ?? [];
        setTools(observed);
        // Preserve the operator's checks across a promotion-triggered reload (same class ⇒ same names);
        // a class switch produces different names, so defaults apply naturally.
        setChecked((prev) => Object.fromEntries(observed.map((t) => [t.name, prev[t.name] ?? defaultChecked(t)])));
        setSuggestNs(s.ns?.[0] ?? "");
        setError("");
      })
      .catch((e: unknown) => {
        if (!alive) return;
        setTools([]);
        setChecked({});
        setError(e instanceof Error ? e.message : "Could not load the tool surface");
      })
      .finally(() => { if (alive) setLoadingTools(false); });
    return () => { alive = false; };
  }, [ns, activeCls, reloadKey]);

  // LIVE coverage: on any checkbox or toggle (or class) change, debounce then evaluate the generated allow-rule
  // server-side against the observed allow_tools + the refinement toggles.
  useEffect(() => {
    if (loadingTools) return; // wait for the checklist to seed so allow_tools reflects the real defaults
    let alive = true;
    const t = window.setTimeout(() => {
      fetchIntentCoverage({ ns, cls: activeCls, allow_tools: checkedTools, intent })
        .then((c) => { if (alive) { setCoverage(c); setError(""); } })
        .catch((e: unknown) => { if (alive) setError(e instanceof Error ? e.message : "Coverage failed"); });
    }, 220);
    return () => { alive = false; window.clearTimeout(t); };
  }, [ns, activeCls, checkedTools, intent, loadingTools]);

  const toggle = (key: keyof IntentToggles) => setIntent((s) => ({ ...s, [key]: !s[key] }));
  const toggleTool = (name: string) => setChecked((s) => ({ ...s, [name]: !s[name] }));
  const selectAll = () => setChecked(Object.fromEntries(tools.map((t) => [t.name, true])));
  const clearAll = () => setChecked(Object.fromEntries(tools.map((t) => [t.name, false])));

  const apply = async () => {
    if (!canApply || applying) return;
    setApplying(true);
    setError("");
    try {
      const covered = coverage?.covered ?? [];
      const d = await createIntentDraft({ ns, cls: activeCls, allow_tools: checkedTools, intent, path_ids: covered.length ? covered : undefined });
      setDraft(d);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Apply failed");
    } finally {
      setApplying(false);
    }
  };

  // Coverage is always PER-CLASS — the denominator + residual are the SELECTED class's attack paths (what the
  // backend returns), matching the Policy Catalog's per-class numbers. An intent policy is one class's allowlist;
  // it can only neutralize THAT class's paths, so measuring it over every class's paths (all N) is misleading.
  // Other classes each need their own intent policy (surfaced in the footer note below).
  const total = coverage?.total ?? paths.length;
  const covered = coverage?.covered_count ?? 0;
  const residualIds = coverage?.residual ?? [];
  const rego = coverage?.rego ?? "  # pick the intended tools to generate the allow-rule";
  const grantedTo = global ? activeCls : ([...new Set(paths.filter((p) => p.tool === tool).map((p) => p.src))].join(", ") || cls);
  const hasSignal = checkedTools.length > 0 || enabledCount > 0;
  const coverColor = !hasSignal ? "#a0a0a0" : residualIds.length === 0 ? "#34d399" : "#FFB020";
  const byId = new Map(paths.map((p) => [p.id, p]));

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 80, display: "flex", alignItems: "center", justifyContent: "center", padding: 24, background: "rgba(6,7,10,0.72)", backdropFilter: "blur(3px)", animation: "agFade 0.16s ease both" }}>
      <div onClick={onClose} style={{ position: "absolute", inset: 0 }} aria-hidden="true" />
      <div
        ref={modalRef}
        role="dialog"
        aria-modal="true"
        aria-label="Define intended behaviour"
        style={{ position: "relative", zIndex: 1, display: "flex", width: 780, maxWidth: "100%", maxHeight: "88vh", background: "linear-gradient(180deg, var(--bg-graph-card), var(--bg-graph-panel))", border: "1px solid var(--graph-border)", borderRadius: 16, overflow: "hidden", boxShadow: "0 40px 90px -30px rgba(0,0,0,0.85)" }}
      >
        {/* left: allowlist builder + refinement toggles */}
        <div style={{ flex: "1 1 auto", minWidth: 0, padding: "22px 22px 20px", display: "flex", flexDirection: "column", overflow: "hidden" }}>
          <div style={{ fontSize: 10.5, fontWeight: 800, letterSpacing: "0.14em", color: "#2ddab8" }}>
            {global ? "POSITIVE-SECURITY POLICY · ALL PATHS" : "POSITIVE-SECURITY POLICY"}
          </div>
          <div style={{ fontSize: 18, fontWeight: 700, marginTop: 5 }}>
            Intended behaviour · <span style={{ fontFamily: "ui-monospace, monospace", color: "#2ddab8" }}>{global ? activeCls : (activeCls || cls)}</span>
          </div>
          {global && classOptions && classOptions.length > 0 ? (
            <div style={{ position: "relative", marginTop: 9 }}>
              <div style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.06em", color: "#6e6e6e", textTransform: "uppercase", marginBottom: 5 }}>Agent class · grouped</div>
              <button
                type="button" onClick={() => setClsMenu((v) => !v)} aria-haspopup="listbox" aria-expanded={clsMenu}
                style={{ display: "flex", alignItems: "center", gap: 10, height: 32, padding: "0 11px", minWidth: 220, background: "var(--bg-graph-card)", border: `1px solid ${clsMenu ? "#2ddab8" : "var(--graph-border)"}`, borderRadius: 9, color: "#e8edf5", fontFamily: "inherit", fontSize: 13, fontWeight: 500, cursor: "pointer" }}
              >
                <span style={{ flex: 1, textAlign: "left" }}>{activeCls}</span>
                <span style={{ fontSize: 11, color: "#a0a0a0" }}>{classOptions.find((c) => c.cls === activeCls)?.count ?? 0} paths</span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#5b6577" strokeWidth="2"><path d="M6 9l6 6 6-6" /></svg>
              </button>
              {clsMenu && (
                <div role="listbox" style={{ position: "absolute", top: 60, left: 0, zIndex: 3, minWidth: 240, maxHeight: 220, overflow: "auto", padding: 5, background: "var(--bg-graph-card)", border: "1px solid var(--graph-border)", borderRadius: 10, boxShadow: "0 18px 40px -14px rgba(0,0,0,0.8)" }}>
                  {classOptions.map((c) => (
                    <div
                      key={c.cls} role="option" aria-selected={c.cls === activeCls}
                      onClick={() => { setSelCls(c.cls); setClsMenu(false); setDraft(null); }}
                      style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, padding: "8px 10px", borderRadius: 7, fontSize: 13, color: c.cls === activeCls ? "#e8edf5" : "#a0a0a0", cursor: "pointer" }}
                    >
                      <span>{c.cls}</span>
                      <span style={{ fontSize: 11, color: "#a0a0a0" }}>{c.count}{c.cls === activeCls ? " ✓" : ""}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div style={{ fontSize: 12, color: "#a0a0a0", marginTop: 5, lineHeight: 1.5 }}>
              Granted to <b style={{ color: "#b8c2d6" }}>{grantedTo}</b>. Allow only what you intend — everything else is denied by default.
            </div>
          )}

          {/* allowlist checklist header + select-all/clear */}
          <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 18, marginBottom: 8 }}>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", color: "#a0a0a0", textTransform: "uppercase" }}>
              Intended tools <span style={{ color: "#6e6e6e" }}>· observed call surface</span>
            </div>
            <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
              <button type="button" onClick={selectAll} disabled={!tools.length} style={miniBtn}>Select all</button>
              <button type="button" onClick={clearAll} disabled={!tools.length} style={miniBtn}>Clear</button>
            </div>
          </div>

          {/* the checklist — scrolls independently so the toggles + apply row stay visible */}
          <div style={{ overflowY: "auto", maxHeight: 240, display: "flex", flexDirection: "column", gap: 7, paddingRight: 2 }}>
            {loadingTools ? (
              <div style={{ fontSize: 12, color: "#a0a0a0", padding: "10px 2px" }}>Loading observed tools…</div>
            ) : tools.length === 0 ? (
              <div style={{ fontSize: 12, color: "#a0a0a0", padding: "10px 2px", lineHeight: 1.5 }}>
                No tools observed for this class in the runtime graph. The refinement toggles below still generate a default-deny policy.
              </div>
            ) : (
              tools.map((t) => {
                const on = !!checked[t.name];
                const isChoke = t.tag === "chokepoint";
                const isEgress = t.tag === "egress";
                // Self-referential "reached X via X" (a tool-terminal path) is noise — only flag a
                // tool that goes on to reach a DIFFERENT target.
                const flagged = isChoke && t.in_attack_path && t.target !== t.name;
                const preHi = !global && !!tool && t.name === tool; // per-path entry pre-highlights the selected tool
                const borderCol = on ? "#2ddab8" : flagged ? "#4a3a1a" : isEgress ? "#4a1f28" : "var(--graph-border-soft)";
                const bg = on ? "rgba(45,218,184,0.1)" : preHi ? "rgba(45,218,184,0.05)" : "var(--bg-graph-card)";
                return (
                  <label
                    key={t.name}
                    style={{ display: "flex", alignItems: "flex-start", gap: 11, padding: "10px 12px", borderRadius: 10, background: bg, border: `1px solid ${preHi && !on ? "#2a2a2a" : borderCol}`, cursor: "pointer" }}
                  >
                    <input
                      type="checkbox" checked={on} onChange={() => toggleTool(t.name)}
                      aria-label={`Intended: ${t.name}`}
                      style={{ marginTop: 2, width: 15, height: 15, accentColor: "#2ddab8", cursor: "pointer", flex: "none" }}
                    />
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 7, flexWrap: "wrap" }}>
                        <span style={{ fontFamily: "ui-monospace, monospace", fontSize: 12.5, fontWeight: 650, color: "#e8edf5", overflowWrap: "anywhere" }}>{t.name}</span>
                        {/* What the tool DOES — the classification LIFECYCLE: a classified verb (registry or
                            admin-promoted), an OBSERVING tool whose params suggest a verb (promotable), or a
                            genuinely unknown tool (stays under observation — review, never read as safe). */}
                        {t.op ? (() => {
                          const c = t.op_risk === "critical" ? ["#3a1414", "#ff8fa3"]
                            : t.op_risk === "high" ? ["#3a2410", "#ffcf82"]
                            : t.op_risk === "medium" ? ["#2a2a10", "#e8e08a"]
                            : ["#12332a", "#6ee7b7"];
                          return (
                            <>
                              <span style={chip(c[0], c[1])} title={`${t.op} operation · ${t.op_risk ?? "low"} risk${t.op_src === "learned" ? " · promoted from observed evidence" : ""}`}>{t.op}</span>
                              {t.op_src === "learned" && (
                                <>
                                  <span style={chip("#12332a", "#6ee7b7")} title="Verb promoted by an admin from this tool's observed call evidence.">✓ learned</span>
                                  {isAdmin && (
                                    <button
                                      type="button"
                                      disabled={promoting === t.name}
                                      onClick={(e) => { e.preventDefault(); e.stopPropagation(); void demote(t); }}
                                      title={`Demote ${t.name} back to the observation phase — the learned verb is removed and evidence keeps accruing.`}
                                      style={miniAction}
                                    >
                                      {promoting === t.name ? "…" : "demote"}
                                    </button>
                                  )}
                                </>
                              )}
                            </>
                          );
                        })() : (
                          <>
                            {t.inferred_verb ? (
                              <span
                                style={chip("#3a2410", "#ffcf82")}
                                title={`Unclassified by name — under observation. Its observed params suggest "${t.inferred_verb}" (${t.inferred_count} of ${t.observed_calls} evidenced calls).`}
                              >
                                observing · {t.inferred_verb} {t.inferred_count}/{t.observed_calls}
                              </span>
                            ) : (
                              // Observation phase, no evidence yet: the tool stays logged (Monitor) until its
                              // params reveal a verb — it must prompt REVIEW, never read as safe/allow.
                              <span style={chip("#2a2a2a", "#a0a0a0")} title="Norviq could not infer this tool's operation from its name yet — it stays under observation (calls are logged); once its params reveal the verb you can promote it. Review before allowing.">unclassified · observing</span>
                            )}
                            {isAdmin && verbMenu !== t.name && (
                              <>
                                {t.inferred_verb && (
                                  <button
                                    type="button"
                                    disabled={promoting === t.name}
                                    onClick={(e) => { e.preventDefault(); e.stopPropagation(); void promote(t); }}
                                    title={`Promote ${t.name} to a defined "${t.inferred_verb}" verb — from then on it is classified everywhere (risk follows the verb).`}
                                    style={{ flex: "none", height: 20, padding: "0 8px", border: "1px solid #2ddab8", borderRadius: 999, background: "rgba(45,218,184,0.08)", color: "#2ddab8", fontFamily: "inherit", fontSize: 10, fontWeight: 700, letterSpacing: "0.03em", cursor: promoting === t.name ? "wait" : "pointer" }}
                                  >
                                    {promoting === t.name ? "Promoting…" : `Promote as ${t.inferred_verb}`}
                                  </button>
                                )}
                                <button
                                  type="button"
                                  disabled={promoting === t.name}
                                  onClick={(e) => { e.preventDefault(); e.stopPropagation(); setVerbMenu(t.name); }}
                                  title="Admin override: promote as a DIFFERENT verb than inferred — you know the tool better than the evidence does."
                                  style={miniAction}
                                >
                                  {t.inferred_verb ? "▾ other" : "▾ set verb"}
                                </button>
                              </>
                            )}
                            {isAdmin && verbMenu === t.name && (
                              <span style={{ display: "inline-flex", gap: 4, alignItems: "center" }} onClick={(e) => { e.preventDefault(); e.stopPropagation(); }}>
                                {(["read", "write", "send", "delete"] as const).map((v) => (
                                  <button
                                    key={v}
                                    type="button"
                                    disabled={promoting === t.name}
                                    onClick={(e) => { e.preventDefault(); e.stopPropagation(); void promote(t, v); }}
                                    title={`Promote ${t.name} as "${v}" (admin override — risk follows the verb).`}
                                    style={{ ...miniAction, borderColor: v === t.inferred_verb ? "#2ddab8" : "var(--graph-border)", color: v === t.inferred_verb ? "#2ddab8" : "#b8c2d6" }}
                                  >
                                    {v}
                                  </button>
                                ))}
                                <button type="button" onClick={(e) => { e.preventDefault(); e.stopPropagation(); setVerbMenu(null); }} style={miniAction} title="Cancel">✕</button>
                              </span>
                            )}
                          </>
                        )}
                        {isChoke && <span style={chip("#4a3a1a", "#ffcf82")}>chokepoint</span>}
                        {isEgress && <span style={chip("#3a1414", "#ff8fa3")}>egress</span>}
                      </div>
                      {flagged && t.target && (
                        <div style={{ marginTop: 4, fontSize: 11.5, fontWeight: 600, color: "#ffcf82", overflowWrap: "anywhere" }}>
                          ⚠ reached <span style={{ fontFamily: "ui-monospace, monospace" }}>{t.target}</span> via {t.name} — intended?
                        </div>
                      )}
                      <div style={{ marginTop: 3, display: "flex", gap: 12, fontSize: 11, color: "#7b8aa3", fontVariantNumeric: "tabular-nums" }}>
                        <span><span style={{ color: "#34d399" }}>{t.allow}</span> allow</span>
                        <span><span style={{ color: t.block > 0 ? "#ff8fa3" : "#a0a0a0" }}>{t.block}</span> block</span>
                      </div>
                    </div>
                  </label>
                );
              })
            )}
          </div>

          {/* DESTRUCTIVE-ALLOWLIST WARNING: an allowlisted mutating tool (its classified/promoted verb) is
              being GRANTED, not blocked — a positive-security allowlist allows what you list. Surface it so
              a promoted "delete" is visible + actionable, with a one-click Read-only that refines it out
              (which makes the delete drive a real block in the generated rego). */}
          {unrefinedDestructive.length > 0 && (
            <div
              data-testid="destructive-allowlist-warning"
              style={{ marginTop: 12, padding: "10px 12px", borderRadius: 10, background: "rgba(255,176,32,0.08)", border: "1px solid #4a3a1a" }}
            >
              <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                <span style={{ flex: "none", marginTop: 1, color: "#ffcf82", fontSize: 13 }}>⚠</span>
                <div style={{ fontSize: 11.5, lineHeight: 1.5, color: "#e8d5b0" }}>
                  You're allowing{" "}
                  {unrefinedDestructive.map((t, i) => (
                    <span key={t.name}>
                      {i > 0 ? ", " : ""}
                      <b style={{ fontFamily: "ui-monospace, monospace", color: "#ffcf82" }}>{t.name}</b>
                      <span style={{ color: "#ffcf82" }}> ({t.op})</span>
                    </span>
                  ))}
                  {" "}— a destructive capability{unrefinedDestructive.some((t) => t.op_src === "learned") ? " you promoted" : ""}. Allowlisting <i>grants</i> it. To restrict it to reads, enable Read-only.
                </div>
              </div>
              {unrefinedDestructive.some((t) => t.op === "delete" || t.op === "write") && (
                <button
                  type="button"
                  onClick={() => setIntent((s) => ({ ...s, readonly: true }))}
                  style={{ marginTop: 8, height: 26, padding: "0 12px", border: "1px solid #ffcf82", borderRadius: 999, background: "rgba(255,207,130,0.08)", color: "#ffcf82", fontFamily: "inherit", fontSize: 11, fontWeight: 700, cursor: "pointer" }}
                >
                  Make read-only — deny the mutating verbs
                </button>
              )}
            </div>
          )}

          {/* CONTRADICTORY-POLICY WARNING: a checked egress tool + "No external egress" makes that
              allowlist entry have NO effect — the tool stays blocked despite being allowlisted. Kept
              separate from the destructive-allowlist warning above (which intentionally suppresses this
              case) so the contradiction is its own, clearly-labeled callout. */}
          {egressConflict.length > 0 && (
            <div
              data-testid="egress-conflict-warning"
              style={{ marginTop: 12, padding: "10px 12px", borderRadius: 10, background: "rgba(255,176,32,0.08)", border: "1px solid #4a3a1a" }}
            >
              <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
                <span style={{ flex: "none", marginTop: 1, color: "#ffcf82", fontSize: 13 }}>⚠</span>
                <div style={{ fontSize: 11.5, lineHeight: 1.5, color: "#e8d5b0" }}>
                  {egressConflict.map((t, i) => (
                    <span key={t.name}>
                      {i > 0 ? ", " : ""}
                      <b style={{ fontFamily: "ui-monospace, monospace", color: "#ffcf82" }}>{t.name}</b>
                    </span>
                  ))}
                  {" "}{egressConflict.length === 1 ? "is" : "are"} allowlisted but "No external egress" will always
                  block {egressConflict.length === 1 ? "it" : "them"} — {egressConflict.length === 1 ? "this entry has" : "these entries have"} no effect.
                  Uncheck {egressConflict.length === 1 ? "it" : "them"} or turn off "No external egress" for this class.
                </div>
              </div>
            </div>
          )}

          {/* refinement toggles — coarse constraints ON TOP of the allowed tools */}
          <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", color: "#a0a0a0", textTransform: "uppercase", marginTop: 16, marginBottom: 8 }}>
            Refine the allowed tools
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {INTENT_CONTROLS.map((c) => {
              const on = intent[c.key];
              return (
                <button
                  key={c.key} type="button" onClick={() => toggle(c.key)} aria-pressed={on}
                  style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 13px", borderRadius: 10, background: on ? "rgba(45,218,184,0.1)" : "var(--bg-graph-card)", border: `1px solid ${on ? "#2ddab8" : "var(--graph-border-soft)"}`, cursor: "pointer", textAlign: "left", fontFamily: "inherit" }}
                >
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 13, fontWeight: 650, color: "#e8edf5" }}>{c.label}</div>
                    <div style={{ fontSize: 11.5, color: "#7b8aa3", marginTop: 2 }}>{c.desc}</div>
                  </div>
                  <span style={{ position: "relative", flex: "none", width: 34, height: 20, borderRadius: 999, background: on ? "#2ddab8" : "#2a2a2a", transition: "140ms ease" }}>
                    <span style={{ position: "absolute", top: 2, left: on ? 16 : 2, width: 16, height: 16, borderRadius: "50%", background: "#fff", transition: "140ms ease" }} />
                  </span>
                </button>
              );
            })}
          </div>

          {error && <div role="alert" style={{ marginTop: 12, fontSize: 12, color: "#ff8fa3" }}>{error}</div>}

          <div style={{ marginTop: "auto", paddingTop: 18, display: "flex", alignItems: "center", gap: 10 }}>
            {draft ? (
              <button
                type="button"
                onClick={() => navigate(draft.deeplink)}
                style={{ flex: 1, height: 38, display: "flex", alignItems: "center", justifyContent: "center", gap: 8, border: "1px solid #1f4635", borderRadius: 10, background: "transparent", color: "#6ee7b7", fontFamily: "inherit", fontSize: 13, fontWeight: 700, cursor: "pointer" }}
              >
                ✓ Draft created · dry-run in Policies
              </button>
            ) : (
              <button
                type="button" onClick={apply} disabled={!canApply || applying}
                style={{ flex: 1, height: 38, display: "flex", alignItems: "center", justifyContent: "center", gap: 8, border: "none", borderRadius: 10, background: !canApply ? "#3a3a3a" : "linear-gradient(180deg, #2ddab8, #22c4a4)", color: "#0d0d0d", fontFamily: "inherit", fontSize: 13, fontWeight: 750, cursor: !canApply || applying ? "not-allowed" : "pointer" }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 6 9 17l-5-5" /></svg>
                {applying ? "Applying…" : "Apply intent policy"}
              </button>
            )}
            <button
              type="button" onClick={onClose}
              style={{ height: 38, padding: "0 16px", border: "1px solid var(--graph-border)", borderRadius: 10, background: "transparent", color: "#a0a0a0", fontFamily: "inherit", fontSize: 13, fontWeight: 600, cursor: "pointer" }}
            >
              {draft ? "Close" : "Cancel"}
            </button>
          </div>
        </div>

        {/* right: generated Rego + coverage */}
        <div style={{ flex: "0 0 320px", borderLeft: "1px solid var(--graph-border-soft)", background: "var(--bg-graph-panel)", display: "flex", flexDirection: "column" }}>
          <div style={{ padding: "16px 18px", borderBottom: "1px solid var(--graph-border-soft)" }}>
            <div style={{ display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 10 }}>
              <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", color: "#a0a0a0", textTransform: "uppercase" }}>Attack-path coverage</div>
              <div style={{ fontSize: 20, fontWeight: 800, fontVariantNumeric: "tabular-nums", color: coverColor }}>{covered}/{total}</div>
            </div>
            {hasSignal && residualIds.length === 0 && (
              <div style={{ marginTop: 8, fontSize: 12, fontWeight: 600, color: "#6ee7b7" }}>✓ All paths neutralized · 0 residual</div>
            )}
            {hasSignal && residualIds.length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.05em", color: "#d0a24a", textTransform: "uppercase", marginBottom: 6 }}>Still exploitable</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                  {residualIds.slice(0, 8).map((id) => {
                    const p = byId.get(id);
                    return (
                      <div key={id} style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11.5, color: "#b8c2d6" }}>
                        <span style={{ width: 7, height: 7, flex: "none", borderRadius: "50%", background: p ? SEVERITY_COLORS[p.sev] : "#6e6e6e" }} />
                        <span style={{ minWidth: 0, overflowWrap: "anywhere" }}>{p ? `${p.src} → ${p.tgt}` : id}</span>
                      </div>
                    );
                  })}
                  {residualIds.length > 8 && (
                    <div style={{ fontSize: 11, color: "#a0a0a0", marginTop: 2 }}>+{residualIds.length - 8} more</div>
                  )}
                </div>
              </div>
            )}
            <div style={{ marginTop: 12, fontSize: 10.5, color: "#a0a0a0", lineHeight: 1.45 }}>
              Coverage is for <b style={{ color: "#a0a0a0" }}>{activeCls}</b>'s paths only — an intent policy is one
              class's allowlist. Other classes each need their own intent policy.
            </div>
          </div>
          <div style={{ flex: 1, overflow: "auto", padding: "14px 16px" }}>
            <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.05em", color: "#a0a0a0", textTransform: "uppercase", marginBottom: 8 }}>Generated policy</div>
            <pre style={{ margin: 0, fontFamily: "ui-monospace, 'JetBrains Mono', monospace", fontSize: 11.5, lineHeight: 1.6, color: "#9fb0cc", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{rego}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}

const miniBtn: React.CSSProperties = { height: 24, padding: "0 9px", border: "1px solid var(--graph-border)", borderRadius: 7, background: "transparent", color: "#a0a0a0", fontFamily: "inherit", fontSize: 11, fontWeight: 600, cursor: "pointer" };

/** Tiny inline admin action (demote / verb-override) — quiet by design, sits after the lifecycle chips. */
const miniAction: React.CSSProperties = { flex: "none", height: 20, padding: "0 7px", border: "1px solid var(--graph-border)", borderRadius: 999, background: "transparent", color: "#a0a0a0", fontFamily: "inherit", fontSize: 10, fontWeight: 700, letterSpacing: "0.03em", cursor: "pointer" };

const chip = (bg: string, color: string): React.CSSProperties => ({
  flex: "none", padding: "1px 7px", borderRadius: 999, background: bg, color, fontSize: 9.5, fontWeight: 700, letterSpacing: "0.04em", textTransform: "uppercase"
});
