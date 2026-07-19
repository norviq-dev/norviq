// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Attack Graph — kill-chain triage. The backend precomputes every attack path
// (agent → tool → sensitive data) at GET /api/v1/threats/attack-paths, pre-sorted worst-first. The
// operator triages the ranked list, proves a fix with a what-if block, and turns intent into a
// default-deny policy draft. Three columns inside a Panel: ranked path list · kill-chain canvas ·
// inspector. Plus a clickable stat strip, dark-dropdown filters (Namespace/Agent-class/Range, +Cluster
// when fleetEnabled), severity chips, and the positive-security intent modal. Selection + filters are
// reflected in the URL (?path,ns,cls,status,sev) so a triage view is shareable. Every mutating action
// (Simulate / what-if / Apply intent) is a PREVIEW/dry-run — nothing enforces from this screen.

import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";
import { fleetEnabled } from "../api/fleet";
import { apiSend, apiUrl, createIntentDraft, fetchMe, fetchThreatPaths } from "../api/client";
import { useApi } from "../hooks/useApi";
import { getToken } from "../auth/session";
import { AttackGraphCanvas, type AttackCanvasHandle, type ScopeCard } from "../components/attack-graph/AttackGraphCanvas";
import { AttackGraphLegend } from "../components/attack-graph/AttackGraphLegend";
import { AttackPathDetail, type SimResult } from "../components/attack-graph/AttackPathDetail";
import { AttackPathList } from "../components/attack-graph/AttackPathList";
import { IntentModal } from "../components/attack-graph/IntentModal";
import { ToolVerbsPanel } from "../components/attack-graph/ToolVerbsPanel";
import { SEVERITY_COLORS } from "../components/attack-graph/constants";
import type { PathStatus, Severity, ThreatPath } from "../components/attack-graph/types";

type StatusFilter = "exploitable" | "blocked" | null;
type SevMap = Record<Severity, boolean>;
const ALL_SEV: Severity[] = ["critical", "high", "medium", "low"];
const RANGES = [
  { val: "24h", label: "Last 24h" },
  { val: "7d", label: "Last 7d" },
  { val: "30d", label: "Last 30d" }
];

/** Rank for worst-first triage; the server already sorts, but a what-if flip can re-order locally. */
const RANK_STATUS: Record<PathStatus, number> = { exploitable: 0, unsimulated: 1, blocked: 2 };
const RANK_SEV: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function AttackGraph() {
  const { selectedNamespace, namespaces, selectedCluster, servedCluster, setCluster, setNamespace, clusters } = useApp();
  const [searchParams, setSearchParams] = useSearchParams();

  const [paths, setPaths] = useState<ThreatPath[]>([]);
  const [apiNamespaces, setApiNamespaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [degraded, setDegraded] = useState(false);
  const [recomputing, setRecomputing] = useState(false);

  // filters (hydrated from URL on mount)
  const [range, setRange] = useState(searchParams.get("range") ?? "24h");
  const [agentClass, setAgentClass] = useState(searchParams.get("cls") ?? "all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>(
    searchParams.get("status") === "exploitable" || searchParams.get("status") === "blocked"
      ? (searchParams.get("status") as StatusFilter)
      : null
  );
  const [severities, setSeverities] = useState<SevMap>(() => {
    const raw = searchParams.get("sev");
    if (!raw) return { critical: true, high: true, medium: true, low: true };
    const on = raw.split(",");
    return { critical: on.includes("critical"), high: on.includes("high"), medium: on.includes("medium"), low: on.includes("low") };
  });
  const [openMenu, setOpenMenu] = useState<string | null>(null);

  const [selectedId, setSelectedId] = useState<string | null>(searchParams.get("path"));
  const [scope, setScope] = useState<ScopeCard | null>(null);
  const [whatIf, setWhatIf] = useState<Record<string, number>>({});
  const [sim, setSim] = useState<Record<string, PathStatus>>({});
  const [simResult, setSimResult] = useState<Record<string, SimResult>>({});
  const [simulating, setSimulating] = useState(false);
  const [drafted, setDrafted] = useState<Record<string, boolean>>({});
  // The what-if "Draft blocking policy" persists a REAL dry-run draft and captures its deeplink.
  // draftLinks[pathId] = /policies/catalog?intent_draft=<id>.
  const [draftLinks, setDraftLinks] = useState<Record<string, string>>({});
  const [draftError, setDraftError] = useState<Record<string, string>>({});
  const [intentOpen, setIntentOpen] = useState(false);
  const [intentGlobal, setIntentGlobal] = useState(false);
  // Tool-classification lifecycle management panel; lifecycleTick re-fetches paths after a
  // promote/demote so the per-card stage tags + hop chips update immediately.
  const [toolVerbsOpen, setToolVerbsOpen] = useState(false);
  const [lifecycleTick, setLifecycleTick] = useState(0);
  const me = useApi(() => fetchMe(), []);
  const isAdmin = me.data?.role === "admin";
  // Default-hide probe-rooted kill-chains; shares the one preference key with the Asset graph (localStorage).
  const [showSynthetic, setShowSynthetic] = useState<boolean>(() => localStorage.getItem("nrvq_show_synthetic") === "1");
  const [syntheticHidden, setSyntheticHidden] = useState(0);

  const canvasRef = useRef<AttackCanvasHandle>(null);
  // A failed recompute POST raises `degraded`, but the finally re-triggers the display-fetch
  // effect (recomputing in deps) and a successful READ GET would unconditionally clear it — clobbering
  // the banner the instant stale paths re-render as fresh. Persist the recompute-failure across that
  // refetch: set true on a non-2xx compute POST, cleared only when a compute POST returns ok.
  const recomputeFailedRef = useRef(false);

  // ── fetch ────────────────────────────────────────────────────────────────
  useEffect(() => {
    let alive = true;
    setLoading(true);
    fetchThreatPaths(selectedNamespace, range, agentClass, showSynthetic)
      .then((res) => {
        if (!alive) return;
        setPaths(res.paths ?? []);
        setApiNamespaces(res.namespaces ?? []);
        setSyntheticHidden(res.synthetic_hidden ?? 0);
        // A successful GET does NOT clear a still-outstanding recompute failure — the paths it
        // returned are the STALE precompute the failed recompute couldn't refresh, so keep the banner up.
        setDegraded(recomputeFailedRef.current);
      })
      .catch(() => {
        // Degraded: keep whatever we already have; the banner surfaces the fetch failure.
        if (alive) setDegraded(true);
      })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [selectedNamespace, range, agentClass, recomputing, showSynthetic, lifecycleTick]);

  // Flip synthetic-agent visibility + persist (shared with the Asset graph); the fetch effect re-runs.
  const toggleSynthetic = () => setShowSynthetic((v) => {
    const next = !v;
    localStorage.setItem("nrvq_show_synthetic", next ? "1" : "0");
    return next;
  });

  // ── REAL status: a stored sim result (real /evaluate), else the baseline. A what-if is a
  //    HYPOTHETICAL overlay and is deliberately EXCLUDED here — MUT-4: folding it in made a
  //    hypothetical "Block this step" inflate the headline BLOCKED stat (0→1) and re-order the list
  //    (which auto-switched the selected path). Real status drives stats, ordering, and the filter;
  //    the what-if is surfaced separately via isWhatIf + the canvas/detail overlay. ──
  const statusOf = useMemo(() => {
    return (p: ThreatPath): PathStatus => sim[p.id] ?? p.status;
  }, [sim]);
  const isWhatIf = useMemo(() => (p: ThreatPath): boolean => whatIf[p.id] != null, [whatIf]);
  const whatIfIds = useMemo(() => new Set(Object.keys(whatIf)), [whatIf]);

  // ── visible (severity + status filters) + worst-first order ──
  const visible = useMemo(() => paths.filter((p) => severities[p.sev]), [paths, severities]);
  const listed = useMemo(() => {
    const base = statusFilter ? visible.filter((p) => statusOf(p) === statusFilter) : visible.slice();
    return base.sort((a, b) => (RANK_STATUS[statusOf(a)] - RANK_STATUS[statusOf(b)]) || (RANK_SEV[a.sev] - RANK_SEV[b.sev]));
  }, [visible, statusFilter, statusOf]);

  const selected = useMemo(
    () => listed.find((p) => p.id === selectedId) ?? listed[0] ?? null,
    [listed, selectedId]
  );
  const effSelId = selected?.id ?? null;

  // ── shareable URL: reflect selection + filters ──
  useEffect(() => {
    const q = new URLSearchParams();
    if (effSelId) q.set("path", effSelId);
    if (selectedNamespace && selectedNamespace !== "all") q.set("ns", selectedNamespace);
    if (agentClass !== "all") q.set("cls", agentClass);
    if (statusFilter) q.set("status", statusFilter);
    const sev = ALL_SEV.filter((k) => severities[k]);
    if (sev.length < 4) q.set("sev", sev.join(","));
    if (range !== "24h") q.set("range", range);
    setSearchParams(q, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [effSelId, selectedNamespace, agentClass, statusFilter, severities, range]);

  // ── stats across VISIBLE paths (REAL status only — a what-if never moves these numbers) ──
  const stats = useMemo(() => {
    const crit = visible.filter((p) => p.sev === "critical").length;
    const high = visible.filter((p) => p.sev === "high").length;
    const exploitable = visible.filter((p) => statusOf(p) === "exploitable").length;
    const blocked = visible.filter((p) => statusOf(p) === "blocked").length;
    // How many VISIBLE paths carry a hypothetical block right now — shown as a separate
    // annotation, never merged into `blocked`.
    const whatIfCount = visible.filter((p) => isWhatIf(p)).length;
    const maxBlast = visible.reduce((m, p) => Math.max(m, p.blast), 0);
    const toolCount: Record<string, number> = {};
    visible.forEach((p) => p.steps.forEach((st) => { if (st.kind === "tool") toolCount[st.to] = (toolCount[st.to] || 0) + 1; }));
    const chokepoints = Object.values(toolCount).filter((c) => c >= 2).length;
    return { crit, high, exploitable, blocked, whatIfCount, maxBlast, chokepoints };
  }, [visible, statusOf, isWhatIf]);

  // ── filter helpers ──
  const onlyCrit = severities.critical && !severities.high && !severities.medium && !severities.low;
  const onlyHigh = !severities.critical && severities.high && !severities.medium && !severities.low;
  const setOnlySeverity = (keys: Severity[]) =>
    setSeverities({ critical: keys.includes("critical"), high: keys.includes("high"), medium: keys.includes("medium"), low: keys.includes("low") });
  const toggleSeverity = (k: Severity) => setSeverities((s) => ({ ...s, [k]: !s[k] }));
  const toggleStatusFilter = (k: "exploitable" | "blocked") => setStatusFilter((s) => (s === k ? null : k));
  // Resets THIS page's filters only. Namespace is the GLOBAL console scope (the header selector) —
  // a page-local reset must not silently rescope every other surface back to "All namespaces".
  const resetFilters = () => {
    setSeverities({ critical: true, high: true, medium: true, low: true });
    setStatusFilter(null);
    setAgentClass("all");
  };

  const toggleWhatIf = (idx: number) => {
    if (!selected) return;
    setWhatIf((s) => {
      const next = { ...s };
      if (next[selected.id] === idx) delete next[selected.id];
      else next[selected.id] = idx;
      return next;
    });
    setSimResult((s) => ({ ...s, [selected.id]: null }));
  };

  // ── Simulate: run each step as a REAL /evaluate call (blocked if ANY step blocks). PREVIEW only. ──
  const simulate = async () => {
    if (!selected || simulating) return;
    setSimulating(true);
    try {
      const agent_identity = {
        spiffe_id: `spiffe://norviq/ns/${selected.ns}/sa/${selected.cls}`,
        namespace: selected.ns,
        agent_class: selected.cls
      };
      const tools = selected.steps.filter((st) => st.kind === "tool").map((st) => st.to);
      const probes = tools.length ? tools : [selected.tool || selected.tgt];
      let enforced = false; // a real block by an authored policy (Enforce mode)
      let wouldBlock = false; // decision "audit" = a would-block softened by Monitor mode — NOT a gap
      let failClosed = false; // blocked ONLY because no policy is loaded (fail-closed default) — not real coverage
      for (const tool of probes) {
        const res = await apiSend<{ decision: string; rule_id?: string }>("/api/v1/evaluate", "POST", {
          tool_name: tool,
          tool_params: {},
          agent_identity,
          session_id: `simulate-${selected.id}`,
          framework: "attack-graph"
        });
        // A block from rule_id "no_policy_loaded" is the fail-closed DEFAULT (this namespace has no policy),
        // NOT a control the operator authored — reporting it as "blocked by policy" would be misleading.
        if (res.decision === "block" && res.rule_id === "no_policy_loaded") { failClosed = true; continue; }
        if (res.decision === "block") { enforced = true; break; }
        if (res.decision === "audit") { wouldBlock = true; } // keep scanning for a hard block on a later hop
      }
      // Covered = a policy addresses this path (real block OR monitor would-block). A fail-closed default or a
      // fully-allowed path is NOT covered — the first needs a real policy, the second is a genuine gap.
      const covered = enforced || wouldBlock;
      setSim((s) => ({ ...s, [selected.id]: covered ? "blocked" : "exploitable" }));
      setSimResult((s) => ({
        ...s,
        [selected.id]: enforced
          ? { blocked: true, label: "Blocked by an authored policy" }
          : wouldBlock
          ? { blocked: true, monitor: true, label: "Would be blocked — this namespace is in Monitor mode (evaluated, not enforced)" }
          : failClosed
          ? { blocked: false, label: "Blocked only by the fail-closed default — no policy is loaded for this namespace. Author a policy to control it intentionally." }
          : { blocked: false, label: "Simulation found a policy gap — no policy covers this path" }
      }));
    } catch (e: unknown) {
      setSimResult((s) => ({ ...s, [selected.id]: { blocked: false, label: e instanceof Error ? e.message : "Simulation failed" } }));
    } finally {
      setSimulating(false);
    }
  };

  // ── Recompute: re-run server-side path computation, then refetch. ──
  const recompute = async () => {
    if (recomputing) return;
    setRecomputing(true);
    setWhatIf({});
    setSim({});
    setSimResult({});
    try {
      const token = getToken();
      const res = await fetch(apiUrl(`/api/v1/attack-paths/compute?namespace=${encodeURIComponent(selectedNamespace)}`), {
        method: "POST",
        headers: token ? { Authorization: `Bearer ${token}` } : {}
      });
      // A non-2xx (500 / 403 / …) does NOT throw from fetch — check res.ok explicitly so a failed
      // recompute surfaces the degraded banner instead of silently claiming success and refetching.
      // Latch the outcome so the follow-on refetch (below) can't clear the banner on a
      // successful READ of the stale paths — only a compute POST that returns ok clears the latch.
      if (!res.ok) { recomputeFailedRef.current = true; setDegraded(true); }
      else recomputeFailedRef.current = false;
    } catch {
      recomputeFailedRef.current = true;
      setDegraded(true);
    } finally {
      setRecomputing(false); // flips the fetch effect to refetch
    }
  };

  // Persist a REAL dry-run intent draft for the path's class (a tighten-only default-deny with the
  // readonly refinement — non-enforcing until reviewed + applied in Policies) and capture its deeplink, so the
  // confirmation becomes a live link to the draft instead of a fabricated static label.
  const draftBlocking = async () => {
    if (!selected) return;
    const pid = selected.id;
    setDraftError((s) => { const n = { ...s }; delete n[pid]; return n; });
    try {
      const d = await createIntentDraft({
        ns: selected.ns,
        cls: selected.cls,
        allow_tools: [],
        intent: { readonly: true, scope: false, rate: false, egress: false },
        path_ids: [pid]
      });
      setDrafted((s) => ({ ...s, [pid]: true }));
      if (d.deeplink) setDraftLinks((s) => ({ ...s, [pid]: d.deeplink as string }));
    } catch (e) {
      setDraftError((s) => ({ ...s, [pid]: e instanceof Error ? e.message.replace(/^Error:\s*/, "") : "Draft failed" }));
    }
  };

  // ── namespace / class dropdown option sources ──
  const nsOptions = useMemo(() => {
    const src = (namespaces.length ? namespaces : apiNamespaces).filter(Boolean);
    return [{ value: "all", label: "All namespaces" }, ...[...new Set(src)].map((n) => ({ value: n, label: n }))];
  }, [namespaces, apiNamespaces]);
  const classOptions = useMemo(() => {
    const distinct = [...new Set(paths.map((p) => p.cls).filter(Boolean))];
    return [{ value: "all", label: "All classes" }, ...distinct.map((c) => ({ value: c, label: c }))];
  }, [paths]);
  // Global intent: classes across all VISIBLE paths with their path counts (grouped-by-class), worst-first.
  const classGroups = useMemo(() => {
    const m: Record<string, number> = {};
    visible.forEach((p) => { if (p.cls) m[p.cls] = (m[p.cls] || 0) + 1; });
    return Object.entries(m).map(([cls, count]) => ({ cls, count })).sort((a, b) => b.count - a.count);
  }, [visible]);

  const dropdowns = [
    {
      key: "namespace", title: "Namespace", value: selectedNamespace,
      label: nsOptions.find((o) => o.value === selectedNamespace)?.label ?? "All namespaces",
      options: nsOptions, onSelect: (v: string) => { setNamespace(v); setOpenMenu(null); }
    },
    {
      key: "agentClass", title: "Agent class", value: agentClass,
      label: agentClass === "all" ? "All classes" : agentClass,
      options: classOptions, onSelect: (v: string) => { setAgentClass(v); setOpenMenu(null); }
    },
    // Cluster: multi-cluster installs only (existing fleetEnabled signal) — switches the global context.
    ...(fleetEnabled
      ? [{
          key: "cluster", title: "Cluster", value: selectedCluster || servedCluster,
          label: selectedCluster || servedCluster || "—",
          options: clusters.map((c) => ({ value: c, label: c })),
          onSelect: (v: string) => { setCluster(v); setOpenMenu(null); }
        }]
      : []),
    {
      key: "range", title: "Range", value: range,
      label: RANGES.find((r) => r.val === range)?.label ?? "Last 24h",
      options: RANGES.map((r) => ({ value: r.val, label: r.label })), onSelect: (v: string) => { setRange(v); setOpenMenu(null); }
    }
  ];

  const statCells: Array<{ label: string; value: number; sub?: string; color: string; onClick?: () => void; active?: boolean }> = [
    { label: "Critical paths", value: stats.crit, color: "#FF3B5C", onClick: () => setOnlySeverity(onlyCrit ? ["critical", "high", "medium", "low"] : ["critical"]), active: onlyCrit },
    { label: "High", value: stats.high, color: "#FF7A45", onClick: () => setOnlySeverity(onlyHigh ? ["critical", "high", "medium", "low"] : ["high"]), active: onlyHigh },
    { label: "Chokepoints", value: stats.chokepoints, sub: "tools", color: "#e8edf5" },
    { label: "Max blast radius", value: stats.maxBlast, sub: "assets", color: "#FFB020" },
    { label: "Exploitable", value: stats.exploitable, color: "#FF3B5C", onClick: () => toggleStatusFilter("exploitable"), active: statusFilter === "exploitable" },
    // BLOCKED counts REAL blocks only. A live what-if preview is annotated separately (sub) so the
    // headline can never be read as enforced blocks that don't exist.
    {
      label: "Blocked",
      value: stats.blocked,
      sub: stats.whatIfCount > 0 ? `+${stats.whatIfCount} what-if` : undefined,
      color: "#34d399",
      onClick: () => toggleStatusFilter("blocked"),
      active: statusFilter === "blocked"
    }
  ];

  const wf = selected ? (whatIf[selected.id] ?? -1) : -1;
  // Don't flash the "no attack paths" empty-state while the first fetch/recompute is still in flight.
  const empty = listed.length === 0 && !loading && !recomputing;
  const nsLabel = selectedNamespace === "all" ? "All namespaces" : selectedNamespace;

  return (
    <div className="page-enter">
      <PageHead title="Attack Graph" subtitle={`Showing: ${nsLabel}`} />

      {degraded && (
        <div role="alert" style={{ margin: "14px 0", display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", background: "rgba(255,176,32,0.08)", border: "1px solid #4a3a1a", borderRadius: 10 }}>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#FFB020" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
          <span style={{ fontSize: 12.5, fontWeight: 600, color: "#ffcf82" }}>API unavailable. Showing partial data.</span>
        </div>
      )}

      {/* Probe-rooted kill-chains hidden by default — surface the count + a reveal toggle. */}
      {(syntheticHidden > 0 || showSynthetic) && (
        <div role="status" style={{ margin: "14px 0", display: "flex", alignItems: "center", gap: 9, padding: "9px 14px", background: "var(--bg-graph-panel, #141414)", border: "1px solid var(--graph-border, #2a2a2a)", borderRadius: 10, fontSize: 12, color: "var(--text-secondary, #9aa4b2)" }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#7c8a9a" strokeWidth="1.8" style={{ flex: "none" }}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" /></svg>
          <span>
            {showSynthetic
              ? "Showing test/probe kill-chains (synthetic identities from the red-team / e2e harness)."
              : <>{syntheticHidden} test/probe kill-chain{syntheticHidden === 1 ? "" : "s"} hidden.</>}
          </span>
          <button onClick={toggleSynthetic} style={{ marginLeft: 4, background: "transparent", border: "1px solid var(--graph-border, #2a2a2a)", borderRadius: 7, color: "var(--accent, #00e5a0)", padding: "3px 10px", fontSize: 12, cursor: "pointer" }}>
            {showSynthetic ? "Hide" : "Show"}
          </button>
        </div>
      )}

      <Panel>
        {/* panel head */}
        <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "18px 20px", borderBottom: "1px solid var(--graph-border-soft)" }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 700 }}>Threat Relationships</div>
            <div style={{ fontSize: 12, color: "#a0a0a0", marginTop: 2 }}>{visible.length} attack paths · precomputed from the runtime asset graph</div>
          </div>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ display: "flex", alignItems: "center", border: "1px solid var(--graph-border)", borderRadius: 9, overflow: "hidden" }}>
              <button type="button" onClick={() => canvasRef.current?.zoomBy(0.8)} aria-label="Zoom out" style={iconBtn}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14" /></svg>
              </button>
              <button type="button" onClick={() => canvasRef.current?.zoomBy(1.25)} aria-label="Zoom in" style={{ ...iconBtn, borderLeft: "1px solid var(--graph-border)" }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 5v14M5 12h14" /></svg>
              </button>
            </div>
            <button type="button" onClick={() => canvasRef.current?.fitView()} style={pillBtn}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5" /></svg>
              Re-layout
            </button>
            <button type="button" onClick={recompute} disabled={recomputing} style={pillBtn}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 2v6h-6" /><path d="M3 12a9 9 0 0 1 15-6.7L21 8" /><path d="M3 22v-6h6" /><path d="M21 12a9 9 0 0 1-15 6.7L3 16" /></svg>
              Recompute
            </button>
            {/* GLOBAL positive-security intent across ALL classes. The per-path "Define intended behaviour" +
                "Simulate" live in the inspector (scoped to the selected path) — this one is the bulk entry. */}
            <button type="button" onClick={() => { setIntentGlobal(true); setIntentOpen(true); }} disabled={!visible.length} style={{ height: 32, padding: "0 14px", display: "flex", alignItems: "center", gap: 7, border: "1px solid var(--accent, #2ddab8)", borderRadius: 9, background: "rgba(45,218,184,0.12)", color: "var(--accent, #2ddab8)", fontFamily: "inherit", fontSize: 12.5, fontWeight: 700, cursor: visible.length ? "pointer" : "default" }}>
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="m9 12 2 2 4-4" /></svg>
              Define intended behaviour · all classes
            </button>
            {/* Tool-classification lifecycle home: observing candidates (evidence + promote) and learned
                overrides (audit trail + demote). The per-card stage tags link the eye here. */}
            <button type="button" onClick={() => setToolVerbsOpen(true)} style={pillBtn} title="Tool classification lifecycle — observing candidates, learned verbs, promote/demote (admin).">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3" /><path d="M12 3v3M12 18v3M3 12h3M18 12h3" /></svg>
              Tool verbs
            </button>
          </div>
        </div>

        {/* filter dropdowns */}
        {openMenu && <div onClick={() => setOpenMenu(null)} style={{ position: "fixed", inset: 0, zIndex: 40 }} aria-hidden="true" />}
        <div style={{ display: "flex", alignItems: "flex-end", gap: 14, flexWrap: "wrap", padding: "14px 20px 12px", borderBottom: "1px solid var(--graph-border-soft)" }}>
          {dropdowns.map((d) => {
            const open = openMenu === d.key;
            return (
              <div key={d.key} style={{ position: "relative", display: "flex", flexDirection: "column", gap: 5 }}>
                <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.08em", color: "#6e6e6e", textTransform: "uppercase", paddingLeft: 2 }}>{d.title}</span>
                <button
                  type="button" onClick={() => setOpenMenu(open ? null : d.key)} aria-haspopup="listbox" aria-expanded={open} aria-label={d.title}
                  style={{ display: "flex", alignItems: "center", gap: 10, height: 34, padding: "0 11px", minWidth: 152, background: "var(--bg-graph-card)", border: `1px solid ${open ? "#2ddab8" : "var(--graph-border)"}`, borderRadius: 9, color: "#e8edf5", fontFamily: "inherit", fontSize: 13, fontWeight: 500, cursor: "pointer", zIndex: open ? 50 : "auto" }}
                >
                  <span style={{ flex: 1, textAlign: "left", whiteSpace: "nowrap" }}>{d.label}</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#5b6577" strokeWidth="2"><path d="M6 9l6 6 6-6" /></svg>
                </button>
                {open && (
                  <div role="listbox" aria-label={d.title} style={{ position: "absolute", top: 62, left: 0, zIndex: 50, minWidth: 190, padding: 5, background: "var(--bg-graph-card)", border: "1px solid var(--graph-border)", borderRadius: 10, boxShadow: "0 18px 40px -14px rgba(0,0,0,0.8)" }}>
                    {d.options.map((o) => (
                      <div
                        key={o.value} role="option" aria-selected={o.value === d.value} onClick={() => d.onSelect(o.value)}
                        style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, padding: "8px 10px", borderRadius: 7, fontSize: 13, color: o.value === d.value ? "#e8edf5" : "#a0a0a0", cursor: "pointer" }}
                      >
                        <span>{o.label}</span>
                        {o.value === d.value && <span style={{ color: "#2ddab8", fontWeight: 700 }}>✓</span>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* severity toolbar */}
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", padding: "14px 20px", borderBottom: "1px solid var(--graph-border-soft)" }}>
          <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.06em", color: "#6e6e6e" }}>SEVERITY</span>
          <div style={{ display: "flex", gap: 7 }}>
            {ALL_SEV.map((k) => {
              const on = severities[k];
              const c = SEVERITY_COLORS[k];
              return (
                <button
                  key={k} type="button" onClick={() => toggleSeverity(k)} aria-pressed={on}
                  style={{ display: "inline-flex", alignItems: "center", gap: 7, height: 30, padding: "0 11px", borderRadius: 8, border: `1px solid ${on ? c + "66" : "var(--graph-border)"}`, background: on ? c + "1a" : "transparent", color: on ? "#e8edf5" : "#5b6577", fontFamily: "inherit", fontSize: 12.5, fontWeight: 600, cursor: "pointer", transition: "120ms ease" }}
                >
                  <span style={{ width: 9, height: 9, borderRadius: "50%", background: c }} />
                  {k.charAt(0).toUpperCase() + k.slice(1)}
                </button>
              );
            })}
          </div>
        </div>

        {/* stat strip */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", borderBottom: "1px solid var(--graph-border-soft)" }}>
          {statCells.map((s) => (
            <div
              key={s.label}
              data-testid={`stat-${s.label.toLowerCase().replace(/\s+/g, "-")}`}
              onClick={s.onClick}
              role={s.onClick ? "button" : undefined}
              aria-pressed={s.onClick ? !!s.active : undefined}
              style={{ position: "relative", padding: "14px 18px", borderRight: "1px solid var(--graph-border-soft)", cursor: s.onClick ? "pointer" : "default" }}
            >
              <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.04em", color: "#a0a0a0", textTransform: "uppercase" }}>{s.label}</div>
              <div style={{ display: "flex", alignItems: "baseline", gap: 7, marginTop: 6 }}>
                <span style={{ fontSize: 24, fontWeight: 700, letterSpacing: "-0.02em", color: s.color, fontVariantNumeric: "tabular-nums" }}>{s.value}</span>
                {s.sub && <span style={{ fontSize: 11, color: "#a0a0a0" }}>{s.sub}</span>}
              </div>
              <div style={{ position: "absolute", left: 0, right: 0, bottom: 0, height: 2, background: s.active ? s.color : "transparent" }} />
            </div>
          ))}
        </div>

        {/* body: path list + canvas + inspector, each in its own rounded card. Top-aligned so the OPEN-ENDED
            list/inspector grow to their natural height (page scrolls) without letterboxing the canvas. */}
        <div style={{ display: "flex", alignItems: "flex-start", gap: 14, padding: "14px 16px 18px", minHeight: 520, overflowX: "auto" }}>
          {empty ? (
            <div style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 12, minHeight: 520, textAlign: "center" }}>
              <div style={{ fontSize: 13, color: "#a0a0a0", lineHeight: 1.5 }}>
                {paths.length === 0 && !loading ? "No attack paths stored for this namespace." : "No attack paths match the current filters."}
              </div>
              <div style={{ display: "flex", gap: 10 }}>
                <button type="button" onClick={resetFilters} style={{ height: 30, padding: "0 14px", border: "1px solid var(--graph-border, #2a2a2a)", borderRadius: 8, background: "transparent", color: "#a0a0a0", fontFamily: "inherit", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>Reset</button>
                <button type="button" onClick={recompute} disabled={recomputing} style={{ height: 30, padding: "0 14px", border: "1px solid var(--graph-border, #2a2a2a)", borderRadius: 8, background: "transparent", color: "#a0a0a0", fontFamily: "inherit", fontSize: 12, fontWeight: 600, cursor: "pointer" }}>
                  {recomputing ? "Recomputing…" : "Recompute attack paths"}
                </button>
              </div>
            </div>
          ) : (
            <>
              <AttackPathList
                paths={listed}
                selectedId={selected?.id}
                statusOf={statusOf}
                whatIfIds={whatIfIds}
                onSelect={(p) => { setSelectedId(p.id); setScope(null); }}
              />

              {/* kill-chain canvas card — fixed viewport height; the horizontal chain fits via viewBox (no scroll). */}
              <div style={{ flex: "1 0 330px", minWidth: 0, height: 560, position: "relative", background: "radial-gradient(circle at 46% 42%, rgba(30,20,50,0.55) 0%, transparent 62%), var(--bg-graph-panel)", border: "1px solid var(--graph-border)", borderRadius: 14, overflow: "hidden" }}>
                {selected && (
                  <div style={{ position: "absolute", top: 14, left: 20, zIndex: 4, fontSize: 12.5, color: "#a0a0a0" }}>
                    Kill chain · <b style={{ color: "#e8edf5" }}>{selected.src}</b> <span style={{ color: "#5b6577" }}>→</span> <b style={{ color: "#ff8fa3" }}>{selected.tgt}</b>
                  </div>
                )}
                {selected && wf < 0 && statusOf(selected) === "exploitable" && !selected.steps.some((st) => st.dec === "block") && (
                  <div style={{ position: "absolute", top: 44, left: "50%", transform: "translateX(-50%)", zIndex: 5, pointerEvents: "none", display: "flex", alignItems: "center", gap: 8, padding: "7px 14px", background: "rgba(23,23,23,0.92)", border: "1px solid #2a2a2a", borderRadius: 999, fontSize: 12, fontWeight: 600, color: "#2ddab8", whiteSpace: "nowrap" }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2ddab8" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 11.5 12 8l7 7" /><path d="m3 21 6-6" /><circle cx="9" cy="15" r="1" /></svg>
                    Click a hop to simulate blocking it
                  </div>
                )}
                {selected && wf >= 0 && (
                  <div style={{ position: "absolute", top: 44, left: "50%", transform: "translateX(-50%)", zIndex: 5, pointerEvents: "none", display: "flex", alignItems: "center", gap: 8, padding: "7px 14px", background: "rgba(58,20,32,0.92)", border: "1px solid #FF3B5C", borderRadius: 999, fontSize: 12, fontWeight: 700, color: "#ff9fb0", whiteSpace: "nowrap" }}>
                    <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#FF3B5C" }} />
                    What-if block active · path neutralized
                  </div>
                )}

                {selected && (
                  <AttackGraphCanvas
                    ref={canvasRef}
                    path={selected}
                    allPaths={paths}
                    whatIfIndex={wf}
                    onToggleWhatIf={toggleWhatIf}
                    onScope={setScope}
                  />
                )}

                {/* scope card */}
                {scope && (
                  <div style={{ position: "absolute", top: 14, right: 14, zIndex: 6, width: 232, background: "rgba(20,20,20,0.95)", border: "1px solid var(--graph-border)", borderRadius: 12, padding: "13px 14px", backdropFilter: "blur(8px)", boxShadow: "0 16px 40px -18px rgba(0,0,0,0.8)", animation: "agFade 0.18s ease both" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ width: 9, height: 9, flex: "none", borderRadius: "50%", background: scope.kindColor }} />
                      <span style={{ flex: 1, minWidth: 0, fontFamily: "ui-monospace, monospace", fontSize: 12, fontWeight: 600, color: "#e8edf5", overflowWrap: "anywhere" }}>{scope.id}</span>
                      <span style={{ fontSize: 9.5, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", color: scope.kindColor }}>{scope.kindLabel}</span>
                      <button type="button" onClick={() => setScope(null)} aria-label="Close scope card" style={{ width: 20, height: 20, flex: "none", display: "flex", alignItems: "center", justifyContent: "center", background: "transparent", border: "none", borderRadius: 6, color: "#5b6577", cursor: "pointer", fontSize: 13, fontFamily: "inherit" }}>×</button>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", gap: 7, marginTop: 11 }}>
                      {scope.rows.map((r, i) => (
                        <div key={i} style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
                          <span style={{ flex: "none", width: 86, fontSize: 10, fontWeight: 700, letterSpacing: "0.05em", textTransform: "uppercase", color: "#6e6e6e" }}>{r.k}</span>
                          <span style={{ flex: 1, minWidth: 0, fontSize: 11.5, color: "#b8c2d6", lineHeight: 1.4, overflowWrap: "anywhere" }}>{r.v}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {(loading || recomputing) && (
                  <div style={{ position: "absolute", inset: 0, zIndex: 7, display: "flex", alignItems: "center", justifyContent: "center", gap: 12, background: "rgba(8,9,12,0.72)", backdropFilter: "blur(2px)" }}>
                    <span className="ak-spin" style={{ width: 22, height: 22, border: "2.5px solid #2a2a2a", borderTopColor: "#2ddab8", borderRadius: "50%" }} />
                    <span style={{ fontSize: 13, color: "#b8c2d6", fontWeight: 600 }}>Recomputing attack paths…</span>
                  </div>
                )}

                <AttackGraphLegend />
              </div>

              {/* inspector */}
              {selected && (
                <AttackPathDetail
                  path={selected}
                  status={statusOf(selected)}
                  whatIfIndex={wf}
                  simResult={simResult[selected.id] ?? null}
                  simulating={simulating}
                  drafted={!!drafted[selected.id]}
                  draftLink={draftLinks[selected.id]}
                  draftError={draftError[selected.id]}
                  onToggleWhatIf={toggleWhatIf}
                  onDefineIntent={() => { setIntentGlobal(false); setIntentOpen(true); }}
                  onSimulate={simulate}
                  onDraft={draftBlocking}
                />
              )}
            </>
          )}
        </div>
      </Panel>

      {intentOpen && (intentGlobal ? classGroups.length > 0 : !!selected) && (
        <IntentModal
          ns={selectedNamespace}
          cls={intentGlobal ? (classGroups[0]?.cls ?? "") : (selected?.cls ?? "")}
          tool={intentGlobal ? "" : (selected?.tool ?? "")}
          paths={visible}
          global={intentGlobal}
          classOptions={intentGlobal ? classGroups : undefined}
          onClose={() => { setIntentOpen(false); setIntentGlobal(false); }}
          onLifecycleChange={() => setLifecycleTick((t) => t + 1)}
        />
      )}

      {toolVerbsOpen && (
        <ToolVerbsPanel
          ns={selectedNamespace}
          isAdmin={isAdmin}
          onClose={() => setToolVerbsOpen(false)}
          onChanged={() => setLifecycleTick((t) => t + 1)}
        />
      )}
    </div>
  );
}

const iconBtn: React.CSSProperties = { width: 34, height: 32, display: "flex", alignItems: "center", justifyContent: "center", background: "transparent", border: "none", color: "#a0a0a0", cursor: "pointer" };
const pillBtn: React.CSSProperties = { height: 32, padding: "0 13px", display: "flex", alignItems: "center", gap: 7, background: "transparent", border: "1px solid var(--graph-border)", borderRadius: 9, color: "#a0a0a0", fontFamily: "inherit", fontSize: 12.5, fontWeight: 600, cursor: "pointer" };

export default AttackGraph;
