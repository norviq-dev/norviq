// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Asset Graph page: per-agent circular meshes in the overview, click an
// agent to focus its subgraph as a live force layout, floating inspector with blast radius, clickable
// stat strip. Adapted to the EXISTING backend: /api/v1/asset-graph?namespace=all|<ns>&range=… (the
// multi-namespace union endpoint) — the Namespace dropdown drives the server-side namespace param,
// Range drives the API range param, everything else filters client-side (see model.ts for the
// field mapping). The Cluster dropdown exists ONLY in a multi-cluster install (existing fleetEnabled
// signal) and switches the global cluster context (ClusterScoped handles remote clusters).

import { useEffect, useMemo, useRef, useState } from "react";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";
import { apiUrl } from "../api/client";
import { fleetEnabled } from "../api/fleet";
import { AssetGraphCanvas, type CanvasHandle } from "../components/asset-graph/AssetGraphCanvas";
import { AssetGraphFilters, type DropdownSpec, type RiskKey, type TypeKey } from "../components/asset-graph/AssetGraphFilters";
import { AssetGraphLegend } from "../components/asset-graph/AssetGraphLegend";
import { AssetNodeDetail } from "../components/asset-graph/AssetNodeDetail";
import { buildModel, computeSets, type FilterState } from "../components/asset-graph/model";
import { NS_HULL_COLORS } from "../lib/d3-helpers";
import type { AssetGraphResponse } from "../components/asset-graph/types";
import { getToken } from "../auth/session";

const RANGE_OPTIONS = [
  { value: "1h", label: "Last 1h" },
  { value: "6h", label: "Last 6h" },
  { value: "24h", label: "Last 24h" },
  { value: "7d", label: "Last 7d" },
  { value: "30d", label: "Last 30d" }
];

const CSS = `
@keyframes agDash { to { stroke-dashoffset: -28; } }
.ag-flow { animation: agDash 0.7s linear infinite; }
@keyframes agPulse { 0%,100% { opacity: 0.85; transform: scale(1); } 50% { opacity: 0.18; transform: scale(1.55); } }
.ag-pulse { animation: agPulse 1.7s ease-in-out infinite; transform-box: fill-box; transform-origin: center; }
.ag-node { cursor: grab; }
.ag-node:active { cursor: grabbing; }
@media (prefers-reduced-motion: reduce) { .ag-flow, .ag-pulse { animation: none !important; } }
`;

export default function AssetGraph() {
  const {
    timeRange, clusters, selectedCluster, servedCluster, setCluster,
    selectedNamespace, namespaces: appNamespaces, setNamespace
  } = useApp();
  // The graph's namespace scope IS the global selector — never a divergent page-local state. The
  // in-panel Namespace dropdown below reflects it and drives it (same contract as the Attack Graph), so
  // changing the global selection re-fetches this graph scoped, and vice versa.
  const nsScope = selectedNamespace || "all";
  const [range, setRange] = useState<string>(timeRange || "24h");
  const [data, setData] = useState<AssetGraphResponse | null>(null);
  // The FULL namespace universe (from the "all" response). Kept separate so the Namespace dropdown always
  // lists every namespace + the real "(N)" count — scoping to one namespace must NOT collapse the list.
  const [allNamespaces, setAllNamespaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [openMenu, setOpenMenu] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [types, setTypes] = useState<Record<TypeKey, boolean>>({ agent: true, tool: true, data: true });
  const [risks, setRisks] = useState<Record<RiskKey, boolean>>({ low: true, medium: true, high: true, critical: true });
  const [agentClass, setAgentClass] = useState("all");
  const [blockedOnly, setBlockedOnly] = useState(false);
  // Default-hide synthetic/probe agents; the choice persists across visits (localStorage).
  const [showSynthetic, setShowSynthetic] = useState<boolean>(() => localStorage.getItem("nrvq_show_synthetic") === "1");
  // Default-hide real-but-awaiting (never-observed) agents; independent of showSynthetic (orthogonal flags).
  const [showAwaiting, setShowAwaiting] = useState<boolean>(() => localStorage.getItem("nrvq_show_awaiting") === "1");
  const [focus, setFocus] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [inspectorSide, setInspectorSide] = useState<"left" | "right">("right");
  const canvasRef = useRef<CanvasHandle>(null);

  useEffect(() => {
    let alive = true;
    const token = getToken();
    setLoading(true);
    setError("");
    fetch(apiUrl(`/api/v1/asset-graph?namespace=${encodeURIComponent(nsScope)}&range=${encodeURIComponent(range)}&include_synthetic=${showSynthetic}&include_awaiting=${showAwaiting}`), {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
      .then(async (res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`);
        const json = (await res.json()) as AssetGraphResponse;
        if (alive) {
          setData(json);
          // Only the unscoped "all" response carries the full namespace universe — capture it so the
          // dropdown keeps every namespace after the user drills into one.
          if (nsScope === "all") setAllNamespaces([...(json.namespaces ?? [])].sort());
          setFocus(null);
          setSelectedId(null);
        }
      })
      .catch((e: unknown) => { if (alive) setError(e instanceof Error ? e.message : "Failed to load"); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [nsScope, range, showSynthetic, showAwaiting]);

  // Flip the synthetic-agent visibility + persist the choice; the fetch effect re-runs on the state change.
  const toggleSynthetic = () => setShowSynthetic((v) => {
    const next = !v;
    localStorage.setItem("nrvq_show_synthetic", next ? "1" : "0");
    return next;
  });
  // Flip awaiting-agent visibility + persist; the fetch effect re-runs (independent of synthetic).
  const toggleAwaiting = () => setShowAwaiting((v) => {
    const next = !v;
    localStorage.setItem("nrvq_show_awaiting", next ? "1" : "0");
    return next;
  });

  // Close an open dropdown when clicking anywhere outside a dropdown (stacking-context-proof; see note in JSX).
  useEffect(() => {
    if (!openMenu) return;
    const onDown = (e: PointerEvent) => {
      if (!(e.target as Element).closest("[data-ag-menu]")) setOpenMenu(null);
    };
    document.addEventListener("pointerdown", onDown, true);
    return () => document.removeEventListener("pointerdown", onDown, true);
  }, [openMenu]);

  const model = useMemo(() => buildModel(data?.nodes ?? [], data?.edges ?? []), [data]);
  const namespaces = useMemo(
    () => (data?.namespaces?.length ? [...data.namespaces].sort() : model.namespaces),
    [data, model]
  );
  // The dropdown always offers the full namespace universe (so you can jump between namespaces or back to
  // "All" after drilling in), not just whatever the current scoped response returned. Prefer the global
  // universe from /cluster-info (what the header selector lists): landing already scoped (a persisted
  // `nrvq_namespace`) never fetches `namespace=all`, so `allNamespaces` would stay empty and collapse this
  // dropdown to the single scoped namespace. Sorted so a namespace keeps its hull colour across scopes.
  const dropdownNamespaces = useMemo(() => {
    const src = appNamespaces.length ? appNamespaces : allNamespaces.length ? allNamespaces : namespaces;
    return [...new Set(src.filter(Boolean))].sort();
  }, [appNamespaces, allNamespaces, namespaces]);
  const nsColorMap = useMemo(() => {
    // Colour by the full list so a namespace keeps the same hull colour across scopes.
    const map: Record<string, string> = {};
    (dropdownNamespaces.length ? dropdownNamespaces : namespaces).forEach((ns, i) => (map[ns] = NS_HULL_COLORS[i % NS_HULL_COLORS.length]));
    return map;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dropdownNamespaces.join("|"), namespaces]);
  const nsColor = (ns: string) => nsColorMap[ns] ?? "#a0a0a0";

  const filterState: FilterState = useMemo(
    () => ({ search, types, risks, agentClass, blockedOnly, focus, selectedId }),
    [search, types, risks, agentClass, blockedOnly, focus, selectedId]
  );
  const { vis, reach } = useMemo(() => computeSets(model, filterState), [model, filterState]);

  // stat math over the VISIBLE graph
  const visNodes = useMemo(() => model.nodes.filter((n) => vis[n.id]), [model, vis]);
  const visEdges = useMemo(() => model.edges.filter((e) => e.type !== "belongs_to" && vis[e.s] && vis[e.t]), [model, vis]);
  const blockedEdges = visEdges.filter((e) => e.verdict === "blocked").length;
  const highRisk = visNodes.filter((n) => n.risk === "high" || n.risk === "critical").length;
  // CAP-STAT: least-privilege signal at the top of the page — data sources whose worst OPEN verb is a
  // MUTATING one (write/delete/send), so the "write/delete-open" KPI is accurate. A dormant READ grant is
  // a lesser least-privilege note, not write/destructive exposure, so it must NOT light this red.
  const dataNodes = visNodes.filter((n) => n.kind === "data");
  const exposedSources = dataNodes.filter((n) => {
    const v = n.capability?.worst?.verb;
    return v === "write" || v === "delete" || v === "send";
  }).length;
  const activeNs = new Set(visNodes.map((n) => n.ns).filter(Boolean)).size;
  const agentCount = visNodes.filter((n) => n.kind === "agent" && !n.isIdentity && !n.awaiting).length;
  const awaitingAgents = visNodes.filter((n) => n.kind === "agent" && n.awaiting);
  const riskFocused = !risks.low && !risks.medium && risks.high && risks.critical;

  const focusGroup = focus ? model.groups.find((g) => g.key === focus) : null;
  const focusTools = focus ? visNodes.filter((n) => n.kind === "tool").length : 0;
  const focusData = focus ? visNodes.filter((n) => n.kind === "data").length : 0;
  const selectedNode = selectedId ? model.nodes.find((n) => n.id === selectedId) ?? null : null;

  const rangeLabel = RANGE_OPTIONS.find((o) => o.value === range)?.label ?? range;
  // Reconcile the header with the payload: "observed" = agents with traffic (excludes awaiting +
  // the shared-identity container); awaiting agents are surfaced separately so the counts add up.
  const awaitingCount = awaitingAgents.length;
  const showingText =
    nsScope === "all"
      ? `All namespaces · ${agentCount} agents observed${awaitingCount ? ` · ${awaitingCount} awaiting` : ""}`
      : `${nsScope} namespace`;

  const dropdowns: DropdownSpec[] = [
    {
      key: "ns", title: "Namespace", value: nsScope,
      options: [{ value: "all", label: `All namespaces (${dropdownNamespaces.length})` }, ...dropdownNamespaces.map((ns) => ({ value: ns, label: ns }))],
      // Drives the GLOBAL selector (P2-3) — the whole console follows, and so does this graph via nsScope.
      onSelect: (v) => { setNamespace(v); setOpenMenu(null); setFocus(null); setSelectedId(null); }
    },
    {
      key: "class", title: "Agent class", value: agentClass,
      options: [{ value: "all", label: "All classes" }, ...model.agentClasses.map((c) => ({ value: c, label: c }))],
      onSelect: (v) => { setAgentClass(v); setOpenMenu(null); }
    },
    // Cluster: multi-cluster installs only (existing fleetEnabled signal) — switches the global context.
    ...(fleetEnabled
      ? [{
          key: "cluster", title: "Cluster", value: selectedCluster || servedCluster,
          options: clusters.map((c) => ({ value: c, label: c })),
          onSelect: (v: string) => { setCluster(v); setOpenMenu(null); }
        }]
      : []),
    {
      key: "range", title: "Range", value: range,
      options: RANGE_OPTIONS,
      onSelect: (v) => { setRange(v); setOpenMenu(null); }
    }
  ];

  const statCell = (label: string, value: number | string, sub: string, color: string, onClick?: () => void, activeBar?: string) => (
    <div
      key={label}
      role={onClick ? "button" : undefined}
      onClick={onClick}
      style={{ position: "relative", padding: "14px 18px", borderRight: "1px solid #232323", cursor: onClick ? "pointer" : "default" }}
    >
      <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.04em", color: "#a0a0a0", textTransform: "uppercase" }}>{label}</div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 7, marginTop: 6 }}>
        <span style={{ fontSize: 24, fontWeight: 700, letterSpacing: "-0.02em", color, fontVariantNumeric: "tabular-nums" }}>{value}</span>
        <span style={{ fontSize: 11, color: "#a0a0a0" }}>{sub}</span>
      </div>
      <div style={{ position: "absolute", left: 0, right: 0, bottom: 0, height: 2, background: activeBar ?? "transparent" }} />
    </div>
  );

  if (loading) return <div>Loading asset graph...</div>;
  if (error) return <div>Failed to load asset graph: {error}</div>;
  const empty = !data || (model.nodes.length === 0);

  return (
    <div className="page-enter">
      <style>{CSS}</style>
      {/* Close open dropdown on any click outside a [data-ag-menu]. A fixed overlay div does NOT work here:
          `.panel` has backdrop-filter (a stacking context), so the menu is trapped below a root-level overlay
          and the overlay would swallow the option clicks. A document listener is stacking-context-proof. */}
      <PageHead title="Asset Graph" subtitle={<>Showing: <b>{showingText}</b> · {rangeLabel}</>} />
      {/* pad=false keeps the filter/stat/canvas rows edge-to-edge; the header below is a PADDED first child
          (18px 20px) so "Asset Relationships" never collides with the panel outline. Panel is untouched. */}
      <Panel pad={false} style={{ marginTop: 4 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14, padding: "18px 20px", borderBottom: "1px solid #232323" }}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 700 }}>Asset Relationships</div>
            <div style={{ fontSize: 12, color: "#a0a0a0", marginTop: 2 }}>
              {activeNs} namespaces · {visNodes.length} nodes · {visEdges.length} edges · drag to rearrange
            </div>
          </div>
          <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ display: "flex", alignItems: "center", border: "1px solid #23262f", borderRadius: 9, overflow: "hidden" }}>
              <button type="button" aria-label="Zoom out" onClick={() => canvasRef.current?.zoomBy(1 / 1.3)}
                style={{ width: 34, height: 32, display: "flex", alignItems: "center", justifyContent: "center", background: "transparent", border: "none", color: "#a0a0a0", cursor: "pointer" }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14" /></svg>
              </button>
              <button type="button" aria-label="Zoom in" onClick={() => canvasRef.current?.zoomBy(1.3)}
                style={{ width: 34, height: 32, display: "flex", alignItems: "center", justifyContent: "center", background: "transparent", border: "none", borderLeft: "1px solid #23262f", color: "#a0a0a0", cursor: "pointer" }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 5v14M5 12h14" /></svg>
              </button>
            </div>
            <button
              type="button"
              onClick={() => { setFocus(null); setSelectedId(null); canvasRef.current?.relayout(); }}
              style={{ height: 32, padding: "0 13px", display: "flex", alignItems: "center", gap: 7, background: "transparent", border: "1px solid #23262f", borderRadius: 9, color: "#a0a0a0", fontFamily: "inherit", fontSize: 12.5, fontWeight: 600, cursor: "pointer" }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5" /></svg>
              Re-layout
            </button>
          </div>
        </div>
        <AssetGraphFilters
          dropdowns={dropdowns}
          openMenu={openMenu}
          onToggleMenu={(k) => setOpenMenu((cur) => (cur === k ? null : k))}
          search={search}
          onSearch={setSearch}
          types={types}
          onToggleType={(k) => setTypes((t) => ({ ...t, [k]: !t[k] }))}
          risks={risks}
          onToggleRisk={(k) => setRisks((r) => ({ ...r, [k]: !r[k] }))}
        />

        {/* stat strip — High risk + Blocked are quick filters */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(6, 1fr)", borderBottom: "1px solid #232323" }} data-testid="stat-strip">
          {statCell("Namespaces", activeNs, activeNs === 1 ? "namespace" : "", "#a0a0a0")}
          {statCell("Nodes", visNodes.length, "assets", "#e8edf5")}
          {statCell("Tools", visNodes.filter((n) => n.kind === "tool").length, "", "#00E5A0")}
          {statCell(
            "Data",
            dataNodes.length,
            exposedSources > 0 ? `${exposedSources} write/delete-open` : "sources",
            exposedSources > 0 ? "#FF3B5C" : "#FFB020"
          )}
          {statCell("High risk", highRisk, "nodes", highRisk ? "#FF3B5C" : "#a0a0a0",
            () => setRisks(riskFocused ? { low: true, medium: true, high: true, critical: true } : { low: false, medium: false, high: true, critical: true }),
            riskFocused ? "#FF3B5C" : "transparent")}
          {statCell("Blocked", blockedEdges, "paths", blockedEdges ? "#FF3B5C" : "#a0a0a0",
            () => { setBlockedOnly((b) => !b); setSelectedId(null); setFocus(null); },
            blockedOnly ? "#FF3B5C" : "transparent")}
        </div>

        {/* focus breadcrumb */}
        {focusGroup && (
          <div style={{ display: "flex", alignItems: "center", gap: 13, padding: "11px 20px", borderBottom: "1px solid #232323", background: "rgba(255,255,255,0.02)" }}>
            <button
              type="button"
              onClick={() => { setFocus(null); setSelectedId(null); }}
              style={{ display: "inline-flex", alignItems: "center", gap: 7, height: 30, padding: "0 12px", background: "transparent", border: "1px solid #23262f", borderRadius: 8, color: "#b8c2d6", fontFamily: "inherit", fontSize: 12.5, fontWeight: 600, cursor: "pointer" }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M19 12H5M12 19l-7-7 7-7" /></svg>
              All namespaces
            </button>
            <div style={{ width: 1, height: 20, background: "#1c1f27" }} />
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <span style={{ width: 10, height: 10, borderRadius: "50%", background: "#7C5CFC", boxShadow: "0 0 8px #7C5CFC" }} />
              <span style={{ fontSize: 13, color: "#a0a0a0" }}>
                Focused graph · <b style={{ color: "#e8edf5" }}>{focusGroup.label}</b>{" "}
                <span style={{ color: "#a0a0a0" }}>({focusGroup.ns})</span> · {focusTools} tools · {focusData} data sources in reach
              </span>
            </div>
            <button
              type="button"
              onClick={() => setSelectedId(focus)}
              style={{ marginLeft: "auto", display: "inline-flex", alignItems: "center", gap: 7, height: 30, padding: "0 12px", background: "transparent", border: "1px solid #23262f", borderRadius: 8, color: "#b8c2d6", fontFamily: "inherit", fontSize: 12.5, fontWeight: 600, cursor: "pointer" }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="9" /><path d="M12 16v-4M12 8h.01" /></svg>
              Details
            </button>
          </div>
        )}

        {/* Real-but-awaiting (registered, never-observed) agents are hidden by default — surface the count
            + a Show/Hide toggle. When shown they render dimmed inline (same as before). */}
        {((data?.awaiting_hidden ?? 0) > 0 || showAwaiting) && (
          <div
            role="status"
            style={{ display: "flex", alignItems: "center", gap: 9, margin: "12px 20px 0", padding: "9px 14px", background: "var(--bg-graph-panel, #141414)", border: "1px solid var(--graph-border, #2a2a2a)", borderRadius: 10, fontSize: 12, color: "var(--text-secondary, #9aa4b2)" }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ffb020" strokeWidth="1.8" style={{ flex: "none" }}><circle cx="12" cy="12" r="9" /><path d="M12 8v5" /><path d="M12 16h.01" /></svg>
            <span>
              {showAwaiting
                ? <>Showing {awaitingAgents.length || ""} awaiting agent{awaitingAgents.length === 1 ? "" : "s"} (registered, no tool call yet) — dimmed until observed.</>
                : <>Awaiting ({data?.awaiting_hidden}) — registered agent{(data?.awaiting_hidden ?? 0) === 1 ? "" : "s"} with no tool call yet.</>}
            </span>
            <button
              onClick={toggleAwaiting}
              style={{ marginLeft: 4, background: "transparent", border: "1px solid var(--graph-border, #2a2a2a)", borderRadius: 7, color: "var(--accent, #00e5a0)", padding: "3px 10px", fontSize: 12, cursor: "pointer" }}
            >
              {showAwaiting ? "Hide" : "Show"}
            </button>
          </div>
        )}

        {/* Synthetic/probe agents are hidden by default — surface the count + a toggle to reveal them. */}
        {((data?.synthetic_hidden ?? 0) > 0 || showSynthetic) && (
          <div
            role="status"
            style={{ display: "flex", alignItems: "center", gap: 9, margin: "12px 20px 0", padding: "9px 14px", background: "var(--bg-graph-panel, #141414)", border: "1px solid var(--graph-border, #2a2a2a)", borderRadius: 10, fontSize: 12, color: "var(--text-secondary, #9aa4b2)" }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#7c8a9a" strokeWidth="1.8" style={{ flex: "none" }}><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" /></svg>
            <span>
              {showSynthetic
                ? "Showing test/probe agents (synthetic identities from the red-team / e2e harness)."
                : <>{data?.synthetic_hidden} test/probe agent{(data?.synthetic_hidden ?? 0) === 1 ? "" : "s"} hidden.</>}
            </span>
            <button
              onClick={toggleSynthetic}
              style={{ marginLeft: 4, background: "transparent", border: "1px solid var(--graph-border, #2a2a2a)", borderRadius: 7, color: "var(--accent, #00e5a0)", padding: "3px 10px", fontSize: 12, cursor: "pointer" }}
            >
              {showSynthetic ? "Hide" : "Show"}
            </button>
          </div>
        )}

        {/* canvas + overlays */}
        <div style={{ position: "relative", height: 680, background: "radial-gradient(circle at 50% 42%, rgba(28,28,28,0.6) 0%, transparent 60%)" }}>
          {empty ? (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "100%", color: "#a0a0a0" }}>
              No assets observed for this scope.
            </div>
          ) : (
            <AssetGraphCanvas
              ref={canvasRef}
              model={model}
              filters={filterState}
              nsColor={nsColor}
              onSelect={(id) => setSelectedId(id)}
              onFocusAgent={(g) => { setFocus(g); setSelectedId(null); }}
              onSelectedSide={setInspectorSide}
            />
          )}

          {!empty && <AssetGraphLegend side={selectedNode && inspectorSide === "left" ? "right" : "left"} />}

          {!selectedNode && !empty && (
            <div style={{ position: "absolute", left: "50%", transform: "translateX(-50%)", bottom: 16, display: "flex", alignItems: "center", gap: 8, padding: "9px 13px", background: "rgba(23,23,23,0.85)", backdropFilter: "blur(10px)", border: "1px solid var(--graph-border, #2a2a2a)", borderRadius: 10, fontSize: 12, color: "var(--text-muted, #9aa4b2)", whiteSpace: "nowrap", zIndex: 5 }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00e5a0" strokeWidth="1.8"><path d="M9 11l3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" /></svg>
              Click an agent to focus · drag an agent to move its whole circle
            </div>
          )}

          {selectedNode && (
            <AssetNodeDetail
              node={selectedNode}
              model={model}
              reach={reach}
              cluster={fleetEnabled ? selectedCluster || servedCluster : servedCluster || undefined}
              side={inspectorSide}
              onClose={() => setSelectedId(null)}
            />
          )}
        </div>
      </Panel>
    </div>
  );
}
