import { FileText } from "lucide-react";
import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  fetchAgents,
  fetchAuditRecords,
  fetchAuditStats,
  fetchCoverageByCategory,
  fetchRedteamLatest,
  fetchTopBlocked,
  fetchVolume,
  type RedteamLatest
} from "../api/client";
import { fleetEnabled, fetchFleetAuditSummary, fetchFleetAgents } from "../api/fleet";
import { RemoteScopedPanel } from "../components/common/RemoteClusterNotice";
import { DecisionBadge } from "../components/common/DecisionBadge";
import { KitButton } from "../components/common/KitButton";
import { KPICard } from "../components/common/KPICard";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";

// The 4 chart components each pull echarts-core (~582KB, the app's biggest chunk). Dashboard
// is the default landing route, so importing them statically put echarts on the critical path of the first
// authenticated screen — before the user does anything. Lazy-load them so the KPI tiles (pure numbers)
// paint immediately and echarts streams in after, off the initial-render path. Each has a skeleton fallback.
const CategoryBars = lazy(() => import("../components/charts/CategoryBars").then((m) => ({ default: m.CategoryBars })));
const AgentClassCoverage = lazy(() => import("../components/charts/AgentClassCoverage").then((m) => ({ default: m.AgentClassCoverage })));
const VolumeChart = lazy(() => import("../components/charts/VolumeChart").then((m) => ({ default: m.VolumeChart })));
const DonutChart = lazy(() => import("../components/common/DonutChart").then((m) => ({ default: m.DonutChart })));
const ScoreGauge = lazy(() => import("../components/common/ScoreGauge").then((m) => ({ default: m.ScoreGauge })));

// Shared skeleton for a chart still loading its code (mirrors the existing data-loading skeletons).
const ringSkeleton = (
  <div className="panel" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 14, minHeight: 200 }}>
    <div className="skeleton-line" style={{ width: 120, height: 120, borderRadius: "50%" }} />
    <div className="skeleton-line" style={{ width: "45%", height: 12 }} />
  </div>
);
const barsSkeleton = (
  <div className="panel" style={{ minHeight: 200, display: "flex", flexDirection: "column", justifyContent: "center", gap: 10 }}>
    <div className="skeleton-line" style={{ width: "35%", height: 12 }} />
    <div className="skeleton-line" style={{ width: "90%", height: 90 }} />
  </div>
);
import { useApi } from "../hooks/useApi";
import { exportCsv } from "../lib/csv";
import { fmtTime } from "../lib/format";
import { useApp } from "../store/AppContext";

type AuditStats = {
  total?: number;
  blocked?: number;
  allowed?: number;
  block_rate_pct?: number;
  engine_errors?: number;  // fail-closed OPA-eval faults (distinct from policy blocks)
  avg_latency_ms?: number; // real AVG(latency_ms) over the window (from /audit/stats)
};

type AuditRecord = {
  id?: string;
  timestamp: string;
  tool_name: string;
  decision: "allow" | "block" | "escalate" | "audit";
  rule_id?: string;
  namespace?: string;
  latency_ms?: number;
  agent_class?: string; // included in the CSV export
  reason?: string;
};

// `synthetic` marks a probe/eval/test identity (backend /agents flag). The Overview trust donut
// excludes them by default so it reconciles with the asset/attack graph, which hides exactly these probes.
type Agent = { category?: string; synthetic?: boolean };

function TopBlockedTools({ data }: { data: Array<{ tool: string; count: number }> }) {
  const max = Math.max(...data.map((d) => d.count), 1);
  return (
    <Panel title="Top blocked tools" sub="Most-blocked in selected range">
      <div style={{ display: "flex", flexDirection: "column", gap: 13, marginTop: 4 }}>
        {data.length === 0 && (
          <div style={{ color: "var(--text-muted)", fontSize: 13, padding: "16px 0", textAlign: "center" }}>
            No blocked tool calls in the selected range
          </div>
        )}
        {data.map((d) => (
          <div key={d.tool} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span
              className="mono"
              style={{
                fontSize: 13,
                color: "var(--text-secondary)",
                width: 104,
                flex: "none",
                whiteSpace: "nowrap",
                overflow: "hidden",
                textOverflow: "ellipsis"
              }}
            >
              {d.tool}
            </span>
            <div style={{ flex: 1, height: 10, borderRadius: 3, background: "#1f1f1f", overflow: "hidden" }}>
              <div
                style={{
                  width: `${(d.count / max) * 100}%`,
                  height: "100%",
                  background: "#ff3b5c",
                  borderRadius: 3
                }}
              />
            </div>
            <span style={{ fontSize: 13, color: "var(--text-primary)", width: 24, textAlign: "right", flex: "none" }}>
              {d.count}
            </span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

export function Dashboard() {
  const { selectedNamespace, selectedCluster, servedCluster, timeRange, selectedClusterConsoleUrl, posture } = useApp();
  // In Monitor mode the "Blocked" tile counts WOULD-BLOCK decisions, not live blocks — label it
  // so the headline number can't be read as enforced blocks. Concrete-namespace posture only (the "all"
  // aggregate mixes namespaces with possibly different modes).
  const monitorScope = posture.mode === "audit" && selectedNamespace !== "all";
  const navigate = useNavigate();
  // Cluster-aware Overview: in fleet mode, picking a cluster OTHER than the one this console serves (or "All
  // clusters") sources the cluster-scoped metrics from the HUB rollups (the only cross-cluster source). The
  // metrics the hub keeps per cluster (Total/Blocked/Block-Rate + Trust) then change on switch; the deep
  // telemetry the hub does NOT keep per cluster (latency, coverage, top-tools, volume) is honestly scoped out.
  const useHub = fleetEnabled && selectedCluster !== "" && selectedCluster !== servedCluster;
  const scopeCluster = selectedCluster === "all" ? "All clusters" : selectedCluster || servedCluster;
  const [reportMenuOpen, setReportMenuOpen] = useState(false);
  const stats = useApi<AuditStats>(
    () => fetchAuditStats(timeRange, selectedNamespace),
    [timeRange, selectedNamespace],
    {
      cacheKey: `dashboard-stats:${selectedNamespace}:${timeRange}`,
      staleTimeMs: 30_000,
      // Never cache an empty {total:0}, and on a warm-up/race empty, retry a few times so the real numbers
      // bind (a genuinely-empty range still settles on 0 after the bounded retries). Combined with useApi's
      // latest-wins guard, the cards always reflect the freshest /audit/stats — never stuck at 0.
      isEmpty: (d) => !d || (d.total ?? 0) === 0,
      emptyRetries: 4,
      emptyRetryMs: 1200
    }
  );
  const blocked = useApi<AuditRecord[]>(
    () => fetchAuditRecords({ range: timeRange, namespace: selectedNamespace, decision: "block", limit: 10 }),
    [timeRange, selectedNamespace]
  );
  const topBlocked = useApi<Array<{ tool_name: string; count: number }>>(
    () => fetchTopBlocked(timeRange, selectedNamespace),
    [timeRange, selectedNamespace]
  );
  const volume = useApi<Array<{ time: string; allow: number; block: number }>>(
    () => fetchVolume(timeRange, selectedNamespace),
    [timeRange, selectedNamespace]
  );
  const records = useApi<AuditRecord[]>(
    () => fetchAuditRecords({ range: timeRange, namespace: selectedNamespace, limit: 200 }),
    [timeRange, selectedNamespace]
  );
  const agents = useApi<Agent[]>(() => fetchAgents(selectedNamespace), [selectedNamespace], {
    cacheKey: `dashboard-agents:${selectedNamespace}`,
    staleTimeMs: 60_000,
    refetchIntervalMs: 60_000
  });
  // Real policy coverage per risk category — drives both the posture gauge and the category bars.
  const coverage = useApi(() => fetchCoverageByCategory(selectedNamespace), [selectedNamespace], {
    cacheKey: `dashboard-coverage:${selectedNamespace}`,
    staleTimeMs: 60_000
  });
  // The last Red Team run's efficacy — coverage is "rules present"; efficacy is "proven-blocking". When a
  // run exists we upgrade the honest "not efficacy-tested" caption to the REAL "X% proven-blocking (last run)".
  const efficacy = useApi<RedteamLatest>(() => fetchRedteamLatest(), [], {
    cacheKey: "dashboard-redteam-latest",
    staleTimeMs: 30_000
  });
  const provenPct = efficacy.data?.has_run ? efficacy.data.efficacy?.overall.proven_blocking_pct : undefined;
  // The caption is NEUTRAL (ScoreGauge renders --text-muted); only the proven-blocking % is teal --accent.
  // No block-red — that hue is reserved for real block decisions.
  const gaugeSub =
    provenPct != null ? (
      <>rules present · <b style={{ color: "var(--accent)" }}>{provenPct}% proven-blocking</b> (last run)</>
    ) : (
      "rules present — not efficacy-tested"
    );

  // Hub-rollup sources — only fetched when the Overview is scoped to a remote cluster (or "All clusters").
  const hubSummary = useApi(
    () => (useHub ? fetchFleetAuditSummary(timeRange, selectedCluster) : Promise.resolve([])),
    [useHub, timeRange, selectedCluster]
  );
  const hubAgents = useApi(
    () => (useHub ? fetchFleetAgents(selectedCluster) : Promise.resolve([])),
    [useHub, selectedCluster]
  );
  const hubTotals = useMemo(() => {
    const rows = Array.isArray(hubSummary.data) ? hubSummary.data : [];
    const scoped = selectedCluster === "all" ? rows : rows.filter((r) => r.cluster_id === selectedCluster);
    const total = scoped.reduce((a, r) => a + (r.total ?? 0), 0);
    const block = scoped.reduce((a, r) => a + (r.block ?? 0), 0);
    return { total, block, rate: total ? Math.round((block / total) * 100) : 0 };
  }, [hubSummary.data, selectedCluster]);

  const totalCalls = useHub ? hubTotals.total : stats.data?.total ?? 0;
  const blockedToday = useHub ? hubTotals.block : stats.data?.blocked ?? 0;
  const blockRate = useHub ? hubTotals.rate : Math.round(stats.data?.block_rate_pct ?? 0);
  // Engine (OPA-eval) faults — fail-closed, NOT policy decisions. Surfaced as a distinct signal.
  const engineErrors = stats.data?.engine_errors ?? 0;
  // First paint — no data resolved yet. Show skeletons instead of flashing 0/0/0 + a half-drawn donut.
  const kpiLoading = !useHub && stats.loading && stats.data == null;
  const postureLoading = !useHub && coverage.loading && coverage.data == null;
  const trustLoading = !useHub && agents.loading && agents.data == null;

  // Avg latency is the real AVG(latency_ms) over the window from /audit/stats (same call as the other KPIs,
  // updates on range change, avoids a stuck zero) — computed server-side, not client-side over ≤200 records.
  const avgLatency = Math.round(stats.data?.avg_latency_ms ?? 0);

  const trust = useMemo(() => {
    // Trust IS available per cluster from the hub (FleetAgent.trust_category), so the donut stays accurate
    // when scoped to a remote cluster; locally it's derived from the served cluster's agents.
    const cats = useHub
      ? (Array.isArray(hubAgents.data) ? hubAgents.data : []).map((a) => a.trust_category ?? "")
      // Exclude synthetic/probe identities so the donut counts the SAME real identities the
      // asset/attack graph shows (it default-hides these probes). Reconciles the two Overview surfaces.
      : (Array.isArray(agents.data) ? agents.data : []).filter((a) => !a.synthetic).map((a) => a.category ?? "");
    return ["high", "medium", "low", "frozen"].map((name) => ({
      name,
      value: cats.filter((c) => c.toLowerCase() === name).length
    }));
  }, [useHub, hubAgents.data, agents.data]);

  // Posture = overall real policy coverage %; category bars = real per-category coverage scores.
  const score = coverage.data?.coverage_pct ?? 0;

  // Export the loaded audit records as CSV (wired to the Export button and Report ▼ "Export CSV").
  const onExportCsv = () => {
    const rows = Array.isArray(records.data) ? records.data : [];
    setReportMenuOpen(false);
    exportCsv(
      `norviq-audit-${selectedNamespace}-${timeRange}.csv`,
      rows,
      ["timestamp", "decision", "tool_name", "rule_id", "agent_class", "namespace", "latency_ms", "reason"]
    );
  };

  // Only categories actually IN SCOPE for this namespace (baseline + enabled packs). Un-enabled sector
  // packs are NOT rendered as empty 0% "gaps" — they surface as an "available to add" affordance below.
  // ACCURACY: the bar `score` is rules-PRESENT (loaded), which is NOT the same as PROTECTED — a rule can be
  // loaded yet never have blocked anything (`effective=false`), and in Monitor mode it only logs a
  // would-block. So we colour PROVEN-effective categories solid green and LOADED-BUT-UNPROVEN ones a muted
  // slate, so "100% loaded" can never be misread as "100% protected".
  const categoryScores = useMemo(
    () =>
      (coverage.data?.categories ?? [])
        .filter((c) => c.in_scope ?? c.covered > 0)
        .map((c) => ({
          category: c.category,
          score: c.score,
          color: c.effective ? "#00E5A0" : "#5f6b7a" // proven-blocking vs loaded-but-unproven
        })),
    [coverage.data]
  );
  const availableSectors = coverage.data?.available ?? 0;

  const topBlockedData = useMemo(
    () =>
      (Array.isArray(topBlocked.data) ? topBlocked.data : []).map((item) => ({
        tool: item.tool_name,
        count: item.count
      })),
    [topBlocked.data]
  );

  const apiError = useHub
    ? hubSummary.error || hubAgents.error
    : stats.error || blocked.error || records.error || agents.error || topBlocked.error || volume.error;

  useEffect(() => {
    const interval = setInterval(() => {
      void stats.refetch();
    }, 30_000);
    return () => clearInterval(interval);
  }, [timeRange, selectedNamespace]);

  return (
    <div className="page-enter">
      <PageHead
        title="Overview"
        subtitle={
          fleetEnabled
            ? `Showing: ${scopeCluster} · ${selectedNamespace}${useHub ? " — summary from fleet hub" : ""}`
            : `Showing: ${selectedNamespace}`
        }
        actions={
          <>
            <KitButton
              variant="ghost"
              icon={FileText}
              style={{ background: "transparent", border: "1px solid #2A2A2A", color: "#A0A0A0" }}
              onClick={() => setReportMenuOpen((v) => !v)}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = "#2DDAB8")}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = "#2A2A2A")}
            >
              Report ▼
            </KitButton>
            {reportMenuOpen && (
              <div
                style={{
                  position: "absolute",
                  marginTop: 36,
                  background: "#171717",
                  border: "1px solid #2A2A2A",
                  borderRadius: 10,
                  padding: 6,
                  minWidth: 180,
                  zIndex: 20
                }}
              >
                <button className="dd-item" style={{ padding: "8px 12px" }} onClick={onExportCsv}>
                  Export CSV
                </button>
                <button className="dd-item" style={{ padding: "8px 12px", color: "#666666" }} disabled>
                  Export PDF (coming soon)
                </button>
                <button className="dd-item" style={{ padding: "8px 12px", color: "#666666" }} disabled>
                  Schedule Report (coming soon)
                </button>
              </div>
            )}
            {/* The Report ▾ menu is the single export affordance — there is no separate standalone Export
                button — and it also houses the future PDF / Schedule options. */}
          </>
        }
      />
      <div className="stack" style={{ gap: 20 }}>
        <div className="grid grid-cols-4 lg:grid-cols-4 md:grid-cols-2 gap-5 dashboard-kpi-grid">
          {kpiLoading ? (
            // Skeleton cards on first paint — never flash 0/0/0 before the stats resolve.
            [0, 1, 2, 3].map((i) => (
              <div key={i} className="panel kpi" style={{ background: "var(--bg-surface)", boxShadow: "var(--shadow-card)" }}>
                <div className="skeleton-line" style={{ width: "58%", height: 11, marginBottom: 12 }} />
                <div className="skeleton-line" style={{ width: "40%", height: 26 }} />
              </div>
            ))
          ) : (
            <>
              <KPICard testid="kpi-total" label={`Total Calls ${timeRange}`} value={totalCalls} color="#2ddab8" />
              <KPICard
                testid="kpi-blocked"
                label={monitorScope ? `Would-block (${timeRange})` : `Blocked (${timeRange})`}
                value={blockedToday}
                color="#ff3b5c"
                trend={monitorScope ? "Monitor mode — not blocked live" : undefined}
              />
              <KPICard testid="kpi-blockrate" label={monitorScope ? `Would-block Rate % (${timeRange})` : `Block Rate % (${timeRange})`} value={blockRate} color="#ffb020" />
              {/* Latency isn't kept per-cluster at the hub — show "—" rather than the served cluster's number. */}
              {useHub ? (
                <div className="panel kpi" style={{ background: "var(--bg-surface)", boxShadow: "var(--shadow-card)" }}>
                  <div className="kpi-label">{`Avg Latency ms (${timeRange})`}</div>
                  <div className="kpi-value" style={{ color: "var(--text-muted)" }}>—</div>
                  <div className="kpi-trend" style={{ color: "var(--text-muted)" }}>per-cluster, on its own console</div>
                </div>
              ) : (
                <KPICard testid="kpi-latency" label={`Avg Latency ms (${timeRange})`} value={avgLatency} color="#00e5a0" />
              )}
            </>
          )}
        </div>

        {/* Engine-error signal — fail-closed OPA-eval faults are made visible on the Overview (not just the
            API), and clearly distinct from policy blocks. Only shown when there ARE faults, so it stays quiet. */}
        {!useHub && engineErrors > 0 && (
          <div
            role="status"
            style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", background: "rgba(255,176,32,0.08)", border: "1px solid #4a3a1a", borderRadius: 10, fontSize: 12.5 }}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#FFB020" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flex: "none" }}><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
            <span style={{ color: "#ffcf82" }}>
              <b>{engineErrors.toLocaleString()}</b> engine error{engineErrors === 1 ? "" : "s"} in {timeRange} — fail-closed OPA-evaluation faults, <b>not</b> policy blocks.
            </span>
            <button onClick={() => navigate("/audit")} style={{ marginLeft: "auto", background: "transparent", border: "none", cursor: "pointer", color: "var(--accent, #00e5a0)", fontWeight: 600, fontSize: 12.5 }}>Review in Audit Log →</button>
          </div>
        )}

        <div className="grid grid-cols-3 lg:grid-cols-3 md:grid-cols-1 gap-5 dashboard-row-two">
          {/* One honest headline — this gauge IS policy coverage (rules present), not a "Security Score /
              High Risk" verdict on the same number. The Trust donut + the per-category bars are its support. */}
          {useHub ? (
            <RemoteScopedPanel title="Policy Coverage" cluster={scopeCluster} consoleUrl={selectedClusterConsoleUrl} />
          ) : postureLoading ? (
            // Skeleton the gauge until coverage resolves (never flash a 0% ring).
            <div className="panel" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 14, minHeight: 200 }}>
              <div className="skeleton-line" style={{ width: 120, height: 120, borderRadius: "50%" }} />
              <div className="skeleton-line" style={{ width: "50%", height: 12 }} />
            </div>
          ) : (
            <Suspense fallback={ringSkeleton}>
              <ScoreGauge score={score} title="Policy Coverage" unit="%" sub={gaugeSub} />
            </Suspense>
          )}
          {/* Trust is cluster-aware (hub keeps it per cluster) — the donut changes on switch. */}
          {trustLoading ? (
            // Skeleton the trust donut until agents resolve (never render broken fragments).
            <div className="panel" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 14, minHeight: 200 }}>
              <div className="skeleton-line" style={{ width: 120, height: 120, borderRadius: "50%" }} />
              <div className="skeleton-line" style={{ width: "40%", height: 12 }} />
            </div>
          ) : (
            // The trust donut restates data fully explorable on Agent Monitor — make it a
            // drill-through (keyboard-accessible) instead of a decorative repeat, matching "See All →".
            <div
              role="link"
              tabIndex={0}
              title="Open Agent Monitor"
              onClick={() => navigate("/agents")}
              onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); navigate("/agents"); } }}
              style={{ cursor: "pointer" }}
            >
              <Suspense fallback={ringSkeleton}>
                <DonutChart data={trust} />
              </Suspense>
            </div>
          )}
          {useHub ? (
            <RemoteScopedPanel title="Top blocked tools" sub="Most-blocked in selected range" cluster={scopeCluster} consoleUrl={selectedClusterConsoleUrl} />
          ) : (
            <TopBlockedTools data={topBlockedData} />
          )}
        </div>

        {useHub ? (
          <RemoteScopedPanel title="Policy Coverage by Category" cluster={scopeCluster} consoleUrl={selectedClusterConsoleUrl} />
        ) : (
          // ONE "Policy Coverage" card, two dimensions (risk category + agent class), color-first: the bar
          // COLOUR is the whole legend (green = proven-blocking, grey = loaded-not-proven). Verbose legend
          // sentences / state badges / captions were removed — a compact color key + a Monitor dot carry it.
          <Panel
            title="Policy Coverage"
            action={
              <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 11, color: "var(--text-muted)" }}>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }} title="Proven blocking — a rule in this category has actually stopped (or would-block) traffic">
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: "#00E5A0" }} /> proven
                </span>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }} title="Loaded but not yet proven — no traffic has exercised these rules; run the Red Team suite to prove them">
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: "#5f6b7a" }} /> loaded
                </span>
                {posture.mode === "audit" && (
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 5, color: "var(--escalate)" }} title="Monitor mode — matched rules log a would-block but do NOT enforce. Switch to Block in Target Settings.">
                    <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--escalate)" }} /> monitor
                  </span>
                )}
              </div>
            }
          >
            <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 4 }}>By risk category</div>
            <Suspense fallback={barsSkeleton}>
              <CategoryBars data={categoryScores} bare />
            </Suspense>
            {availableSectors > 0 && (
              <button
                type="button"
                onClick={() => navigate("/policies/packs")}
                style={{
                  display: "inline-flex", alignItems: "center", gap: 6, marginTop: 6,
                  background: "transparent", border: "none", color: "var(--text-muted)",
                  fontFamily: "inherit", fontSize: 11.5, cursor: "pointer", padding: 0
                }}
                title="Enable a sector pack to extend coverage to more risk categories"
              >
                <span style={{ color: "var(--accent)", fontWeight: 700 }}>+{availableSectors}</span>
                more available — enable a pack →
              </button>
            )}

            {/* AGENT-CLASS dimension in the SAME card, below a divider — same color language, scales to
                many classes as a clean list of colour-coded bars. */}
            {(coverage.data?.agent_class_policies?.length ?? 0) > 0 && (
              <>
                <div style={{ height: 1, background: "var(--border)", margin: "16px 0 12px" }} />
                <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 8 }}>By agent class</div>
                <Suspense fallback={barsSkeleton}>
                  <AgentClassCoverage
                    policies={coverage.data?.agent_class_policies ?? []}
                    namespaceMode={coverage.data?.namespace_mode}
                    bare
                  />
                </Suspense>
              </>
            )}
          </Panel>
        )}

        {useHub ? (
          <RemoteScopedPanel title="Tool Call Volume" cluster={scopeCluster} consoleUrl={selectedClusterConsoleUrl} />
        ) : (
          <Suspense fallback={barsSkeleton}>
            <VolumeChart data={Array.isArray(volume.data) ? volume.data : []} />
          </Suspense>
        )}

        {useHub ? (
          <RemoteScopedPanel title="Recent Blocked" sub="Last 10 blocked tool calls" cluster={scopeCluster} consoleUrl={selectedClusterConsoleUrl} />
        ) : (
        <Panel
          title="Recent Blocked"
          sub="Last 10 blocked tool calls"
          style={{ paddingBottom: 6 }}
          action={
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => navigate(`/audit?decision=block`)}
              type="button"
            >
              See All →
            </button>
          }
        >
          <div style={{ overflowX: "auto" }}>
            {(Array.isArray(blocked.data) ? blocked.data : []).length === 0 ? (
              <div
                style={{
                  textAlign: "center",
                  color: "var(--text-muted)",
                  padding: "32px 0",
                  fontSize: 13
                }}
              >
                No blocked tool calls in the selected range
              </div>
            ) : (
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Tool</th>
                    <th>Decision</th>
                    <th>Rule</th>
                    <th>Namespace</th>
                  </tr>
                </thead>
                <tbody>
                  {(Array.isArray(blocked.data) ? blocked.data : []).map((row, i) => (
                    <tr
                      key={row.id ?? i}
                      onClick={() => {
                        const params = new URLSearchParams({ decision: "block" });
                        if (row.tool_name) params.set("tool_name", row.tool_name);
                        navigate(`/audit?${params.toString()}`);
                      }}
                    >
                      <td className="mono muted">{fmtTime(row.timestamp)}</td>
                      <td>{row.tool_name}</td>
                      <td>
                        <DecisionBadge decision={row.decision} />
                      </td>
                      <td className="mono muted">{row.rule_id ?? "—"}</td>
                      <td className="mono">{row.namespace ?? selectedNamespace}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </Panel>
        )}

        {apiError && (
          <div style={{ color: "var(--block)", fontSize: 13 }}>
            API unavailable. Showing partial data.
          </div>
        )}
      </div>
    </div>
  );
}
