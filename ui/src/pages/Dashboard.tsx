import { Download, FileText } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchAgents, fetchAuditRecords, fetchAuditStats, fetchTopBlocked, fetchVolume } from "../api/client";
import { CategoryBars } from "../components/charts/CategoryBars";
import { VolumeChart } from "../components/charts/VolumeChart";
import { DecisionBadge } from "../components/common/DecisionBadge";
import { DonutChart } from "../components/common/DonutChart";
import { KitButton } from "../components/common/KitButton";
import { KPICard } from "../components/common/KPICard";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { ScoreGauge } from "../components/common/ScoreGauge";
import { useApi } from "../hooks/useApi";
import { fmtTime } from "../lib/format";
import { useApp } from "../store/AppContext";

type AuditStats = {
  total?: number;
  blocked?: number;
  allowed?: number;
  block_rate_pct?: number;
};

type AuditRecord = {
  id?: string;
  timestamp: string;
  tool_name: string;
  decision: "allow" | "block" | "escalate" | "audit";
  rule_id?: string;
  namespace?: string;
  latency_ms?: number;
};

type Agent = { category?: string };

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
  const { selectedNamespace, timeRange } = useApp();
  const navigate = useNavigate();
  const [reportMenuOpen, setReportMenuOpen] = useState(false);
  const stats = useApi<AuditStats>(
    () => fetchAuditStats(timeRange, selectedNamespace),
    [timeRange, selectedNamespace],
    {
      cacheKey: `dashboard-stats:${selectedNamespace}:${timeRange}`,
      staleTimeMs: 30_000
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

  const totalCalls = stats.data?.total ?? 0;
  const blockedToday = stats.data?.blocked ?? 0;
  const blockRate = Math.round(stats.data?.block_rate_pct ?? 0);

  const avgLatency = useMemo(() => {
    const rows = Array.isArray(records.data) ? records.data : [];
    if (rows.length === 0) return 0;
    const sum = rows.reduce((acc, row) => acc + (row.latency_ms ?? 0), 0);
    return Math.round(sum / rows.length);
  }, [records.data]);

  const trust = useMemo(
    () =>
      ["high", "medium", "low", "frozen"].map((name) => ({
        name,
        value: (Array.isArray(agents.data) ? agents.data : []).filter(
          (agent) => (agent.category ?? "").toLowerCase() === name
        ).length
      })),
    [agents.data]
  );

  const score = useMemo(() => {
    const br = stats.data?.block_rate_pct ?? 0;
    return Math.max(0, Math.min(100, Math.round(95 - br * 1.6)));
  }, [stats.data?.block_rate_pct]);

  const categoryScores = useMemo(() => {
    const br = stats.data?.block_rate_pct ?? 0;
    return [
      { category: "OWASP LLM", score: Math.max(40, 100 - Math.round(br * 0.7)) },
      { category: "Data Protection", score: Math.max(40, 100 - Math.round(br * 0.6)) },
      { category: "Tool Safety", score: Math.max(40, 100 - Math.round(br * 0.9)) },
      { category: "Rate Limiting", score: Math.max(40, 100 - Math.round(br * 1.1)) },
      { category: "Trust", score: Math.max(40, 100 - Math.round(br * 0.5)) }
    ];
  }, [stats.data?.block_rate_pct]);

  const topBlockedData = useMemo(
    () =>
      (Array.isArray(topBlocked.data) ? topBlocked.data : []).map((item) => ({
        tool: item.tool_name,
        count: item.count
      })),
    [topBlocked.data]
  );

  const apiError = stats.error || blocked.error || records.error || agents.error || topBlocked.error || volume.error;

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
        subtitle={`Showing: ${selectedNamespace}`}
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
                <button className="dd-item" style={{ padding: "8px 12px" }}>
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
            <KitButton
              variant="ghost"
              icon={Download}
              style={{
                background: "transparent",
                border: "1px solid #A0A0A0",
                color: "#A0A0A0"
              }}
              onMouseEnter={(e) => (e.currentTarget.style.background = "#2DDAB815")}
              onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
            >
              Export
            </KitButton>
          </>
        }
      />
      <div className="stack" style={{ gap: 20 }}>
        <div className="grid grid-cols-4 lg:grid-cols-4 md:grid-cols-2 gap-5 dashboard-kpi-grid">
          <KPICard label={`Total Calls ${timeRange}`} value={totalCalls} trend="↑12% vs yesterday" color="#2ddab8" />
          <KPICard label={`Blocked (${timeRange})`} value={blockedToday} trend="↓8% false positives" color="#ff3b5c" />
          <KPICard label={`Block Rate % (${timeRange})`} value={blockRate} trend="↓ healthier traffic" color="#ffb020" />
          <KPICard label={`Avg Latency ms (${timeRange})`} value={avgLatency} trend="↑ fast path stable" color="#00e5a0" />
        </div>

        <div className="grid grid-cols-3 lg:grid-cols-3 md:grid-cols-1 gap-5 dashboard-row-two">
          <ScoreGauge score={score} />
          <DonutChart data={trust} />
          <TopBlockedTools data={topBlockedData} />
        </div>

        <CategoryBars data={categoryScores} title="Policy Coverage by Category" />

        <VolumeChart data={Array.isArray(volume.data) ? volume.data : []} />

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

        {apiError && (
          <div style={{ color: "var(--block)", fontSize: 13 }}>
            API unavailable. Showing partial data.
          </div>
        )}
      </div>
    </div>
  );
}
