import { RotateCcw, Snowflake } from "lucide-react";
import { useMemo, useState } from "react";
import { apiGet, apiSend } from "../api/client";
import { CategoryBars } from "../components/charts/CategoryBars";
import { VolumeChart } from "../components/charts/VolumeChart";
import { DataTable, type Column } from "../components/common/DataTable";
import { DonutChart } from "../components/common/DonutChart";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { StatTile } from "../components/common/StatTile";
import { TrustBadge, trustCategory } from "../components/common/TrustBadge";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";

type AgentRow = {
  spiffe_id: string;
  agent_class?: string;
  namespace?: string;
  score: number;
  category: string;
  behavior?: "normal" | "anomalous";
  violation_count?: number;
  last_seen?: string;
};

export function AgentMonitor() {
  const { namespace } = useApp();
  const [selected, setSelected] = useState<AgentRow | null>(null);
  const agents = useApi<AgentRow[]>(
    () => apiGet(`/api/v1/agents?namespace=${encodeURIComponent(namespace)}`),
    [namespace],
    {
      cacheKey: `agent-monitor:${namespace}`,
      staleTimeMs: 60_000,
      refetchIntervalMs: 60_000
    }
  );

  const rows = agents.data ?? [];

  const trust = useMemo(
    () =>
      ["high", "medium", "low", "frozen"].map((name) => ({
        name,
        value: rows.filter((a) => (a.category ?? "").toLowerCase() === name).length
      })),
    [rows]
  );

  const updateTrust = async (id: string, score: number) => {
    try {
      await apiSend(`/api/v1/agents/${encodeURIComponent(id)}/trust`, "PUT", { score });
      const next = rows.map((a) =>
        a.spiffe_id === id
          ? { ...a, score, category: score === 0 ? "frozen" : trustCategory(score) }
          : a
      );
      agents.setData(next);
      if (selected?.spiffe_id === id) {
        setSelected({ ...selected, score, category: score === 0 ? "frozen" : trustCategory(score) });
      }
    } catch {
      // ignore
    }
  };

  const trustHistory = useMemo(() => {
    const cur = selected?.score ?? 0.8;
    return Array.from({ length: 7 }, (_, i) => {
      const t = Math.max(0, Math.min(1, cur - (6 - i) * 0.04 + (i % 2 ? 0.02 : -0.01)));
      return { time: `D${i + 1}`, allow: Math.round(t * 100), block: Math.round((1 - t) * 100) };
    });
  }, [selected]);

  const toolUsage = useMemo(
    () => [
      { category: "read_file", score: 88 },
      { category: "db_query", score: 72 },
      { category: "http_request", score: 54 },
      { category: "exec_shell", score: 22 },
      { category: "send_email", score: 41 }
    ],
    []
  );

  const columns: Array<Column<AgentRow>> = [
    {
      key: "spiffe_id",
      title: "SPIFFE ID",
      render: (v) => <span className="mono" style={{ fontSize: 12 }}>{String(v)}</span>
    },
    { key: "namespace", title: "Namespace", render: (v) => <span className="mono">{String(v ?? "—")}</span> },
    { key: "agent_class", title: "Class" },
    {
      key: "score",
      title: "Trust Score",
      render: (v) => <span className="mono">{Number(v).toFixed(2)}</span>
    },
    {
      key: "category",
      title: "Tier",
      render: (v) => <TrustBadge category={String(v)} pulse={String(v).toLowerCase() === "low"} />
    },
    {
      key: "behavior",
      title: "Behavior",
      thTitle: "Behavioral anomaly detection · coming in Phase 3",
      render: (_v, _row) => (
        <span className="behavior normal">
          <span className="bdot" />
          <span style={{ color: "#A0A0A0" }}>Normal</span>
        </span>
      )
    },
    {
      key: "violation_count",
      title: "Violations",
      render: (v) => {
        const n = Number(v ?? 0);
        return (
          <span style={{ color: n > 8 ? "#ff3b5c" : n > 3 ? "#ffb020" : "var(--text-secondary)" }}>
            {n}
          </span>
        );
      }
    },
    {
      key: "last_seen",
      title: "Last Seen",
      render: (v) => <span className="mono muted">{String(v ?? "—")}</span>
    }
  ];

  return (
    <div className="page-enter">
      <PageHead title="Agent Monitor" subtitle={`Showing: ${namespace}`} />
      <div className="stack">
        <div className="grid-kit g3">
          <div style={{ gridColumn: "span 1" }}>
            <DonutChart data={trust} title="Trust Distribution" />
          </div>
          <div
            className="grid-kit g2"
            style={{ gridColumn: "span 2", gridTemplateColumns: "1fr 1fr", alignContent: "start" }}
          >
            <StatTile label="Agents Tracked" value={rows.length} color="#2ddab8" />
            <StatTile
              label="Frozen"
              value={rows.filter((a) => a.category === "frozen").length}
              color="#666666"
            />
            <StatTile
              label="Low Trust"
              value={rows.filter((a) => a.category === "low").length}
              color="#ff3b5c"
            />
            <StatTile
              label="High Trust"
              value={rows.filter((a) => a.category === "high").length}
              color="#00e5a0"
            />
          </div>
        </div>

        <DataTable
          columns={columns}
          rows={rows}
          rowKey="spiffe_id"
          selectedKey={selected?.spiffe_id ?? null}
          onRowClick={(r) => setSelected(r)}
          placeholder="Search SPIFFE ID, class, tier…"
        />

        {selected && (
          <div className="grid-kit g3">
            <VolumeChart data={trustHistory} title="Trust History · 7d" labels={["Trust", "Risk"]} />
            <CategoryBars data={toolUsage} title="Tool Usage" />
            <Panel title="Agent Actions">
              <div
                className="mono"
                style={{
                  fontSize: 12,
                  color: "var(--text-secondary)",
                  wordBreak: "break-all",
                  marginBottom: 14
                }}
              >
                {selected.spiffe_id}
              </div>
              <div className="kv">
                <span className="k">Class</span>
                <span>{selected.agent_class ?? "—"}</span>
              </div>
              <div className="kv">
                <span className="k">Namespace</span>
                <span className="mono">{selected.namespace ?? "—"}</span>
              </div>
              <div className="kv">
                <span className="k">Current trust</span>
                <span>
                  <TrustBadge category={selected.category} />{" "}
                  <span className="mono">{selected.score.toFixed(2)}</span>
                </span>
              </div>
              <div className="kv">
                <span className="k">Violations</span>
                <span>{selected.violation_count ?? 0}</span>
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 16 }}>
                <KitButton
                  variant="primary"
                  icon={RotateCcw}
                  onClick={() => updateTrust(selected.spiffe_id, 0.8)}
                >
                  Reset Trust
                </KitButton>
                <KitButton
                  variant="destructive"
                  icon={Snowflake}
                  onClick={() => updateTrust(selected.spiffe_id, 0)}
                >
                  Freeze Agent
                </KitButton>
              </div>
            </Panel>
          </div>
        )}
      </div>
    </div>
  );
}
