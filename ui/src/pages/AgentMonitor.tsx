import { ArrowLeft, RotateCcw, Snowflake, Sun } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { apiGet, apiSend, fetchAgentToolUsage, fetchAgentTrustHistory } from "../api/client";
import { CategoryBars } from "../components/charts/CategoryBars";
import { VolumeChart } from "../components/charts/VolumeChart";
import { DataTable, type Column } from "../components/common/DataTable";
import { DonutChart } from "../components/common/DonutChart";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { timeAgo } from "../lib/d3-helpers";
import { StatTile } from "../components/common/StatTile";
import { TrustBadge, trustCategory } from "../components/common/TrustBadge";
import { useApi, invalidateApiCache } from "../hooks/useApi";
import { useApp } from "../store/AppContext";

// CAP-2: tool risk-tier → bar colour (matches the graph RISK palette). Used to colour the Tool Usage
// bars by risk instead of by call volume.
const RISK_TIER_COLORS: Record<"low" | "medium" | "high" | "critical", string> = {
  low: "#00E5A0",
  medium: "#FFB020",
  high: "#FF7A45",
  critical: "#FF3B5C"
};

type AgentRow = {
  spiffe_id: string;
  agent_class?: string;
  namespace?: string;
  score: number;
  category: string;
  behavior?: "normal" | "anomalous";
  violation_count?: number;
  last_seen?: string;
  signals?: Record<string, number>;
  dominant_signal?: string;
  recommendation?: string;
};

export function AgentMonitor() {
  const { namespace, timeRange } = useApp();
  const [selected, setSelected] = useState<AgentRow | null>(null);
  // DEF-040: a freeze/reset that fails (e.g. 403 for a non-admin viewer, network, 5xx) must NOT be
  // swallowed — surface the reason near the action buttons so the control isn't a silent dead no-op.
  const [actionError, setActionError] = useState<string | null>(null);
  // P5: the detail renders below a potentially long table — scroll it into view on select so clicking a row
  // visibly OPENS the detail (trust history + freeze/adjust) instead of silently rendering off-screen.
  const detailRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (selected && detailRef.current?.scrollIntoView) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [selected?.spiffe_id]);
  const agents = useApi<AgentRow[]>(
    () => apiGet(`/api/v1/agents?namespace=${encodeURIComponent(namespace)}`),
    // Pause the 60s auto-refetch while an agent detail is OPEN so the list + panel don't mutate under the
    // operator mid-interaction (freezing/inspecting an agent shouldn't have the view refresh itself). The
    // `!!selected` dep re-runs the effect only on the open↔close transition — switching between two already-
    // open agents doesn't refetch; closing (Back) resumes the interval and pulls a fresh, persisted list.
    [namespace, !!selected],
    {
      cacheKey: `agent-monitor:${namespace}`,
      staleTimeMs: 60_000,
      refetchIntervalMs: selected ? undefined : 60_000
    }
  );

  // Compliance deep-link: an affected-agent-class chip opens the Agents page pre-filtered to that class (?class=).
  const [searchParams] = useSearchParams();
  const classFilter = searchParams.get("class");
  const rows = useMemo(() => {
    const all = agents.data ?? [];
    return classFilter ? all.filter((a) => a.agent_class === classFilter) : all;
  }, [agents.data, classFilter]);

  const trust = useMemo(
    () =>
      ["high", "medium", "low", "frozen"].map((name) => ({
        name,
        value: rows.filter((a) => (a.category ?? "").toLowerCase() === name).length
      })),
    [rows]
  );

  const updateTrust = async (id: string, score: number) => {
    setActionError(null);
    try {
      await apiSend(`/api/v1/agents/${encodeURIComponent(id)}/trust`, "PUT", { score });
      // DEF-022: read-modify-write the FULL fleet (agents.data), not `rows` — which is a strict subset
      // when a ?class= deep-link filter is active. setData below fully REPLACES agents.data, so building
      // `next` from the filtered `rows` would drop every other agent until the 60s refetch (clearing the
      // filter would then show only the one class and the StatTiles would undercount). The
      // (a.spiffe_id === id) predicate still mutates only the frozen/reset agent.
      const next = (agents.data ?? []).map((a) =>
        a.spiffe_id === id
          ? { ...a, score, category: score === 0 ? "frozen" : trustCategory(score) }
          : a
      );
      agents.setData(next);
      // STALE-8: setData only updates React state — the module cache (60s TTL) still holds the pre-freeze
      // score, so an unmount/remount within the window served the stale list (freeze looked reverted). Bust it.
      invalidateApiCache("agent-monitor:");
      if (selected?.spiffe_id === id) {
        setSelected({ ...selected, score, category: score === 0 ? "frozen" : trustCategory(score) });
      }
    } catch (e) {
      // DEF-040: surface the failure instead of swallowing it (backend requires admin — apiSend throws on
      // a 403 !ok — plus network/5xx). Without this the Freeze/Reset buttons look like dead controls.
      setActionError((e as Error).message || "Trust update failed");
    }
  };

  // Real per-agent insights from audit_log (F046), fetched when an agent is selected. Honor the header's
  // time range (was silently pinned to 7d, diverging from the range the user picked).
  const trustHistoryApi = useApi(
    () => (selected ? fetchAgentTrustHistory(selected.spiffe_id, namespace, timeRange) : Promise.resolve([])),
    [selected?.spiffe_id, namespace, timeRange]
  );
  const toolUsageApi = useApi(
    () => (selected ? fetchAgentToolUsage(selected.spiffe_id, namespace, timeRange) : Promise.resolve([])),
    [selected?.spiffe_id, namespace, timeRange]
  );

  const trustHistory = useMemo(
    () => (trustHistoryApi.data ?? []).map((p) => ({ time: p.time, allow: p.allow, block: p.block })),
    [trustHistoryApi.data]
  );

  // Tool-call counts, shown as relative usage (busiest tool = 100%) so the shared bar chart stays 0–100.
  // CAP-2: colour each bar by the tool's RISK tier (server-provided), not by usage volume — so a heavy
  // destructive tool stands out red instead of looking identical to a heavy benign search.
  const toolUsage = useMemo(() => {
    const rows = toolUsageApi.data ?? [];
    const max = Math.max(1, ...rows.map((r) => r.count));
    return rows.map((r) => ({
      category: r.tool,
      score: Math.round((r.count / max) * 100),
      color: RISK_TIER_COLORS[r.risk ?? "medium"]
    }));
  }, [toolUsageApi.data]);

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
    // "Behavior" column removed: it unconditionally rendered "Normal" for every agent (a not-yet-built
    // Phase-3 feature) sitting next to real Trust/Violations telemetry, reading as fabricated live data.
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
      // B4: humanize the ISO last-observation timestamp (was raw/"–").
      render: (v) => <span className="mono muted">{v ? timeAgo(String(v)) : "—"}</span>
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
            <StatTile label="Agents Tracked" value={rows.length} color="var(--accent)" />
            <StatTile
              label="Frozen"
              value={rows.filter((a) => a.category === "frozen").length}
              color="var(--text-muted)"
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
          <div className="grid-kit g3" ref={detailRef} style={{ scrollMarginTop: 16 }}>
            <VolumeChart data={trustHistory} title={`Trust History · ${timeRange}`} labels={["Trust", "Risk"]} />
            <CategoryBars data={toolUsage} title="Tool Usage" sub="bar length = call volume · colour = tool risk tier" />
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
              <div className="kv">
                <span className="k">Recommendation</span>
                <span className="mono">{selected.recommendation ?? "allow"}</span>
              </div>
              <div style={{ marginTop: 14 }}>
                <div className="k" style={{ marginBottom: 8 }}>
                  Signal Breakdown {selected.dominant_signal ? `(dominant: ${selected.dominant_signal})` : ""}
                </div>
                {Object.entries(selected.signals ?? {}).map(([name, value]) => (
                  <div className="kv" key={name}>
                    <span className="mono">{name}</span>
                    <span className="mono">{Number(value).toFixed(2)}</span>
                  </div>
                ))}
              </div>
              <div style={{ display: "flex", gap: 8, marginTop: 16, flexWrap: "wrap" }}>
                {/* Explicit way back to the full list — the detail renders below the table with no other exit. */}
                <KitButton variant="ghost" icon={ArrowLeft} onClick={() => setSelected(null)}>
                  Back to all agents
                </KitButton>
                {selected.category === "frozen" || selected.score === 0 ? (
                  // A frozen agent's one meaningful action is to UNFREEZE (restore trust) — resetting the score
                  // of a frozen agent is a no-op-looking dead end, so swap the Freeze control for an explicit
                  // Unfreeze rather than leaving the operator with only "Reset Trust" to guess at.
                  <KitButton
                    variant="primary"
                    icon={Sun}
                    onClick={() => updateTrust(selected.spiffe_id, 0.8)}
                  >
                    Unfreeze Agent
                  </KitButton>
                ) : (
                  <>
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
                  </>
                )}
              </div>
              {actionError && (
                // DEF-040: failed freeze/reset feedback — the control is no longer silent on 403/network/5xx.
                <div
                  role="alert"
                  style={{ marginTop: 12, fontSize: 12.5, color: "var(--block)", wordBreak: "break-word" }}
                >
                  {actionError}
                </div>
              )}
            </Panel>
          </div>
        )}
      </div>
    </div>
  );
}
