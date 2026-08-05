// Agent Monitor — the governed fleet's per-agent trust view: a sortable roster with trust scores,
// behavior signals and recommendations, plus a per-agent drill-down (tool usage by risk tier, trust
// history, and freeze/unfreeze controls). Namespace-scoped.

import { ArrowLeft, RefreshCw, RotateCcw, Snowflake, Sun } from "lucide-react";
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

// Tool risk-tier → bar colour (matches the graph RISK palette). Used to colour the Tool Usage
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
  /**
   * A probe / eval / red-team identity rather than a real agent.
   *
   * The API has always sent this; this type simply did not declare it, so this page counted every
   * identity including probes while the Overview's donut — reading the SAME endpoint — filtered them
   * out (`Dashboard.tsx`: `.filter((a) => !a.synthetic)`). Two "agents" numbers over one population,
   * with nothing on either screen saying which was which.
   */
  synthetic?: boolean;
  behavior?: "normal" | "anomalous";
  violation_count?: number;
  last_seen?: string;
  signals?: Record<string, number>;
  dominant_signal?: string;
  recommendation?: string;
};

/**
 * A chart that could not be drawn because the read behind it FAILED.
 *
 * `VolumeChart` and `CategoryBars` are shared components with no error state: handed `[]` they draw a
 * complete, well-formed, EMPTY chart — axes, gridlines, a bar track — which is the picture of "we
 * measured this agent and it did nothing". A 503 must not paint that picture. It matters most here
 * because the drill-down asks the operator to decide whether to FREEZE an identity, and "no blocked
 * calls in the window" is the reading that argues against freezing.
 *
 * The split that introduced the Trust panel made it acute: `Decision volume` and `Trust` are fed by
 * ONE request (`/agents/{id}/trust-history`), so with only the Trust half error-aware the same failure
 * rendered as a stated error beside a drawn chart — the console contradicting itself about one fetch.
 */
function UnreadableChart({
  title,
  what,
  error,
  testId
}: {
  title: string;
  what: string;
  error: string;
  testId: string;
}) {
  return (
    <Panel title={title} data-testid={testId}>
      <div style={{ fontSize: 12.5, lineHeight: 1.6, color: "var(--text-secondary)" }}>
        Couldn&rsquo;t read {what} — <span className="mono">{error}</span>. No chart is drawn here on purpose:
        an empty one would read as &ldquo;measured, and there was no activity&rdquo;, which is the opposite of
        what happened.
      </div>
    </Panel>
  );
}

/**
 * The agent's real trust score over the window — the series the "Trust History" panel used to promise
 * and never plotted.
 *
 * `/agents/{id}/trust-history` computes it per bucket as `round(sum(trust)/n, 3)` and returns `null`
 * for a bucket in which no decision carried a trust score. A null is a bucket NOBODY MEASURED, so it
 * is a break in the line and a stated count — never a plotted zero, which on a 0–1 axis is the worst
 * score there is and would read as an agent that collapsed.
 *
 * Hand-drawn rather than routed through VolumeChart: that component is a two-series 0..n line chart
 * with allow-green and block-red hardcoded per series index, and it is shared with the Overview.
 */
function TrustHistory({
  points,
  range,
  loading,
  error
}: {
  points: Array<{ time: string; score: number | null }>;
  range: string;
  loading: boolean;
  error: string | null;
}) {
  const measured = points.filter((p) => p.score != null);
  const gaps = points.length - measured.length;

  // Contiguous runs of measured buckets, so an unmeasured one leaves a visible break.
  const segments: Array<Array<{ x: number; y: number }>> = [];
  let run: Array<{ x: number; y: number }> = [];
  points.forEach((p, i) => {
    if (p.score == null) {
      if (run.length) segments.push(run);
      run = [];
      return;
    }
    const x = points.length === 1 ? 50 : (i / (points.length - 1)) * 100;
    run.push({ x, y: (1 - Math.min(1, Math.max(0, p.score))) * 40 });
  });
  if (run.length) segments.push(run);

  const first = measured[0]?.score ?? null;
  const last = measured[measured.length - 1]?.score ?? null;

  return (
    <Panel title={`Trust · ${range}`} data-testid="agent-trust-history">
      {error ? (
        // Unknown is not zero. A failed read drawn as a flat line at the bottom of a 0–1 axis is the
        // one thing this panel must never do.
        <div style={{ fontSize: 12.5, lineHeight: 1.6, color: "var(--text-secondary)" }}>
          Couldn&rsquo;t read this agent&rsquo;s trust history — <span className="mono">{error}</span>. Not the same
          as a flat or falling score; nothing was measured.
        </div>
      ) : loading ? (
        <div className="muted" style={{ fontSize: 12.5 }}>
          Reading trust history…
        </div>
      ) : measured.length === 0 ? (
        <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.6 }}>
          No decision in the last {range} carried a trust score for this agent, so there is no history to plot. That
          is an absence of measurements, not a low score.
        </div>
      ) : (
        <>
          <svg
            viewBox="0 0 100 40"
            preserveAspectRatio="none"
            role="img"
            aria-label={`Average trust score per bucket over the last ${range}`}
            style={{ width: "100%", height: 120, display: "block" }}
          >
            {[0, 20, 40].map((y) => (
              <line key={y} x1="0" y1={y} x2="100" y2={y} stroke="#2A2A2A" strokeWidth="0.5" vectorEffect="non-scaling-stroke" />
            ))}
            {segments.map((seg, i) =>
              seg.length === 1 ? (
                <circle key={i} cx={seg[0].x} cy={seg[0].y} r="2" fill="var(--accent)" vectorEffect="non-scaling-stroke" />
              ) : (
                <polyline
                  key={i}
                  points={seg.map((p) => `${p.x},${p.y}`).join(" ")}
                  fill="none"
                  stroke="var(--accent)"
                  strokeWidth="2"
                  vectorEffect="non-scaling-stroke"
                />
              )
            )}
          </svg>
          <div className="muted" style={{ fontSize: 11.5, display: "flex", justifyContent: "space-between" }}>
            <span>0.00</span>
            <span>1.00 · average trust per bucket</span>
          </div>
          <div style={{ fontSize: 12.5, marginTop: 8, color: "var(--text-secondary)" }} data-testid="agent-trust-trend">
            <span className="mono">{first!.toFixed(2)}</span> →{" "}
            <span
              className="mono"
              style={{ color: last! < first! ? "var(--block)" : last! > first! ? "var(--allow)" : undefined }}
            >
              {last!.toFixed(2)}
            </span>{" "}
            over {measured.length} measured bucket{measured.length === 1 ? "" : "s"}
          </div>
          {gaps > 0 && (
            <div className="muted" style={{ fontSize: 12, marginTop: 4 }} data-testid="agent-trust-gaps">
              {gaps} bucket{gaps === 1 ? "" : "s"} recorded no trust score and {gaps === 1 ? "is" : "are"} drawn as a
              break, not as zero.
            </div>
          )}
        </>
      )}
    </Panel>
  );
}

export function AgentMonitor() {
  const { namespace, timeRange } = useApp();
  const [selected, setSelected] = useState<AgentRow | null>(null);
  // A freeze/reset that fails (e.g. 403 for a non-admin viewer, network, 5xx) must NOT be
  // swallowed — surface the reason near the action buttons so the control isn't a silent dead no-op.
  const [actionError, setActionError] = useState<string | null>(null);
  // The detail renders below a potentially long table — scroll it into view on select so clicking a row
  // visibly OPENS the detail (trust history + freeze/adjust) instead of silently rendering off-screen.
  const detailRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (selected && detailRef.current?.scrollIntoView) {
      detailRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [selected?.spiffe_id]);
  const agents = useApi<AgentRow[]>(
    () => apiGet(`/api/v1/agents?namespace=${encodeURIComponent(namespace)}`),
    // Fetch on mount / namespace change only. NO auto-refetch: an admin action here is deliberate (freeze
    // stays frozen until explicitly unfrozen — it's persisted in agent_registry), so the view must be stable.
    // A background poll (a) surprised the operator by mutating the list mid-interaction, and (b) racing the
    // optimistic freeze update collapsed the list to just the mutated agent on Back. Refresh is user-driven
    // (the Refresh button below); mutations update the row optimistically without a reload.
    [namespace],
    {
      cacheKey: `agent-monitor:${namespace}`,
      staleTimeMs: 60_000
    }
  );

  // Compliance deep-link: an affected-agent-class chip opens the Agents page pre-filtered to that class (?class=).
  const [searchParams] = useSearchParams();
  const classFilter = searchParams.get("class");
  // Hidden by DEFAULT, with an escape hatch and a count — the idiom the Attack Graph already uses
  // ("N test/probe kill-chains hidden · Show"). Excluding them silently would make this page's total
  // disagree with the Overview in the other direction; including them silently is what it did before.
  const [showSynthetic, setShowSynthetic] = useState(false);
  const scoped = useMemo(() => {
    const all = agents.data ?? [];
    return classFilter ? all.filter((a) => a.agent_class === classFilter) : all;
  }, [agents.data, classFilter]);
  const syntheticCount = useMemo(() => scoped.filter((a) => a.synthetic).length, [scoped]);
  const rows = useMemo(
    () => (showSynthetic ? scoped : scoped.filter((a) => !a.synthetic)),
    [scoped, showSynthetic]
  );

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
      // Read-modify-write the FULL fleet (agents.data), not `rows` — which is a strict subset
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
      // setData only updates React state — the module cache (60s TTL) still holds the pre-freeze
      // score, so an unmount/remount within the window served the stale list (freeze looked reverted). Bust it.
      invalidateApiCache("agent-monitor:");
      if (selected?.spiffe_id === id) {
        setSelected({ ...selected, score, category: score === 0 ? "frozen" : trustCategory(score) });
      }
    } catch (e) {
      // Surface the failure instead of swallowing it (backend requires admin — apiSend throws on
      // a 403 !ok — plus network/5xx). Without this the Freeze/Reset buttons look like dead controls.
      setActionError((e as Error).message || "Trust update failed");
    }
  };

  // Real per-agent insights from audit_log, fetched when an agent is selected. Honor the header's
  // time range so the insights match the range the user picked.
  const trustHistoryApi = useApi(
    () => (selected ? fetchAgentTrustHistory(selected.spiffe_id, namespace, timeRange) : Promise.resolve([])),
    [selected?.spiffe_id, namespace, timeRange]
  );
  const toolUsageApi = useApi(
    () => (selected ? fetchAgentToolUsage(selected.spiffe_id, namespace, timeRange) : Promise.resolve([])),
    [selected?.spiffe_id, namespace, timeRange]
  );

  // DECISION COUNTS, and nothing else. `/agents/{id}/trust-history` returns `allow` and `block` per
  // bucket alongside the bucket's average `trust_score`; this maps the two counts, which is what the
  // shared VolumeChart plots. The panel used to be titled "Trust History" with these two series
  // relabelled ["Trust", "Risk"] — so an agent that merely got BUSIER showed its "Trust" line climbing
  // 40 → 120 on the day its real average trust fell 0.90 → 0.42, contradicting the "Current trust"
  // row in the panel beside it. The trust score is plotted for real below.
  const decisionVolume = useMemo(
    () => (trustHistoryApi.data ?? []).map((p) => ({ time: p.time, allow: p.allow, block: p.block })),
    [trustHistoryApi.data]
  );

  // The series the old panel title promised. `trust_score` is null for a bucket in which no decision
  // carried one, which is NOT a trust of zero — it is a gap, and it is drawn as one.
  const trustSeries = useMemo(
    () => (trustHistoryApi.data ?? []).map((p) => ({ time: p.time, score: p.trust_score })),
    [trustHistoryApi.data]
  );

  // Tool-call counts, shown as a share of the BUSIEST TOOL (busiest = 100%) because the shared bar
  // chart hardcodes a 0–100 x-axis and a "{c}%" value label. That normalisation is fine; captioning it
  // "bar length = call volume" was not — read_file on 10 calls and send_email on 5 were labelled
  // "100%" and "50%", percentages that sum to 150, with the real counts nowhere on screen to
  // contradict the reading that read_file is all of this agent's traffic (it is 67%). The caption now
  // says what the bar length measures, and the raw counts are printed beneath the chart.
  //
  // THE CATEGORY IS THE BARE TOOL NAME, and nothing else. `r.tool` is whatever an MCP server called
  // its tool — an attacker-controlled string — so folding a product-authored measurement into the same
  // text node (`${r.tool} · ${r.count} calls`) lets a server named `read_file · 4000 calls` publish a
  // count this console never computed, rendered in the console's own voice on the console's own axis.
  // ECharts draws the category as ONE right-aligned label and repeats it verbatim in the tooltip, so
  // there is no delimiter between the two halves. The counts go in `toolCounts` below instead, where
  // the name sits in its own element and the number is unambiguously ours.
  //
  // Colour each bar by the tool's RISK tier, not by usage volume — so a heavy destructive tool stands
  // out red instead of looking identical to a heavy benign search. `?? "medium"` mirrors the server's
  // own default (`TOOL_RISK_MAP.get(name, RiskLevel.MEDIUM)`), so it is not a client-side guess.
  const toolUsage = useMemo(() => {
    const rows = toolUsageApi.data ?? [];
    const max = Math.max(1, ...rows.map((r) => r.count));
    return rows.map((r) => ({
      category: r.tool,
      score: Math.round((r.count / max) * 100),
      color: RISK_TIER_COLORS[r.risk ?? "medium"]
    }));
  }, [toolUsageApi.data]);

  /** The raw counts the normalised bars cannot carry, each name in its own element. */
  const toolCounts = useMemo(
    () => (toolUsageApi.data ?? []).map((r) => ({ tool: r.tool, count: r.count })),
    [toolUsageApi.data]
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
      // Humanize the ISO last-observation timestamp.
      render: (v) => <span className="mono muted">{v ? timeAgo(String(v)) : "—"}</span>
    }
  ];

  return (
    <div className="page-enter">
      <PageHead
        title="Agent Monitor"
        subtitle={`Showing: ${namespace}`}
        actions={
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            {/* The escape hatch. Hidden BY DEFAULT so this page's identity count reconciles with the
                Overview donut, which has always filtered probes — but never silently, because a
                probe you cannot see is a probe you cannot investigate. */}
            {syntheticCount > 0 && (
              <button
                type="button"
                className="linklike"
                style={{ fontSize: 12 }}
                data-testid="agents-synthetic-toggle"
                onClick={() => setShowSynthetic((v) => !v)}
              >
                {showSynthetic
                  ? `Hide ${syntheticCount} synthetic/probe`
                  : `${syntheticCount} synthetic/probe hidden · Show`}
              </button>
            )}
            {/* Refresh is user-driven now (no background poll) — pull the latest trust/violation state on demand. */}
            <KitButton variant="ghost" icon={RefreshCw} onClick={() => void agents.refetch()} disabled={agents.loading}>
              Refresh
            </KitButton>
          </div>
        }
      />
      <div className="stack">
        <div className="grid-kit g3">
          <div style={{ gridColumn: "span 1" }}>
            <DonutChart data={trust} title="Trust Distribution" />
          </div>
          <div
            className="grid-kit g2"
            style={{ gridColumn: "span 2", gridTemplateColumns: "1fr 1fr", alignContent: "start" }}
          >
            <StatTile
              label="Agents Tracked"
              value={rows.length}
              color="var(--accent)"
              sub={
                syntheticCount > 0
                  ? showSynthetic
                    ? `includes ${syntheticCount} synthetic/probe`
                    : `${syntheticCount} synthetic/probe hidden`
                  : undefined
              }
            />
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
            {/* Both halves of ONE request. If it faulted, neither half may draw. */}
            {trustHistoryApi.error ? (
              <UnreadableChart
                title={`Decision volume · ${timeRange}`}
                what="this agent’s decision volume"
                error={trustHistoryApi.error}
                testId="agent-decision-volume-error"
              />
            ) : (
              <VolumeChart
                data={decisionVolume}
                title={`Decision volume · ${timeRange}`}
                labels={["Allowed", "Blocked"]}
              />
            )}
            <TrustHistory
              points={trustSeries}
              range={timeRange}
              loading={trustHistoryApi.loading}
              error={trustHistoryApi.error}
            />
            {toolUsageApi.error ? (
              <UnreadableChart
                title="Tool Usage"
                what="this agent’s tool usage"
                error={toolUsageApi.error}
                testId="agent-tool-usage-error"
              />
            ) : (
              <Panel
                title="Tool Usage"
                sub="bar length = share of the busiest tool · colour = tool risk tier"
                data-testid="agent-tool-usage"
              >
                {toolCounts.length === 0 ? (
                  <div className="muted" style={{ fontSize: 12.5, lineHeight: 1.6 }}>
                    {toolUsageApi.loading
                      ? "Reading tool usage…"
                      : `No tool call by this agent was recorded in the last ${timeRange}.`}
                  </div>
                ) : (
                  <>
                    {/* `bare` so the counts below live inside the SAME panel as the bars they
                        annotate — a reader should not have to associate two cards. */}
                    <CategoryBars data={toolUsage} bare />
                    <div
                      data-testid="agent-tool-call-counts"
                      style={{ display: "flex", flexWrap: "wrap", gap: "4px 14px", marginTop: 8, fontSize: 12 }}
                    >
                      {toolCounts.map((r) => (
                        <span key={r.tool} style={{ display: "inline-flex", alignItems: "baseline", gap: 5 }}>
                          <span className="mono" style={{ color: "var(--text-secondary)" }}>
                            {r.tool}
                          </span>
                          <span style={{ color: "var(--text-muted)" }}>
                            {r.count} call{r.count === 1 ? "" : "s"}
                          </span>
                        </span>
                      ))}
                    </div>
                  </>
                )}
              </Panel>
            )}
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
                // Failed freeze/reset feedback — the control surfaces 403/network/5xx errors near the buttons.
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
