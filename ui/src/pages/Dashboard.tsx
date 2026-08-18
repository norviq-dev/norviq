// Dashboard — the default landing overview: KPI tiles, decision-volume + coverage charts, a trust
// gauge, top-blocked tools, and the latest red-team efficacy for the selected namespace (fleet-aware
// on multi-cluster installs).

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
  // Monitor mode softens every would-block to an `audit` decision and emits no `block`, so `blocked` is
  // structurally 0 there. These carry the number the relabelled "Would-block" tile actually means.
  would_blocked?: number;
  would_block_rate_pct?: number;
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

// MONITOR MODE: the two block feeds count ENFORCED blocks, and a monitored namespace produces no POLICY
// ones. `_apply_posture` rewrites every would-block/would-escalate to `decision="audit"` with a
// `monitor_would_block:<rule>` rule id, so `AuditLogEntry.decision == "block"` — which is exactly what
// `/audit/top-blocked` filters on and what this page asks `/audit/records` for — cannot match a policy hit.
// Printing "No blocked tool calls in the selected range" there states a fact about the namespace's TRAFFIC
// ("no rule is catching anything") beside a tile reporting hundreds of would-blocks. audit.py:222 says the
// same thing in words for the KPI tile, which was fixed; these two panels were not. One shared sentence so
// the two feeds cannot drift.
//
// It is "no POLICY block", not "nothing": `_apply_posture` returns the decision untouched for the five
// `_POSTURE_EXEMPT_RULES` (trust_frozen, policy_load_pending, evaluator_error, evaluator_invalid_payload,
// rate_limit_exceeded), which stay hard "even when a namespace is set to visibility-only". Those are real
// `decision="block"` rows in a monitored namespace and they DO reach these feeds, so the sentence must not
// tell an operator the namespace enforces nothing — least of all about the trust freeze, the kill switch
// they reach for during an incident.
//
// `confirmed` is NOT decorative. The sentence below explains a MECHANISM ("the engine rewrites every
// match"), so it may only be said when the ENGINE's own field says so — coverage.py `_namespace_mode`,
// this namespace's own persisted enforcement_mode. `monitorScope` deliberately falls back to the
// /settings posture while coverage is loading or after it fails, and that reading MERGES the
// cluster-wide default (settings_router `_effective`), so on a global-audit cluster it says "audit" for
// every namespace the engine really blocks. Rendering the mechanism sentence off that fallback turned
// "we could not read this namespace's posture" into "we read it, and nothing here is enforced" — and
// printed it next to "0 would-blocks were logged in this range", a self-contradiction, over a feed whose
// zero was in fact a real measurement. Unconfirmed gets its own sentence that says the zero is
// uninterpretable, which is the truth.
function MonitorBlockFeedEmpty({
  confirmed,
  wouldBlocked,
  onShowWouldBlocks,
  onCheckPosture,
  testid
}: {
  confirmed: boolean;
  wouldBlocked?: number;
  onShowWouldBlocks: () => void;
  onCheckPosture: () => void;
  testid: string;
}) {
  if (!confirmed) {
    return (
      <div
        data-testid={`${testid}-unconfirmed`}
        style={{ color: "var(--text-muted)", fontSize: 12.5, padding: "16px 2px", lineHeight: 1.6 }}
      >
        {/* "has not been confirmed" rather than "could not be read": this state also covers the first paint,
            before the coverage read has landed. Both are the same thing for the reader — we are not in a
            position to say what the engine does to this namespace's matched traffic. */}
        <span style={{ color: "var(--escalate)", fontWeight: 600 }}>No enforced blocks in the selected range.</span>{" "}
        Settings report Monitor for this scope, but that reading merges the cluster-wide default and this
        namespace&apos;s own engine posture has not been confirmed — so whether this zero is a measurement or a
        consequence of Monitor mode is <b>unknown</b>.
        <div>
          <button type="button" className="btn btn-ghost btn-sm" style={{ marginTop: 8 }} onClick={onCheckPosture}>
            Check this namespace&apos;s posture →
          </button>
        </div>
      </div>
    );
  }
  return (
    <div data-testid={testid} style={{ color: "var(--text-muted)", fontSize: 12.5, padding: "16px 2px", lineHeight: 1.6 }}>
      {/* NOT "nothing is blocked live", and NOT "structurally empty". Monitor softens POLICY matches only:
          `_apply_posture` returns the decision untouched when `rule_id in _POSTURE_EXEMPT_RULES`
          — trust_frozen, policy_load_pending, evaluator_error, evaluator_invalid_payload,
          rate_limit_exceeded — "an admin trust freeze is an incident-response kill switch that must outrank
          namespace posture". Those still land here as real `decision="block"` rows. Telling an operator that
          a monitored namespace enforces NOTHING is wrong about the one control they reach for during an
          incident, and it throws away the real information an empty feed carries: no freeze, no engine fault
          and no throttle fired in this range. */}
      <span style={{ color: "var(--escalate)", fontWeight: 600 }}>Monitor mode — policy matches are not blocked live.</span>{" "}
      Every policy match is rewritten to an audit row with a <span className="mono">monitor_would_block:</span> rule id,
      so <b>no policy block can appear here</b>. Only the non-policy blocks stay hard in Monitor — a trust freeze,
      an engine fault, a rate-limit throttle — and none were recorded in this range.
      {typeof wouldBlocked === "number" && (
        <> {wouldBlocked.toLocaleString()} would-block{wouldBlocked === 1 ? "" : "s"} were logged in this range.</>
      )}
      <div>
        <button type="button" className="btn btn-ghost btn-sm" style={{ marginTop: 8 }} onClick={onShowWouldBlocks}>
          Show would-blocks in the Audit Log →
        </button>
      </div>
    </div>
  );
}

function TopBlockedTools({
  data,
  monitorScope,
  monitorConfirmed,
  wouldBlocked,
  onShowWouldBlocks,
  onCheckPosture
}: {
  data: Array<{ tool: string; count: number }>;
  monitorScope: boolean;
  monitorConfirmed: boolean;
  wouldBlocked?: number;
  onShowWouldBlocks: () => void;
  onCheckPosture: () => void;
}) {
  const max = Math.max(...data.map((d) => d.count), 1);
  return (
    <Panel
      title="Top blocked tools"
      sub={monitorScope ? "Most-blocked in selected range — enforced blocks only" : "Most-blocked in selected range"}
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 13, marginTop: 4 }}>
        {data.length === 0 && (monitorScope ? (
          <MonitorBlockFeedEmpty
            testid="top-blocked-monitor-empty"
            confirmed={monitorConfirmed}
            wouldBlocked={wouldBlocked}
            onShowWouldBlocks={onShowWouldBlocks}
            onCheckPosture={onCheckPosture}
          />
        ) : (
          <div style={{ color: "var(--text-muted)", fontSize: 13, padding: "16px 0", textAlign: "center" }}>
            No blocked tool calls in the selected range
          </div>
        ))}
        {data.map((d) => (
          <div key={d.tool} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span
              className="mono"
              // The row's ONLY identifier, in a fixed 104px box that holds ~12 characters. The full
              // name has to stay reachable or two tools that share a prefix become one bar in a chart
              // whose entire job is ranking them. RedTeam.tsx does exactly this for its truncated
              // vector ids; this panel was the one place that did not.
              title={d.tool}
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
    // exclude_synthetic mirrors the "Blocked (24h)" tile above, which counts REAL traffic only. Without it
    // this panel listed red-team/synthetic rows the tile did not count, so the card could read "Blocked: 0"
    // directly above a list of blocked calls — and "See All" then landed on an Audit Log that (correctly)
    // defaults to real-traffic-only and showed nothing.
    () => fetchAuditRecords({ range: timeRange, namespace: selectedNamespace, decision: "block", exclude_synthetic: true, limit: 10 }),
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
  // SCOPE: pass the selected namespace and key the effect on it, exactly as Compliance.tsx does. Without the
  // argument this asked for the newest run in ANY namespace and — with empty deps and a namespace-free cache
  // key — never re-issued the request on a namespace switch, so the Overview attributed another namespace's
  // efficacy to the selected one and froze it there. redteam.py's own docstring states the intent: the
  // efficacy a page shows must belong to the namespace it displays, "not whatever cluster-wide run happened
  // to be newest". The cache key is Compliance's key VERBATIM so both surfaces share one entry and cannot
  // drift apart again.
  const efficacy = useApi<RedteamLatest>(() => fetchRedteamLatest(selectedNamespace), [selectedNamespace], {
    cacheKey: `compliance-redteam-latest:${selectedNamespace}`,
    staleTimeMs: 30_000
  });

  // ---- Is the coverage payload we are holding an answer about the scope this page CLAIMS to show? ------
  // `useApi` keeps the last good `data` when a later load fails (its catch only sets `error`), and it does
  // NOT clear `error` when a later load is served from cache. So neither flag alone identifies a usable
  // answer: after switching from ns-A to ns-B, a failed B read leaves A's coverage in `data` with `error`
  // set — and gating only on `data == null` (as the first pass did) re-printed A's coverage_pct, A's
  // categories and A's agent classes under B's name, as measured fact. The response echoes the scope it was
  // computed for, so compare it. Not compared under "all": there the server resolves the scope itself and a
  // SCOPED tenant's "all" legitimately comes back as its own claim namespace (`read_namespace`).
  const coverageOffScope =
    selectedNamespace !== "all" && coverage.data != null && coverage.data.namespace !== selectedNamespace;
  const coverageUsable = coverage.data != null && !coverageOffScope;

  // ---- MONITOR MODE: ONE definition, and it is the ENGINE's, not the settings page's. -----------------
  // "Monitor" on this page means a specific mechanical fact: THIS namespace's would-blocks are softened to
  // `audit` rows carrying a `monitor_would_block:` rule id. The evaluator does that ONLY when the namespace
  // has its OWN persisted enforcement_mode='audit' (`_resolve_posture`: "a null/global mode does NO
  // softening"), which is exactly what coverage.py's `namespace_mode` reports. `posture.mode` comes from
  // /settings, which merges the row with the CLUSTER-WIDE default (`_effective`: `row.enforcement_mode if
  // row ... else app_settings.enforcement_mode`) — so on a cluster deployed with global enforcement_mode
  // =audit, EVERY namespace with no settings row of its own reads "audit" there while the engine is really
  // blocking it. Keying off /settings therefore relabelled the tile "Would-block" over a counter that is
  // structurally 0 (nothing is ever softened, so no `monitor_would_block:` row exists), hid real enforced
  // blocks behind that 0, and told the operator matched rules "do NOT enforce" when they do.
  // Prefer the engine-accurate signal; fall back to the settings posture only until coverage answers.
  const namespaceMode = coverageUsable ? coverage.data?.namespace_mode : undefined;
  const monitorScope =
    selectedNamespace !== "all" && (namespaceMode ? namespaceMode === "audit" : posture.mode === "audit");
  // …and the STRONGER fact: the engine's own field actually answered, and it said Monitor. The fallback
  // above is fine for a LABEL ("Would-block (24h)") — a label the operator reads together with the
  // coverage card's own "could not be read" state. It is NOT enough for a sentence that explains what the
  // engine does to matched traffic, or for a deep link premised on `monitor_would_block:` rows existing.
  // Everything that asserts the MECHANISM keys on this instead, so an unread posture can never be
  // published as "nothing here is enforced".
  const monitorConfirmed = selectedNamespace !== "all" && namespaceMode === "audit";
  const provenPct = efficacy.data?.has_run ? efficacy.data.efficacy?.overall.proven_blocking_pct : undefined;
  // The subset SIZE, so the percentage above cannot be read as coverage of everything (F-023).
  const provenTotal = efficacy.data?.has_run ? efficacy.data.efficacy?.overall.total : undefined;
  // /redteam/results/latest is ADMIN-ONLY (redteam.py require_admin), so a non-admin operator — and any 5xx or
  // network fault — lands here with `error` set and `data` null. That is "we could not ask", which must never
  // render as the FACT "not efficacy-tested": the posture may have been fully red-teamed an hour ago.
  // NOT `&& data == null`: `{has_run:false}` carries no namespace to compare, and useApi keeps the previous
  // namespace's run in `data` when the new one's read fails — so that extra clause let a failed read for
  // ns-B republish ns-A's "92% proven-blocking" as B's. An error means we cannot attest THIS scope's
  // efficacy, whatever we are still holding. (The cost of the latch — a stale error surviving a cache-served
  // load — is a conservative "unknown"; the alternative is a confident number about the wrong namespace.)
  const efficacyUnknown = !!efficacy.error;
  // The caption is NEUTRAL (ScoreGauge renders --text-muted); only the proven-blocking % is teal --accent.
  // No block-red — that hue is reserved for real block decisions.
  const gaugeSub = efficacyUnknown ? (
    <>rules present · <span data-testid="dash-efficacy-unknown">efficacy unknown — the last Red Team run could not be read ({efficacy.error})</span></>
  ) : provenPct != null ? (
    // THE DENOMINATOR IS PART OF THE CLAIM (F-023). This read "100% proven-blocking (last run)",
    // which on first glance is total coverage — it is efficacy over the EVALUATE-REACHABLE red-team
    // subset, and the Compliance page for the same posture honestly says 80% ATLAS / 67% OWASP with
    // named gaps. A bare 100% next to that is the number an operator will quote.
    //
    // `caught`/`total` are already on the payload; showing them makes the subset visible without a
    // click, and "N/N attacks" is what stops "100%" being read as "everything".
    <>
      rules present · <b style={{ color: "var(--accent)" }}>{provenPct}% proven-blocking</b>
      {provenTotal != null ? ` of ${provenTotal} evaluate-reachable red-team attacks` : ""} (last run)
    </>
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
  // In Monitor mode the engine SOFTENS every would-block into an `audit` decision and emits no `block`
  // at all, so `blocked` is structurally 0. The tile already relabels itself "Would-block" here — but it
  // was still bound to `blocked`, so it read a confident 0 for a namespace whose policy was matching
  // constantly. Bind the relabelled tile to the number its label promises.
  const blockedToday = useHub
    ? hubTotals.block
    : (monitorScope ? stats.data?.would_blocked : stats.data?.blocked) ?? 0;
  const blockRate = useHub
    ? hubTotals.rate
    : Math.round((monitorScope ? stats.data?.would_block_rate_pct : stats.data?.block_rate_pct) ?? 0);
  // Engine (OPA-eval) faults — fail-closed, NOT policy decisions. Surfaced as a distinct signal.
  const engineErrors = stats.data?.engine_errors ?? 0;
  // First paint — no data resolved yet. Show skeletons instead of flashing 0/0/0 + a half-drawn donut.
  const kpiLoading = !useHub && stats.loading && stats.data == null;
  // Also skeleton while what we hold answers a DIFFERENT scope: `coverage.loading` lags one render behind a
  // namespace switch (the effect runs after the render that changed it), so `coverageOffScope` is what keeps
  // the previous namespace's ring — or a one-frame "could not be measured" flash — off the screen in between.
  const postureLoading =
    !useHub && !coverageUsable && (coverage.loading || coverageOffScope) && !coverage.error;
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
  // "We could not measure coverage" is NOT "we measured, and you have none". `?? 0` drew the most alarming
  // number on the console — a confident "Policy Coverage 0%" with an empty category chart — out of a fetch
  // error, byte-identical to a genuinely uncovered namespace. So: anything that is not a usable answer ABOUT
  // THIS SCOPE, and is not still loading, is unavailable. Note this is the complement of the two branches
  // above it, which is what guarantees the ring can never be drawn from an absent or off-scope payload.
  const coverageUnavailable = !useHub && !coverageUsable && !postureLoading;
  // The backend flags the agent-class section degraded when its policy OR its 30d-efficacy DB read faulted.
  // Degraded means the section's numbers are unreadable: the list may be empty because we could not look, and
  // any policy in it carries forced-zero efficacy with effective=false. Never draw that as a verdict.
  const agentClassDegraded = !!coverage.data?.agent_class_policies_degraded;
  const agentClassPolicies = coverage.data?.agent_class_policies ?? [];

  // The only reachable population in Monitor mode. `/audit/records` filters `rule_id` by EXACT match, so a
  // `monitor_would_block:` PREFIX is not a server-side filter the console can send — `decision=audit` is the
  // narrowest filter that CAN match these rows, and the Audit Log renders that rule-id prefix specially
  // (AuditLog.tsx: "a Monitor-mode softened row reads clearly as observe-mode"). Pointing "See All →" at
  // `decision=block` here sent the operator to a table that is structurally incapable of returning a row.
  const showWouldBlocks = () => navigate(`/audit?decision=audit`);
  // The unconfirmed empty state's one honest action: go and read the posture this page could not.
  const checkPosture = () => navigate(`/policies/targets`);

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

  // coverage.error belongs in this union: a load where ONLY the coverage endpoint was down showed healthy
  // KPI tiles beside a fabricated 0% ring and no "partial data" notice anywhere.
  // efficacy.error does NOT belong here, and adding it was wrong. /redteam/results/latest is admin-only
  // (redteam.py `require_admin`), so for every NON-ADMIN operator it 403s on every single load — this notice
  // would then read "API unavailable. Showing partial data." permanently, for a normally-functioning API,
  // for a whole class of users. That is both false (the API answered; the caller lacks a role) and corrosive:
  // the only generic outage signal the console has stops meaning anything if it is always on. The efficacy
  // fault is already stated precisely, with the server's own reason, in the gauge caption below.
  const apiError = useHub
    ? hubSummary.error || hubAgents.error
    : stats.error || blocked.error || records.error || agents.error || topBlocked.error || volume.error ||
      coverage.error;

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

        {/* Totals count REAL traffic only — synthetic/probe + red-team test rows are excluded so the Overview
            reconciles with Compliance & Red-Team efficacy. Note it here so "50 calls" vs a red-team-heavy Audit
            Log never reads as a contradiction; the Audit Log's "Real traffic only" filter shows the same set. */}
        {!kpiLoading && !useHub && (
          <div className="muted" style={{ fontSize: 11.5, marginTop: -8 }}>
            Counts real traffic — synthetic &amp; red-team test rows are excluded (visible in the Audit Log).
          </div>
        )}

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
          ) : coverageUnavailable ? (
            // The coverage read FAILED. The skeleton above already refuses to "flash a 0% ring" while loading;
            // the same rule has to hold once the request settles as an error — otherwise the operator reads a
            // fabricated 0% as measured fact and starts remediating a posture that may be fully covered.
            <div
              className="panel"
              data-testid="coverage-unavailable"
              style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 8, minHeight: 200, textAlign: "center", padding: "0 18px" }}
            >
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text-secondary)" }}>Policy Coverage</div>
              <div style={{ fontSize: 34, fontWeight: 700, color: "var(--text-muted)", lineHeight: 1.1 }}>—</div>
              <div style={{ fontSize: 12, color: "var(--escalate)" }}>Coverage could not be measured</div>
              {coverage.error && <div style={{ fontSize: 11.5, color: "var(--text-muted)" }}>{coverage.error}</div>}
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => void coverage.refetch()}
                style={{ marginTop: 2 }}
              >
                Retry
              </button>
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
            <TopBlockedTools
              data={topBlockedData}
              monitorScope={monitorScope}
              monitorConfirmed={monitorConfirmed}
              wouldBlocked={stats.data?.would_blocked}
              onShowWouldBlocks={showWouldBlocks}
              onCheckPosture={checkPosture}
            />
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
              coverageUnavailable ? undefined : (
              <div style={{ display: "flex", alignItems: "center", gap: 12, fontSize: 11, color: "var(--text-muted)" }}>
                {/* ONE legend over TWO sections whose backends define green differently, so it must name
                    BOTH definitions rather than pick one. Category: `effective = blocked > 0` where the
                    roll-up folds ESCALATE into `blocked` (mitre.py `_activity_by_rule` — "the ONE place the
                    product's two blocked-counts differ", named there rather than left to be discovered).
                    Agent class: `effective = blocked > 0 or would_block > 0`, so a Monitor would-block turns
                    a class green even though the call went THROUGH. Two earlier wordings were each false for
                    one half: "stopped (or would-block) traffic" (no category counts a would-block) and then
                    "counted as stopped by these rules" (an escalation is not a stop, and a would-block is the
                    opposite of one). Say what actually happened, per section. */}
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }} title="Proven — real traffic has actually fired these rules. Risk category: a block or an escalation. Agent class: a block, or a Monitor would-block (logged only — that call was NOT stopped).">
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: "#00E5A0" }} /> proven
                </span>
                <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }} title="Loaded — the rules are present, but nothing this section counts has recorded them firing yet">
                  <span style={{ width: 8, height: 8, borderRadius: 2, background: "#5f6b7a" }} /> loaded
                </span>
                {/* Concrete-namespace posture ONLY, and the ENGINE's posture (see `monitorScope`): under
                    "all" this chip asserted "matched rules … do NOT enforce" over an aggregate of namespaces
                    derived from ONE settings row — two inches under a "Blocked (24h)" tile counting real
                    enforced blocks — and on a global-audit cluster it asserted the same thing over every
                    namespace that has no settings row of its own, all of which the engine really blocks.
                    Same guard the KPI tiles on this page use; the Header carries the qualified cluster chip. */}
                {monitorScope && (
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 5, color: "var(--escalate)" }} title="Monitor mode — matched rules log a would-block but do NOT enforce. Switch to Block in Target Settings.">
                    <span style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--escalate)" }} /> monitor
                  </span>
                )}
              </div>
              )
            }
          >
            {coverageUnavailable ? (
              // An empty chart is a claim ("you have no covered categories"). Say what actually happened.
              <div data-testid="coverage-categories-unavailable" style={{ padding: "18px 0", fontSize: 12.5, color: "var(--escalate)" }}>
                Coverage could not be read for this scope — these bars are <b>unavailable, not zero</b>.
                <span style={{ color: "var(--text-muted)" }}> {coverage.error}</span>
              </div>
            ) : (
            <>
            <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 4 }}>By risk category</div>
            <Suspense fallback={barsSkeleton}>
              <CategoryBars data={categoryScores} bare />
            </Suspense>
            {/* In Monitor the engine rewrites every would-block AND every would-escalate to `audit` with a
                `monitor_would_block:<rule>` rule_id, and the category activity roll-up keys on the RAW
                rule_id and counts only block/escalate — so a category's `effective` is structurally
                unreachable here (checked: the intersection of `_POSTURE_EXEMPT_RULES` with
                policies/category_mapping.json is empty, so no category-mapped rule stays hard).
                This claim is only true when the ENGINE is actually softening, which is why `monitorScope`
                is keyed on coverage.py's `namespace_mode` and not on the /settings posture — under the
                settings posture this note printed over bars the backend had computed under Block semantics,
                telling the operator their greyness was a measurement artifact when it meant "never fired".
                Without the note the grey bars read as "these rules are dead weight" while the tile above the
                card reports would-blocks and the agent-class bars below go green off the same traffic. */}
            {monitorScope && (
              <div data-testid="category-monitor-note" style={{ marginTop: 8, fontSize: 11.5, color: "var(--text-muted)" }}>
                Monitor mode: would-blocks are logged against a <span className="mono">monitor_would_block:</span> rule id, which is not
                attributed to a risk category — so no category bar can turn <span style={{ color: "var(--accent)" }}>proven</span> here,
                however much traffic its rules match. The agent-class bars below <b>do</b> count would-blocks.
              </div>
            )}
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
                many classes as a clean list of colour-coded bars. Rendered when there is something to say:
                real policies, OR the backend's degraded flag (an infra fault must not read as "no
                agent-class policies are applied here"). */}
            {(agentClassPolicies.length > 0 || agentClassDegraded) && (
              <>
                <div style={{ height: 1, background: "var(--border)", margin: "16px 0 12px" }} />
                <div style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: 8 }}>By agent class</div>
                {agentClassDegraded ? (
                  // Degraded: the list may be empty because the policy query faulted, and any policy in it
                  // carries efficacy forced to 0 with effective=false. Drawing the bars would state a
                  // proven/unproven verdict and "0 blocked · 0 governed calls" as measured fact, so the bars
                  // are withheld and the classes we DO know about are listed without any verdict colour.
                  <div data-testid="agent-class-degraded" style={{ fontSize: 12, color: "var(--escalate)" }}>
                    Agent-class coverage could not be read — the 30-day figures for this section are{" "}
                    <b>unavailable, not zero</b>, and this list may be incomplete.
                    {agentClassPolicies.length > 0 && (
                      <div className="mono" style={{ marginTop: 6, fontSize: 11.5, color: "var(--text-secondary)" }}>
                        {agentClassPolicies.map((p) => p.cls).join(", ")}
                      </div>
                    )}
                  </div>
                ) : (
                  <Suspense fallback={barsSkeleton}>
                    <AgentClassCoverage
                      policies={agentClassPolicies}
                      namespaceMode={coverage.data?.namespace_mode}
                      bare
                    />
                  </Suspense>
                )}
              </>
            )}
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
          // In Monitor mode this feed counts something the engine never emits — say which population it is
          // over, right in the subtitle, rather than letting "Last 10 blocked tool calls" over an empty table
          // read as "nothing matched". (The rows themselves stay ENFORCED blocks: `/audit/records` cannot
          // filter on the `monitor_would_block:` rule-id prefix, so re-sourcing this feed would mean
          // client-side sampling a capped page — a sample printed as a feed. The empty state names the real
          // would-block number instead and links to the rows.)
          // A claim about the ENGINE, so it keys on `monitorConfirmed`, not on the settings-fallback
          // `monitorScope` (see the note on `monitorConfirmed`). And NOT "this namespace enforces none":
          // `_POSTURE_EXEMPT_RULES` keeps trust-freeze / engine-fault / rate-limit blocks hard in Monitor,
          // and those land in this feed.
          sub={
            monitorConfirmed
              ? "Last 10 enforced blocks — in Monitor, only non-policy ones (trust freeze, engine fault, rate limit)"
              : "Last 10 blocked tool calls"
          }
          // Addressable so a test can scope to the FEED. Searching the page for /blocked/i instead
          // matches this panel's own title, its empty state, the "Blocked (24h)" KPI label and the
          // "Top blocked tools" heading — all rendered before any fetch resolves — which is how
          // audit-pep.spec.ts's block-feed assertion became incapable of failing.
          data-testid="recent-blocked"
          style={{ paddingBottom: 6 }}
          action={
            <button
              className="btn btn-ghost btn-sm"
              // Lands on the Audit Log with decision=block. No real-only param is passed because the Audit Log
              // already DEFAULTS to real-traffic-only, and this panel now uses that same lens — so the list you
              // clicked and the page you arrive at agree. They did not before: this panel included synthetic rows
              // the destination filtered out, so a populated list drilled through to an empty table.
              // `decision=audit` is the right destination only where `monitor_would_block:` rows actually
              // exist — i.e. where the ENGINE confirmed Monitor. Sending an operator there off an unread
              // posture would swap one unmatchable filter for a table of unrelated audit decisions.
              onClick={() => (monitorConfirmed ? showWouldBlocks() : navigate(`/audit?decision=block`))}
              type="button"
            >
              See All →
            </button>
          }
        >
          <div style={{ overflowX: "auto" }}>
            {(Array.isArray(blocked.data) ? blocked.data : []).length === 0 ? (
              monitorScope ? (
                <MonitorBlockFeedEmpty
                  testid="recent-blocked-monitor-empty"
                  confirmed={monitorConfirmed}
                  wouldBlocked={stats.data?.would_blocked}
                  onShowWouldBlocks={showWouldBlocks}
                  onCheckPosture={checkPosture}
                />
              ) : (
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
              )
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
