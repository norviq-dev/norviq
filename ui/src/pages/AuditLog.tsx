// Audit Log — the live decision ledger: every allow/block/escalate/audit decision with its agent, tool,
// rule, trust score and captured params. Backed by a paged fetch plus a WebSocket tail for new records,
// with client-side filtering and a row-detail drawer.

import { X } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { fetchAuditRecords, wsUrl as buildWsUrl } from "../api/client";
import { DataTable, type Column } from "../components/common/DataTable";
import { DecisionBadge } from "../components/common/DecisionBadge";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { TrustBadge, trustCategory } from "../components/common/TrustBadge";
import { useApi } from "../hooks/useApi";
import { useWebSocket } from "../hooks/useWebSocket";
import { fmtDateTime, fmtTime } from "../lib/format";
import { TIME_RANGES, useApp, type TimeRange } from "../store/AppContext";
import { getToken } from "../auth/session";

type AuditRecord = {
  id?: string;
  timestamp: string;
  tool_name: string;
  decision: "allow" | "block" | "escalate" | "audit";
  rule_id?: string;
  agent_id?: string;
  agent_class?: string;
  namespace?: string;
  reason?: string;
  session_id?: string;
  trust_score?: number;
  latency_ms?: number;
  tool_params?: Record<string, unknown> | null; // request args captured with the decision (may be absent)
  framework?: string; // decision source (sidecar / sidecar-http / sdk / redteam / mcp / ...)
  // Server's verdict on the real-traffic-only exclusion (red-team framework OR synthetic/probe class).
  // Computed API-side by the one shared classifier so the live tail applies exactly the predicate
  // `exclude_synthetic` applies to fetched rows, without forking the class-prefix list into TypeScript.
  non_real?: boolean;
  // MCP provenance, present only on decisions that arrived over the Model Context Protocol. With
  // several MCP integrations wired to one agent, "which server served this tool?" is the first thing
  // an operator needs, and the tool name alone does not answer it.
  //
  // Orthogonal to `non_real` above, and both are needed: `non_real` answers "should this row count
  // as real traffic", `mcp` answers "where did it come from". An MCP decision is real traffic.
  mcp?: {
    server?: string;
    transport?: string;
    surface?: string;
    pin_status?: string;
    scan_severity?: string;
    tool_digest?: string;
  } | null;
  _live?: boolean;
};

// E2(b): parse namespace + agent_class out of a SPIFFE id (spiffe://norviq/ns/<ns>/sa/<class>).
// Defensive — returns {} when the id is absent or not in the expected shape.
function parseSpiffe(spiffe?: string): { ns?: string; agentClass?: string } {
  if (!spiffe) return {};
  const ns = spiffe.match(/\/ns\/([^/]+)/)?.[1];
  const agentClass = spiffe.match(/\/sa\/([^/]+)/)?.[1];
  return { ns, agentClass };
}

// E2(b): small labeled key/value row used throughout the structured event-detail panel.
function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div style={{ display: "flex", gap: 12, alignItems: "baseline", padding: "3px 0" }}>
      <span
        style={{ flex: "0 0 116px", fontSize: 12, color: "var(--text-secondary)", textTransform: "uppercase", letterSpacing: 0.4 }}
      >
        {label}
      </span>
      <span style={{ flex: 1, fontSize: 13, minWidth: 0, wordBreak: "break-word" }}>{children}</span>
    </div>
  );
}

const DEC = ["all", "allow", "block", "escalate", "audit"] as const;
type DecisionFilter = (typeof DEC)[number];

/**
 * `fetchAuditRecords`' filter bag, WITH `framework`.
 *
 * `GET /audit/records` has accepted `framework` since the Source column shipped
 * (norviq/api/routers/audit.py — `AuditLogEntry.framework == framework`, exact match). The filter
 * type in `api/client.ts` never declared it, so the red-team evidence deep-link
 * `/audit?rule=<id>&framework=redteam` lost the half that scopes it to red-team traffic — and since
 * `exclude_synthetic` defaults ON and the server's exclusion IS `framework == "redteam"`, the rows
 * the link exists to show were the only rows guaranteed to be hidden.
 *
 * `fetchAuditRecords` serialises whatever keys it is handed, so widening the type here puts the param
 * back on the wire. `client.ts` is owned by another surface and should adopt `framework?: string`
 * into its own filter type; this alias is the seam until it does, not a second definition of it.
 */
type AuditFilters = Parameters<typeof fetchAuditRecords>[0] & { framework?: string };

/** One active filter, printed where the operator can see it and clear it. */
function FilterChip({ label, value, onClear }: { label: string; value: string; onClear: () => void }) {
  return (
    <span
      data-testid={`audit-chip-${label}`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "3px 6px 3px 9px",
        borderRadius: 999,
        border: "1px solid var(--border)",
        background: "var(--bg-elevated)",
        fontSize: 12
      }}
    >
      <span className="muted">{label}</span>
      <span className="mono">{value}</span>
      <button
        type="button"
        className="linklike"
        aria-label={`Clear ${label} filter`}
        data-testid={`audit-chip-clear-${label}`}
        onClick={onClear}
        style={{ display: "inline-flex", alignItems: "center", color: "var(--text-muted)" }}
      >
        <X size={12} />
      </button>
    </span>
  );
}

export function AuditLog() {
  const { selectedNamespace, timeRange, setNamespace, setTimeRange } = useApp();
  const [searchParams] = useSearchParams();

  // ADOPT THE DEEP-LINK'S WINDOW. Compliance builds evidence links as
  // `/audit?rule=<rule_id>&range=<range>`, and `range` was being sent and never read: `timeRange`
  // lives in AppContext as `useState("24h")` with no URL seeding and only two writers (the provider
  // and the header's own click handler), so the param was dropped in transit.
  //
  // For an EVIDENCE link that is a correctness bug, not a convenience one. The operator follows a
  // link from a count computed over 7d, lands on the last 24h, and the rows genuinely do not add up
  // to the number they came from — with nothing on screen saying the window changed.
  //
  // Adopted HERE rather than in AppContext because /threats/graph owns a `?range=` of its own
  // (AttackGraph hydrates a LOCAL range from it); a provider-level adopt-and-strip would fight it.
  // Mount-time is sufficient and correct: arriving from Compliance is a route change, so this
  // component mounts. Validated against the real union — a hand-edited value falls back rather than
  // reaching the API as a range it rejects.
  const linkedRange = searchParams.get("range");
  useEffect(() => {
    if (!linkedRange) return;
    if (!(TIME_RANGES as readonly string[]).includes(linkedRange)) return;
    if (linkedRange === timeRange) return;
    setTimeRange(linkedRange as TimeRange);
    // Deliberately mount-only on the linked value: re-running when the operator later changes the
    // range from the header would drag them back to the link's window on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [linkedRange]);
  const initialDecision = (searchParams.get("decision") as DecisionFilter | null) ?? "all";
  const [decision, setDecision] = useState<DecisionFilter>(DEC.includes(initialDecision) ? initialDecision : "all");
  const [tool, setTool] = useState(searchParams.get("tool_name") ?? "");
  // Debounce the tool-name filter — the input stays responsive but only ONE request fires after typing
  // settles. The filter is already server-side over the selected range.
  const [debouncedTool, setDebouncedTool] = useState(tool);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedTool(tool), 400);
    return () => clearTimeout(t);
  }, [tool]);
  // Seed from the deep-link's `agent` (or legacy `spiffe_id`) param so the SPIFFE filter is pre-applied.
  const [agentFilter, setAgentFilter] = useState(searchParams.get("agent") ?? searchParams.get("spiffe_id") ?? "");
  // The SPIFFE filter is SERVER-SIDE over the whole range, so it never misses matches off-page.
  // Debounced like the tool filter.
  const [debouncedAgent, setDebouncedAgent] = useState(agentFilter);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedAgent(agentFilter), 400);
    return () => clearTimeout(t);
  }, [agentFilter]);
  const [live, setLive] = useState(true);
  const [selected, setSelected] = useState<AuditRecord | null>(null);
  const [page, setPage] = useState(0);
  const pageSize = 50;
  // Compliance deep-link: an evidence row opens the Audit Log pre-filtered by the enforcing rule (?rule=<rule_id>).
  const [rule, setRule] = useState(searchParams.get("rule") ?? "");
  // Red Team deep-link: the per-attack "Audit" link is `/audit?rule=<id>&framework=redteam`, i.e. "the
  // rows this attack wrote". Read it, and send it to the server, which filters on it.
  const [framework, setFramework] = useState(searchParams.get("framework") ?? "");
  // Real-traffic-only (default ON) hides red-team + synthetic/probe rows so this log's population matches the
  // Overview headline (which counts real traffic only). Toggle OFF to see the full ledger incl. test/eval rows.
  //
  // OFF when the link that opened this page asked for red-team rows. The server's real-traffic
  // exclusion is literally `framework == "redteam"` (norviq/api/synthetic.py), so leaving it on makes
  // `framework=redteam` self-cancelling: the operator lands on "No matching records" and concludes
  // the attack left no audit trail, or — worse, when unrelated production traffic shares the rule_id —
  // reads that production row as the red-team evidence they followed the link for.
  const [realOnly, setRealOnly] = useState(() => searchParams.get("framework") !== "redteam");

  // The /audit route stays MOUNTED across query-string changes (React Router doesn't remount it),
  // so a SECOND deep-link fired while already on the page — e.g. the Header Inbox's
  // navigate("/audit?decision=block") from the audit page itself — never applied (filters were seeded once
  // via useState at mount). Re-apply each filter when ITS url param actually changes, so a genuine new
  // deep-link takes effect WITHOUT clobbering the user's manual filter edits (those never touch the URL).
  const lastParamsRef = useRef<Record<string, string | null>>({ init: null });
  useEffect(() => {
    const cur = {
      decision: searchParams.get("decision"),
      tool_name: searchParams.get("tool_name"),
      agent: searchParams.get("agent") ?? searchParams.get("spiffe_id"),
      rule: searchParams.get("rule"),
      framework: searchParams.get("framework"),
      namespace: searchParams.get("namespace")
    };
    const prev = lastParamsRef.current;
    const firstRun = "init" in prev; // mount: seeds already applied via useState — only adopt namespace
    if (!firstRun && cur.decision !== prev.decision && cur.decision)
      setDecision(DEC.includes(cur.decision as DecisionFilter) ? (cur.decision as DecisionFilter) : "all");
    if (!firstRun && cur.tool_name !== prev.tool_name && cur.tool_name != null) setTool(cur.tool_name);
    if (!firstRun && cur.agent !== prev.agent && cur.agent != null) setAgentFilter(cur.agent);
    if (!firstRun && cur.rule !== prev.rule && cur.rule != null) setRule(cur.rule);
    if (!firstRun && cur.framework !== prev.framework && cur.framework != null) {
      setFramework(cur.framework);
      // Same reasoning as the mount-time seed: a second red-team deep-link fired while already on
      // /audit must not be cancelled by a filter the operator never saw applied.
      if (cur.framework === "redteam") setRealOnly(false);
    }
    // Namespace deep-link (Asset Graph inspector) applies on mount too — switch the global scope to the agent's ns.
    if (cur.namespace && cur.namespace !== prev.namespace) setNamespace(cur.namespace);
    lastParamsRef.current = cur;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  // Every active filter, in one place, so the page query and the count probe can never disagree about
  // the population they describe — a count computed over a different filter set than the rows beneath
  // it is the "Showing 6 of 0" class of defect.
  const activeFilters: AuditFilters = {
    range: timeRange,
    namespace: selectedNamespace,
    decision: decision === "all" ? undefined : decision,
    tool_name: debouncedTool || undefined,
    agent: debouncedAgent || undefined,
    rule_id: rule || undefined,
    framework: framework || undefined,
    exclude_synthetic: realOnly || undefined
  };
  const pageFilters: AuditFilters = { ...activeFilters, limit: pageSize, offset: page * pageSize };
  const countFilters: AuditFilters = { ...activeFilters, limit: 500, offset: 0 };

  const base = useApi<AuditRecord[]>(
    () => fetchAuditRecords(pageFilters),
    [timeRange, selectedNamespace, decision, debouncedTool, debouncedAgent, rule, framework, realOnly, page]
  );
  const totalRecords = useApi<AuditRecord[]>(
    () => fetchAuditRecords(countFilters),
    [timeRange, selectedNamespace, decision, debouncedTool, debouncedAgent, rule, framework, realOnly]
  );

  // The /ws/audit socket authenticates before accepting. Browsers can't set Authorization headers on a
  // WebSocket handshake, so the bearer token rides in the Sec-WebSocket-Protocol header as
  // ["nrvq-audit-jwt", token] — NOT a `?token=` query string, which would leak the credential into
  // access logs / browser history / Referer. The server reads it from the subprotocol (main.py).
  const wsToken = getToken() ?? "";
  const wsUrl = buildWsUrl(`/ws/audit?namespace=${encodeURIComponent(selectedNamespace)}`);
  const wsProtocols = useMemo(
    () => (wsToken ? ["nrvq-audit-jwt", wsToken] : undefined),
    [wsToken]
  );
  const ws = useWebSocket<AuditRecord>(wsUrl, live, wsProtocols);

  // Fallback: when the socket isn't connected but Live is on, poll recent records on an
  // interval and merge them in (deduped by id) so the Live feed still updates.
  const [polled, setPolled] = useState<AuditRecord[]>([]);
  useEffect(() => {
    if (live && ws.connected) return; // socket is streaming; no need to poll
    if (!live) {
      setPolled([]);
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const pollFilters: AuditFilters = {
          range: timeRange,
          namespace: selectedNamespace,
          decision: decision === "all" ? undefined : decision,
          tool_name: debouncedTool || undefined,
          framework: framework || undefined,
          exclude_synthetic: realOnly || undefined,
          limit: 10,
          offset: 0
        };
        const recent = await fetchAuditRecords(pollFilters);
        if (cancelled) return;
        setPolled((prev) => {
          const seen = new Set(prev.map((r) => r.id));
          const fresh = recent.filter((r) => r.id && !seen.has(r.id));
          return fresh.length ? [...fresh, ...prev].slice(0, 50) : prev;
        });
      } catch {
        // ignore poll errors
      }
    };
    poll();
    const interval = setInterval(poll, 5000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [live, ws.connected, timeRange, selectedNamespace, decision, debouncedTool, framework, realOnly]);

  const streamed = useMemo(() => {
    const merged = [...ws.messages, ...polled];
    const seen = new Set<string>();
    const out: AuditRecord[] = [];
    for (const m of merged) {
      const id = m.id ?? `${m.timestamp}-${m.tool_name}`;
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({ ...m, _live: true });
    }
    return out.slice(0, 6);
  }, [ws.messages, polled]);

  const rows = useMemo(() => {
    // The live tail must satisfy EVERY active filter, not just real-only.
    //
    // It used to mirror `realOnly` alone, so the filters applied server-side to `base.data` (decision,
    // tool, agent, rule) were simply absent from the streamed rows prepended above it. Selecting "Block"
    // on a namespace whose recent traffic is all allows produced six ALLOW rows under a header reading
    // "Showing 6 of 0 records" — 6 live rows over a server count of 0. In an audit tool that is not a
    // cosmetic slip: someone filtering to Block during an incident sees rows and reasonably reads them as
    // blocks. Always exactly six, because `streamed` is capped at slice(0, 6).
    const liveIds = new Set(streamed.map((r) => r.id).filter(Boolean));
    const needle = debouncedTool.trim().toLowerCase();
    const agentNeedle = debouncedAgent.trim().toLowerCase();
    const ruleNeedle = rule.trim().toLowerCase();
    const live = streamed.filter((r) => {
      // Mirror the server's own predicates. The rest are the substring/equality matches audit/records
      // applies.
      //
      // `non_real` is the SERVER's verdict on the same exclusion audit/records applies with
      // exclude_synthetic (red-team framework OR a synthetic/probe agent class). This used to test
      // `r.framework === "redteam"`, but the live payload carried no `framework` field at all — so the
      // comparison was against `undefined`, never matched, and "Real traffic only" silently passed
      // red-team and probe rows straight into the tail while the fetched rows below were correctly
      // filtered. Reading the server's boolean also avoids forking the synthetic class-name list into TS.
      if (realOnly && r.non_real) return false;
      if (decision !== "all" && r.decision !== decision) return false;
      if (needle && !(r.tool_name ?? "").toLowerCase().includes(needle)) return false;
      if (agentNeedle && !(r.agent_id ?? "").toLowerCase().includes(agentNeedle)) return false;
      if (ruleNeedle && !(r.rule_id ?? "").toLowerCase().includes(ruleNeedle)) return false;
      // The server matches `framework` on EXACT equality, so the tail must too — a substring match
      // here would let `sidecar-http` through a `sidecar` filter and put a row in the tail that the
      // page below it cannot contain.
      if (framework && r.framework !== framework) return false;
      return true;
    });
    return [...(page === 0 ? live : []), ...(base.data ?? []).filter((r) => !liveIds.has(r.id))];
  }, [streamed, base.data, page, realOnly, decision, debouncedTool, debouncedAgent, rule, framework]);

  const totalCount = totalRecords.data?.length ?? 0;
  // The total-count probe is server-capped at limit=500 (audit/records enforces le=500), so records
  // past offset 500 aren't visible to it — without a fallback totalPages maxes at 10 and Next is disabled at page 10 even
  // though the server offset has no upper bound. When the probe comes back full there are likely more rows
  // than it can see, so fall back to "there IS a next page iff the current page returned a full pageSize"
  // and keep the page/record totals honest (show a trailing "+") once we're past what the probe can count.
  const countCapped = totalCount >= 500;
  const pageFull = (base.data?.length ?? 0) === pageSize;
  const knownPages = Math.max(1, Math.ceil(totalCount / pageSize));
  const totalPages = Math.max(knownPages, page + 1);
  const canNext = page < knownPages - 1 || (countCapped && pageFull);
  const loading = base.loading || totalRecords.loading;
  // `rule` and `framework` count. They arrive only by deep-link and have no input of their own, so an
  // empty result under one of them used to render the flat "No matching records in the last 24h." —
  // a full stop, with the very filter responsible for the emptiness omitted from the hint AND printed
  // nowhere on the page. That is the reading an operator takes as "the attack left no audit trail".
  const hasFilter = Boolean(debouncedTool || debouncedAgent || rule || framework || decision !== "all");
  const noResults = !loading && rows.length === 0;
  // The one combination that is guaranteed to return nothing: the server's real-traffic exclusion IS
  // `framework == "redteam"`, so the two filters cancel. Reachable by toggling Real-traffic-only back
  // on after arriving from a red-team link.
  const selfCancelling = framework === "redteam" && realOnly;

  useEffect(() => {
    setPage(0);
  }, [timeRange, selectedNamespace, decision, debouncedTool, debouncedAgent, rule, framework, realOnly]);

  const columns: Array<Column<AuditRecord>> = [
    {
      key: "timestamp",
      title: "Time",
      render: (_v, r) => (
        <span className="mono muted">
          {fmtTime(r.timestamp)}
          {r._live && <span style={{ color: "#00e5a0", marginLeft: 6 }}>●</span>}
        </span>
      )
    },
    { key: "tool_name", title: "Tool" },
    { key: "decision", title: "Decision", render: (v) => <DecisionBadge decision={v as AuditRecord["decision"]} /> },
    { key: "rule_id", title: "Rule", render: (v) => {
      const rid = (v as string) || "";
      // TGT-POSTURE-01: a Monitor-mode softened row (monitor_would_block:<orig>) reads clearly as observe-mode.
      if (rid.startsWith("monitor_would_block:")) {
        return <span className="mono muted" title={rid}>Would-block (monitor) · {rid.slice("monitor_would_block:".length)}</span>;
      }
      return <span className="mono muted">{rid || "—"}</span>;
    } },
    { key: "agent_class", title: "Agent Class" },
    // Decision source so sidecar-enforced calls are distinguishable from API/console-originated ones.
    { key: "framework", title: "Source", render: (v) => <span className="mono muted">{(v as string) || "—"}</span> },
    {
      key: "trust_score",
      title: "Trust",
      render: (v) => <TrustBadge category={trustCategory(Number(v) || 0)} />
    },
    { key: "latency_ms", title: "Latency", render: (v) => <span className="mono">{v as number}ms</span> }
  ];

  return (
    <div className="page-enter">
      <PageHead
        title="Audit Log"
        subtitle={`Showing: ${selectedNamespace}`}
        actions={
          <KitButton variant={live ? "secondary" : "outline"} onClick={() => setLive((v) => !v)}>
            <span className={live ? "live-on" : "muted"}>{live ? "● Live" : "○ Paused"}</span>
          </KitButton>
        }
      />
      <div className="stack">
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <div className="tabs-kit">
            {DEC.map((d) => (
              <button
                key={d}
                className={`tab-kit${decision === d ? " active" : ""}`}
                onClick={() => setDecision(d)}
              >
                {d === "all" ? "All" : d[0].toUpperCase() + d.slice(1)}
              </button>
            ))}
          </div>
          <input
            className="input"
            style={{ maxWidth: 180 }}
            placeholder="Tool name"
            value={tool}
            onChange={(e) => setTool(e.target.value)}
          />
          <input
            className="input"
            style={{ maxWidth: 200 }}
            placeholder="Agent SPIFFE contains…"
            value={agentFilter}
            onChange={(e) => setAgentFilter(e.target.value)}
          />
          <button
            className={`tab-kit${realOnly ? " active" : ""}`}
            onClick={() => setRealOnly((v) => !v)}
            title="Real traffic only hides red-team + synthetic/probe rows so this log matches the Overview totals. Toggle off to see the full ledger."
            style={{ marginLeft: "auto" }}
          >
            {realOnly ? "✓ Real traffic only" : "Showing all (incl. test)"}
          </button>
        </div>

        {/* Deep-linked filters, printed and clearable. `rule` and `framework` have no control of their
            own — they arrive in the query string — so without this the operator cannot see that a
            filter is narrowing the ledger, let alone remove it. */}
        {(rule || framework) && (
          <div
            data-testid="audit-active-filters"
            style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}
          >
            {rule && <FilterChip label="rule" value={rule} onClear={() => setRule("")} />}
            {framework && <FilterChip label="source" value={framework} onClear={() => setFramework("")} />}
          </div>
        )}

        {selfCancelling && (
          // Not a hint — a contradiction. These two filters have an empty intersection by definition,
          // so an empty table under them says nothing about whether the attack wrote any rows.
          <div
            role="status"
            data-testid="audit-redteam-conflict"
            style={{
              padding: "8px 12px",
              borderRadius: "var(--radius-md)",
              border: "1px solid #FFB02040",
              background: "#FFB02012",
              color: "var(--text-secondary)",
              fontSize: 12.5,
              lineHeight: 1.55
            }}
          >
            <strong style={{ color: "var(--escalate)" }}>These two filters cannot both hold.</strong> “Real
            traffic only” hides every row whose source is <span className="mono">redteam</span>, which is
            exactly what this view is filtered to. An empty table here is the filters cancelling, not an
            absence of red-team evidence — switch Real traffic only off to see it.
          </div>
        )}

        {/* Visible count + an explicit no-results state. */}
        <div className="muted" style={{ fontSize: 12, minHeight: 16 }}>
          {loading
            ? "Loading…"
            : `Showing ${rows.length} of ${totalCount}${countCapped ? "+" : ""} record${totalCount === 1 ? "" : "s"} in range (${timeRange})${
                debouncedTool ? ` · tool contains “${debouncedTool}”` : ""
              }${debouncedAgent ? ` · agent contains “${debouncedAgent}”` : ""}${
                realOnly ? " · real traffic only — red-team & synthetic/probe rows hidden (matches the Overview total)" : " · showing all rows incl. red-team & synthetic (excluded from the Overview total)"
              }`}
        </div>

        {noResults ? (
          <div
            style={{
              padding: "28px 16px", textAlign: "center", color: "var(--text-secondary)", fontSize: 13,
              border: "1px solid var(--border, #2a2a2a)", borderRadius: "var(--radius-md)"
            }}
          >
            No matching records in the last {timeRange}
            {hasFilter ? " for these filters." : "."}
            {hasFilter && " Try a broader time range, or clear the filters above — including any rule/source chip a link applied."}
          </div>
        ) : (
          <DataTable
            columns={columns}
            rows={rows}
            rowKey="id"
            selectedKey={selected?.id ?? null}
            onRowClick={(r) => setSelected(r)}
            placeholder="Quick filter rows…"
          />
        )}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
          <KitButton
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
          >
            ← Prev
          </KitButton>
          <span className="muted" style={{ fontSize: 12 }}>
            Page {page + 1} of {totalPages}
            {canNext && page + 1 >= totalPages ? "+" : ""}
          </span>
          <KitButton
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => p + 1)}
            disabled={!canNext}
          >
            Next →
          </KitButton>
        </div>

        {selected && (
          <Panel
            title="Event Detail"
            sub={selected.id}
            action={
              <KitButton variant="ghost" size="sm" icon={X} onClick={() => setSelected(null)}>
                Close
              </KitButton>
            }
          >
            {(() => {
              const spf = parseSpiffe(selected.agent_id);
              // Prefer the parsed SPIFFE namespace; fall back to the flat record field.
              const ns = spf.ns ?? selected.namespace;
              // The record's agent_class is AUTHORITATIVE for the class — it is what the table
              // column and every filter use. The SPIFFE SA segment is the service-account identity and can
              // differ from the class (e.g. sa/etl-loader running as class report-gen), so parsing it here
              // made the detail panel disagree with its own table row. Use the record field first; the full
              // SPIFFE (incl. the SA) is still shown verbatim in the "Agent (SPIFFE)" row above.
              const agentClass = selected.agent_class ?? spf.agentClass;
              // E2(b) Wave-2: distinguish an ENGINE fault from a real policy block. rule_id
              // "evaluator_error" is emitted by the fail-closed path when the evaluator itself
              // errored — it is NOT a policy decision and must be triaged differently.
              const isEngineError = selected.rule_id === "evaluator_error";
              const hasParams = selected.tool_params != null && Object.keys(selected.tool_params).length > 0;
              return (
                <div className="stack" style={{ gap: 16 }}>
                  {isEngineError && (
                    <div
                      style={{
                        display: "flex",
                        gap: 8,
                        alignItems: "center",
                        padding: "8px 12px",
                        borderRadius: "var(--radius-md)",
                        border: "1px solid #FFB02040",
                        background: "#FFB02012",
                        color: "#FFB020",
                        fontSize: 13
                      }}
                    >
                      <span style={{ fontWeight: 600 }}>⚠ Engine fault (fail-closed)</span>
                      <span style={{ color: "var(--text-secondary)" }}>— not a policy decision</span>
                    </div>
                  )}

                  {/* Decision */}
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <DecisionBadge decision={selected.decision} />
                      {selected.rule_id && (
                        <span
                          className="mono"
                          title="Matched rule id"
                          style={{
                            fontSize: 11,
                            padding: "2px 8px",
                            borderRadius: 6,
                            border: "1px solid var(--border)",
                            color: isEngineError ? "#FFB020" : "var(--text-secondary)"
                          }}
                        >
                          {selected.rule_id}
                        </span>
                      )}
                    </div>
                    {selected.reason && (
                      <div style={{ marginTop: 6, fontSize: 13, color: "var(--text-secondary)" }}>{selected.reason}</div>
                    )}
                  </div>

                  {/* Tool call */}
                  <div>
                    <DetailRow label="Tool">
                      <span className="mono">{selected.tool_name || "—"}</span>
                    </DetailRow>
                    {selected.mcp?.server && (
                      <>
                        <DetailRow label="MCP server">
                          <span className="mono">{selected.mcp.server}</span>
                          {selected.mcp.transport && (
                            <span className="muted" style={{ marginLeft: 8 }}>via {selected.mcp.transport}</span>
                          )}
                        </DetailRow>
                        <DetailRow label="Definition">
                          <span className="mono">{selected.mcp.pin_status ?? "unknown"}</span>
                          {selected.mcp.scan_severity && selected.mcp.scan_severity !== "none" && (
                            <span style={{ marginLeft: 8, color: "#FFB020" }}>
                              scanner: {selected.mcp.scan_severity}
                            </span>
                          )}
                        </DetailRow>
                      </>
                    )}
                    <DetailRow label="Params">
                      {hasParams ? (
                        <pre className="json" style={{ margin: 0, fontSize: 12 }}>
                          {JSON.stringify(selected.tool_params, null, 2)}
                        </pre>
                      ) : selected.tool_params != null ? (
                        // Present and empty. A POSITIVE observation: the record carries an arguments
                        // object and it holds nothing.
                        <span className="muted" data-testid="audit-params-empty">
                          Captured — the call carried no arguments.
                        </span>
                      ) : (
                        // Absent. `/audit/records` does not serialise arguments at all: `_to_dict`
                        // emits no `tool_params` key, so this row could never populate, and a bare
                        // em-dash between a real Tool row above and a real Trust row below reads as
                        // "captured, and there were none". They are opposite facts. Masked values may
                        // well be in the database — `audit_capture_masked_params` writes them to
                        // `payload.masked_params` — this console just never asks for them.
                        <span className="muted" data-testid="audit-params-uncaptured">
                          Not captured by this view — the records endpoint does not return call arguments. Not
                          evidence the call carried none.
                        </span>
                      )}
                    </DetailRow>
                  </div>

                  {/* Identity / SPIFFE */}
                  <div>
                    <DetailRow label="Agent (SPIFFE)">
                      <span className="mono" style={{ wordBreak: "break-all" }}>{selected.agent_id || "—"}</span>
                    </DetailRow>
                    <DetailRow label="Namespace">
                      <span className="mono">{ns || "—"}</span>
                    </DetailRow>
                    <DetailRow label="Agent class">
                      <span className="mono">{agentClass || "—"}</span>
                    </DetailRow>
                  </div>

                  {/* Context */}
                  <div>
                    <DetailRow label="Timestamp">
                      <span title={selected.timestamp}>{fmtDateTime(selected.timestamp)}</span>
                    </DetailRow>
                    <DetailRow label="Session">
                      <span className="mono">{selected.session_id || "—"}</span>
                    </DetailRow>
                    <DetailRow label="Trust score">
                      {selected.trust_score != null ? (
                        <TrustBadge category={trustCategory(Number(selected.trust_score) || 0)} />
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </DetailRow>
                    <DetailRow label="Latency">
                      <span className="mono">
                        {selected.latency_ms != null ? `${selected.latency_ms}ms` : "—"}
                      </span>
                    </DetailRow>
                    {selected.framework && (
                      <DetailRow label="Source">
                        <span className="mono">{selected.framework}</span>
                      </DetailRow>
                    )}
                  </div>
                </div>
              );
            })()}
          </Panel>
        )}
      </div>
    </div>
  );
}
