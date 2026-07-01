import { X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
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
import { fmtTime } from "../lib/format";
import { useApp } from "../store/AppContext";

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
  _live?: boolean;
};

const DEC = ["all", "allow", "block", "escalate", "audit"] as const;
type DecisionFilter = (typeof DEC)[number];

export function AuditLog() {
  const { selectedNamespace, timeRange } = useApp();
  const [searchParams] = useSearchParams();
  const initialDecision = (searchParams.get("decision") as DecisionFilter | null) ?? "all";
  const [decision, setDecision] = useState<DecisionFilter>(DEC.includes(initialDecision) ? initialDecision : "all");
  const [tool, setTool] = useState(searchParams.get("tool_name") ?? "");
  // F-35: debounce the tool-name filter — the input stays responsive but only ONE request fires after typing
  // settles (was one request per keystroke). The filter is already server-side over the selected range.
  const [debouncedTool, setDebouncedTool] = useState(tool);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedTool(tool), 400);
    return () => clearTimeout(t);
  }, [tool]);
  const [agentFilter, setAgentFilter] = useState("");
  // F-53: the SPIFFE filter is now SERVER-SIDE over the whole range (was a client-side filter of the current page,
  // so it silently missed matches off-page). Debounced like the tool filter.
  const [debouncedAgent, setDebouncedAgent] = useState(agentFilter);
  useEffect(() => {
    const t = setTimeout(() => setDebouncedAgent(agentFilter), 400);
    return () => clearTimeout(t);
  }, [agentFilter]);
  const [live, setLive] = useState(true);
  const [selected, setSelected] = useState<AuditRecord | null>(null);
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const base = useApi<AuditRecord[]>(
    () =>
      fetchAuditRecords({
        range: timeRange,
        namespace: selectedNamespace,
        decision: decision === "all" ? undefined : decision,
        tool_name: debouncedTool || undefined,
        agent: debouncedAgent || undefined,
        limit: pageSize,
        offset: page * pageSize
      }),
    [timeRange, selectedNamespace, decision, debouncedTool, debouncedAgent, page]
  );
  const totalRecords = useApi<AuditRecord[]>(
    () =>
      fetchAuditRecords({
        range: timeRange,
        namespace: selectedNamespace,
        decision: decision === "all" ? undefined : decision,
        tool_name: debouncedTool || undefined,
        agent: debouncedAgent || undefined,
        limit: 500,
        offset: 0
      }),
    [timeRange, selectedNamespace, decision, debouncedTool, debouncedAgent]
  );

  // The /ws/audit socket authenticates before accepting — pass the bearer token as a query param
  // (browsers can't set Authorization headers on WebSocket handshakes).
  const wsToken = typeof localStorage !== "undefined" ? localStorage.getItem("nrvq_token") ?? "" : "";
  const wsUrl = buildWsUrl(
    `/ws/audit?namespace=${encodeURIComponent(selectedNamespace)}&token=${encodeURIComponent(wsToken)}`
  );
  const ws = useWebSocket<AuditRecord>(wsUrl, live);

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
        const recent = await fetchAuditRecords({
          range: timeRange,
          namespace: selectedNamespace,
          decision: decision === "all" ? undefined : decision,
          tool_name: debouncedTool || undefined,
          limit: 10,
          offset: 0
        });
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
  }, [live, ws.connected, timeRange, selectedNamespace, decision, debouncedTool]);

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
    // F-53: filtering is server-side now (tool + agent); the live stream is only merged on page 0.
    const liveIds = new Set(streamed.map((r) => r.id).filter(Boolean));
    return [...(page === 0 ? streamed : []), ...(base.data ?? []).filter((r) => !liveIds.has(r.id))];
  }, [streamed, base.data, page]);

  const totalCount = totalRecords.data?.length ?? 0;
  const totalPages = Math.max(1, Math.ceil(totalCount / pageSize));
  const loading = base.loading || totalRecords.loading;
  const hasFilter = Boolean(debouncedTool || debouncedAgent || decision !== "all");
  const noResults = !loading && rows.length === 0;

  useEffect(() => {
    setPage(0);
  }, [timeRange, selectedNamespace, decision, debouncedTool, debouncedAgent]);

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
    { key: "rule_id", title: "Rule", render: (v) => <span className="mono muted">{(v as string) || "—"}</span> },
    { key: "agent_class", title: "Agent Class" },
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
        </div>

        {/* F-36 + F-53: visible count + an explicit no-results state (was: an empty table with no explanation). */}
        <div className="muted" style={{ fontSize: 12, minHeight: 16 }}>
          {loading
            ? "Loading…"
            : `Showing ${rows.length} of ${totalCount} record${totalCount === 1 ? "" : "s"} in range (${timeRange})${
                debouncedTool ? ` · tool contains “${debouncedTool}”` : ""
              }${debouncedAgent ? ` · agent contains “${debouncedAgent}”` : ""}`}
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
            {hasFilter && " Try a broader time range or clearing the tool/agent/decision filters."}
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
            Page {Math.min(page + 1, totalPages)} of {totalPages}
          </span>
          <KitButton
            variant="outline"
            size="sm"
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            disabled={page >= totalPages - 1}
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
            <pre className="json">
              {JSON.stringify(
                {
                  id: selected.id,
                  timestamp: selected.timestamp,
                  tool_name: selected.tool_name,
                  decision: selected.decision,
                  rule_id: selected.rule_id,
                  reason: selected.reason,
                  agent_id: selected.agent_id,
                  agent_class: selected.agent_class,
                  namespace: selected.namespace,
                  session_id: selected.session_id,
                  trust_score: selected.trust_score,
                  latency_ms: selected.latency_ms
                },
                null,
                2
              )}
            </pre>
          </Panel>
        )}
      </div>
    </div>
  );
}
