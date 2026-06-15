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
  const [agentFilter, setAgentFilter] = useState("");
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
        tool_name: tool || undefined,
        limit: pageSize,
        offset: page * pageSize
      }),
    [timeRange, selectedNamespace, decision, tool, page]
  );
  const totalRecords = useApi<AuditRecord[]>(
    () =>
      fetchAuditRecords({
        range: timeRange,
        namespace: selectedNamespace,
        decision: decision === "all" ? undefined : decision,
        tool_name: tool || undefined,
        limit: 500,
        offset: 0
      }),
    [timeRange, selectedNamespace, decision, tool]
  );

  const wsUrl = buildWsUrl("/ws/audit");
  const ws = useWebSocket<AuditRecord>(wsUrl, live);

  const streamed = useMemo(
    () =>
      ws.messages.slice(0, 6).map((m) => ({ ...m, _live: true })) as AuditRecord[],
    [ws.messages]
  );

  const rows = useMemo(() => {
    const all = [...(page === 0 ? streamed : []), ...(base.data ?? [])];
    return all.filter((r) =>
      agentFilter ? (r.agent_id ?? "").toLowerCase().includes(agentFilter.toLowerCase()) : true
    );
  }, [streamed, base.data, agentFilter, page]);

  const totalPages = Math.max(1, Math.ceil((totalRecords.data?.length ?? 0) / pageSize));

  useEffect(() => {
    setPage(0);
  }, [timeRange, selectedNamespace, decision, tool]);

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

        <DataTable
          columns={columns}
          rows={rows}
          rowKey="id"
          selectedKey={selected?.id ?? null}
          onRowClick={(r) => setSelected(r)}
          placeholder="Quick filter rows…"
        />
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
