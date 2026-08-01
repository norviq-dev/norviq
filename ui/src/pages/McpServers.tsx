// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// MCP Servers — the inventory of Model Context Protocol servers the agent estate talks to, and the
// approval state of every tool DEFINITION they serve.
//
// This is the console half of Gate A. The proxy withholds a poisoned or drifted definition from the
// model in the microseconds before it forwards `tools/list`; this screen is where the operator finds
// out that happened, sees exactly what changed, and decides whether to adopt the new definition.
// Without it the enforcement is real but invisible — the agent quietly loses a tool and nobody knows
// why, which is how a security control gets switched off.
//
// The SERVER list leads because it answers the first question a chatbot operator asks — "which MCP
// integrations are live, and is any of them misbehaving?" — before any per-tool detail.

import { CSSProperties, useCallback, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, RefreshCw, ShieldAlert, ShieldCheck, XCircle } from "lucide-react";
import { apiGet, apiSend } from "../api/client";
import { Column, DataTable } from "../components/common/DataTable";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { StatTile } from "../components/common/StatTile";
import { useToast } from "../components/common/Toast";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";

export type McpServerRow = {
  namespace: string;
  server_id: string;
  transport: string;
  tools: number;
  drifted: number;
  quarantined: number;
  flagged: number;
  worst_severity: string;
  health: string;
  first_seen_at: string | null;
  last_seen_at: string | null;
  [key: string]: unknown;
};

export type McpFinding = { rule: string; severity: string; field: string; evidence: string; detail: string };

export type McpPinRow = {
  namespace: string;
  server_id: string;
  tool_name: string;
  approved_digest: string;
  last_digest: string;
  approved: boolean;
  approved_by: string;
  approved_at: string | null;
  scan_severity: string;
  findings: McpFinding[];
  drift_count: number;
  status: string;
  approved_canonical: string;
  last_canonical: string;
  [key: string]: unknown;
};

// Reuses the DecisionBadge colour language so severity reads the same way it does everywhere else in
// the console: red = enforced against, amber = needs a human, green = fine.
const TONE: Record<string, CSSProperties> = {
  bad: { background: "#FF3B5C15", color: "#FF3B5C", borderColor: "#FF3B5C30" },
  warn: { background: "#FFB02015", color: "#FFB020", borderColor: "#FFB02030" },
  ok: { background: "#00E5A015", color: "#00E5A0", borderColor: "#00E5A030" },
  neutral: { background: "#7C5CFC15", color: "#7C5CFC", borderColor: "#7C5CFC30" }
};

const HEALTH_META: Record<string, { label: string; tone: string; icon: typeof ShieldCheck }> = {
  drift: { label: "definition changed", tone: "bad", icon: ShieldAlert },
  quarantined: { label: "awaiting approval", tone: "warn", icon: AlertTriangle },
  flagged: { label: "scanner findings", tone: "warn", icon: AlertTriangle },
  ok: { label: "healthy", tone: "ok", icon: ShieldCheck }
};

const STATUS_TONE: Record<string, string> = { drift: "bad", quarantined: "warn", pinned: "ok" };

function Pill({ text, tone }: { text: string; tone: string }) {
  return (
    <span className="pill" style={TONE[tone] ?? TONE.neutral}>
      {text}
    </span>
  );
}

function severityTone(sev: string): string {
  return sev === "critical" || sev === "high" ? "bad" : sev === "none" ? "ok" : "warn";
}

/** Approved vs currently-served definition, side by side.
 *
 *  This is why the pin keeps `approved_canonical`: when a rug pull fires, the operator's first
 *  question is "what changed?", and the old definition cannot be re-fetched from a server that has
 *  already replaced it. Showing both turns an alarm into a decision. */
function DefinitionDiff({ approved, served }: { approved: string; served: string }) {
  const fmt = (s: string): string => {
    if (!s) return "(none recorded)";
    try {
      return JSON.stringify(JSON.parse(s), null, 2);
    } catch {
      return s;
    }
  };
  const changed = approved !== served && Boolean(served);
  return (
    <div className="grid grid-cols-2 md:grid-cols-1 gap-5">
      <div>
        <div className="page-sub">Approved definition</div>
        <pre className="json" data-testid="approved-definition">{fmt(approved)}</pre>
      </div>
      <div>
        <div className="page-sub" style={changed ? { color: "#FF3B5C" } : undefined}>
          {changed ? "Definition served now (CHANGED)" : "Definition served now"}
        </div>
        <pre className="json" data-testid="served-definition">{fmt(served)}</pre>
      </div>
    </div>
  );
}

export function McpServers() {
  const { selectedNamespace } = useApp();
  const toast = useToast();
  const ns = selectedNamespace || "all";
  const [selectedServer, setSelectedServer] = useState<string | null>(null);
  const [selectedTool, setSelectedTool] = useState<McpPinRow | null>(null);
  const [busy, setBusy] = useState(false);

  const loadServers = useCallback(
    () => apiGet<McpServerRow[]>(`/api/v1/mcp/servers?namespace=${encodeURIComponent(ns)}`),
    [ns]
  );
  const loadPins = useCallback(
    () => apiGet<McpPinRow[]>(`/api/v1/mcp/pins?namespace=${encodeURIComponent(ns)}`),
    [ns]
  );

  const servers = useApi<McpServerRow[]>(loadServers, [ns], { cacheKey: `mcp-servers:${ns}`, staleTimeMs: 5000 });
  const pins = useApi<McpPinRow[]>(loadPins, [ns], { cacheKey: `mcp-pins:${ns}`, staleTimeMs: 5000 });

  const serverRows = useMemo(() => servers.data ?? [], [servers.data]);
  const pinRows = useMemo(
    () => (pins.data ?? []).filter((p) => !selectedServer || p.server_id === selectedServer),
    [pins.data, selectedServer]
  );

  const totals = useMemo(() => {
    const t = { servers: serverRows.length, tools: 0, drifted: 0, quarantined: 0, flagged: 0 };
    for (const s of serverRows) {
      t.tools += s.tools;
      t.drifted += s.drifted;
      t.quarantined += s.quarantined;
      t.flagged += s.flagged;
    }
    return t;
  }, [serverRows]);

  const refresh = useCallback(() => {
    void servers.refetch();
    void pins.refetch();
  }, [servers, pins]);

  const act = useCallback(
    async (row: McpPinRow, action: "approve" | "revoke") => {
      setBusy(true);
      try {
        // Approve names the SERVED digest explicitly. The API refuses a digest it has not seen, so a
        // server that changes its definition again between this screen rendering and the click
        // landing gets a 409 rather than an accidental blessing.
        const body =
          action === "approve"
            ? {
                namespace: row.namespace,
                server_id: row.server_id,
                tool_name: row.tool_name,
                digest: row.last_digest || row.approved_digest
              }
            : { namespace: row.namespace, server_id: row.server_id, tool_name: row.tool_name };
        await apiSend<McpPinRow>(`/api/v1/mcp/pins/${action}`, "POST", body);
        toast.push({
          kind: "success",
          message:
            action === "approve"
              ? `Approved ${row.tool_name}`
              : `Revoked ${row.tool_name}`,
          detail:
            action === "approve"
              ? "The served definition is now the approved one; the tool is visible to the model again."
              : "The tool is withheld from the model and calls to it are refused until it is re-approved."
        });
        setSelectedTool(null);
        refresh();
      } catch (err) {
        toast.push({
          kind: "error",
          message: `Could not ${action} ${row.tool_name}`,
          detail: (err as Error).message
        });
      } finally {
        setBusy(false);
      }
    },
    [refresh, toast]
  );

  const serverColumns: Array<Column<McpServerRow>> = [
    { key: "server_id", title: "Server", render: (v) => <span className="mono">{String(v)}</span> },
    { key: "namespace", title: "Namespace", render: (v) => <span className="muted">{String(v)}</span> },
    { key: "transport", title: "Transport", render: (v) => <span className="mono muted">{String(v)}</span> },
    { key: "tools", title: "Tools" },
    {
      key: "health",
      title: "Status",
      render: (v) => {
        const meta = HEALTH_META[String(v)] ?? HEALTH_META.ok;
        const Icon = meta.icon;
        return (
          <span className="pill" style={{ ...TONE[meta.tone], display: "inline-flex", alignItems: "center", gap: 5 }}>
            <Icon size={12} /> {meta.label}
          </span>
        );
      }
    },
    {
      key: "drifted",
      title: "Drifted",
      render: (v) => (Number(v) > 0 ? <Pill text={String(v)} tone="bad" /> : <span className="muted">0</span>)
    },
    {
      key: "flagged",
      title: "Flagged",
      render: (v) => (Number(v) > 0 ? <Pill text={String(v)} tone="warn" /> : <span className="muted">0</span>)
    },
    {
      key: "last_seen_at",
      title: "Last seen",
      render: (v) => <span className="mono muted">{v ? new Date(String(v)).toLocaleString() : "—"}</span>
    }
  ];

  const pinColumns: Array<Column<McpPinRow>> = [
    { key: "tool_name", title: "Tool", render: (v) => <span className="mono">{String(v)}</span> },
    { key: "server_id", title: "Server", render: (v) => <span className="mono muted">{String(v)}</span> },
    {
      key: "status",
      title: "Pin",
      render: (v) => <Pill text={String(v).toUpperCase()} tone={STATUS_TONE[String(v)] ?? "neutral"} />
    },
    {
      key: "scan_severity",
      title: "Scan",
      render: (v) =>
        String(v) === "none" ? (
          <span className="muted">clean</span>
        ) : (
          <Pill text={String(v).toUpperCase()} tone={severityTone(String(v))} />
        )
    },
    {
      key: "approved_digest",
      title: "Approved",
      render: (v) => <span className="mono muted">{String(v).slice(0, 12) || "—"}</span>
    },
    {
      key: "last_digest",
      title: "Served",
      render: (v, row) => (
        <span className="mono" style={row.status === "drift" ? { color: "#FF3B5C" } : { opacity: 0.7 }}>
          {String(v).slice(0, 12) || "—"}
        </span>
      )
    },
    {
      key: "drift_count",
      title: "Drifts",
      render: (v) => (Number(v) > 0 ? <Pill text={String(v)} tone="bad" /> : <span className="muted">0</span>)
    },
    { key: "approved_by", title: "Approved by", render: (v) => <span className="muted">{String(v) || "—"}</span> }
  ];

  const loading = servers.loading || pins.loading;
  const error = servers.error || pins.error;

  return (
    <div className="stack page-enter">
      <PageHead
        title="MCP Servers"
        subtitle="Model Context Protocol integrations, and the approval state of every tool definition they serve"
        actions={
          <button type="button" className="btn btn-outline" onClick={refresh} disabled={loading}>
            <RefreshCw size={14} /> Refresh
          </button>
        }
      />

      <div className="grid grid-cols-5 lg:grid-cols-5 md:grid-cols-2 gap-5" data-testid="mcp-totals">
        <StatTile label="Servers" value={totals.servers} />
        <StatTile label="Tool definitions" value={totals.tools} />
        <StatTile label="Drifted" value={totals.drifted} color={totals.drifted ? "#FF3B5C" : undefined} />
        <StatTile label="Awaiting approval" value={totals.quarantined} color={totals.quarantined ? "#FFB020" : undefined} />
        <StatTile label="Scanner findings" value={totals.flagged} color={totals.flagged ? "#FFB020" : undefined} />
      </div>

      {error && (
        <Panel title="MCP inventory unavailable">
          <div className="muted">{String(error)}</div>
        </Panel>
      )}

      {!error && !loading && serverRows.length === 0 && (
        <Panel title="No MCP servers observed yet">
          <div className="muted">
            A server appears here the first time an agent runs a <span className="mono">tools/list</span> through the
            Norviq MCP proxy. Point the host&apos;s server command at{" "}
            <span className="mono">python -m norviq.mcp -- &lt;server command&gt;</span> to start governing it.
          </div>
        </Panel>
      )}

      {serverRows.length > 0 && (
        <Panel
          title="Servers"
          sub={
            selectedServer
              ? `Filtered to ${selectedServer} — click the row again to clear`
              : "Click a server to filter the tool definitions below"
          }
        >
          <DataTable<McpServerRow>
            columns={serverColumns}
            rows={serverRows}
            rowKey="server_id"
            selectedKey={selectedServer}
            onRowClick={(row) => setSelectedServer((cur) => (cur === row.server_id ? null : row.server_id))}
            placeholder="Filter servers…"
          />
        </Panel>
      )}

      {pinRows.length > 0 && (
        <Panel
          title="Tool definitions"
          sub="Pinned by content hash. A definition that changes after approval is a rug pull, and the tool is withheld from the model."
        >
          <DataTable<McpPinRow>
            columns={pinColumns}
            rows={pinRows}
            rowKey="tool_name"
            selectedKey={selectedTool ? `${selectedTool.server_id}/${selectedTool.tool_name}` : null}
            onRowClick={(row) =>
              setSelectedTool((cur) =>
                cur?.tool_name === row.tool_name && cur?.server_id === row.server_id ? null : row
              )
            }
            placeholder="Filter tools…"
          />
        </Panel>
      )}

      {selectedTool && (
        <Panel
          title={`${selectedTool.server_id} / ${selectedTool.tool_name}`}
          sub={
            selectedTool.status === "drift"
              ? "This server is serving a definition that DIFFERS from the one approved. Calls to this tool are refused until an operator adopts the change."
              : selectedTool.status === "quarantined"
                ? "Not approved. The tool is withheld from the model and calls to it are refused."
                : "Approved. The served definition matches the approved one."
          }
          action={
            <div style={{ display: "flex", gap: 8 }}>
              {selectedTool.status !== "pinned" && (
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={busy}
                  onClick={() => void act(selectedTool, "approve")}
                >
                  <CheckCircle2 size={14} /> Approve served definition
                </button>
              )}
              {selectedTool.approved && (
                <button
                  type="button"
                  className="btn btn-destructive"
                  disabled={busy}
                  onClick={() => void act(selectedTool, "revoke")}
                >
                  <XCircle size={14} /> Revoke
                </button>
              )}
            </div>
          }
          data-testid="mcp-detail"
        >
          {selectedTool.findings.length > 0 && (
            <div style={{ marginBottom: 20 }}>
              <div className="page-sub">Scanner findings</div>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Severity</th>
                    <th>Field</th>
                    <th>Why it fired</th>
                  </tr>
                </thead>
                <tbody>
                  {selectedTool.findings.map((f, i) => (
                    <tr key={`${f.rule}-${i}`}>
                      <td className="mono">{f.rule}</td>
                      <td>
                        <Pill text={f.severity.toUpperCase()} tone={severityTone(f.severity)} />
                      </td>
                      <td className="mono muted">{f.field}</td>
                      <td className="muted">{f.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <DefinitionDiff approved={selectedTool.approved_canonical} served={selectedTool.last_canonical} />
        </Panel>
      )}
    </div>
  );
}
