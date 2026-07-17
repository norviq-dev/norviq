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
import { useApp } from "../store/AppContext";
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
  tool_params?: Record<string, unknown> | null; // E2(b): request args captured with the decision (may be absent)
  framework?: string; // OBS-2: decision source (sidecar / sidecar-http / sdk / redteam / ...)
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

export function AuditLog() {
  const { selectedNamespace, timeRange, setNamespace } = useApp();
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
  // Seed from the deep-link's `agent` (or legacy `spiffe_id`) param so the SPIFFE filter is pre-applied.
  const [agentFilter, setAgentFilter] = useState(searchParams.get("agent") ?? searchParams.get("spiffe_id") ?? "");
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
  // Compliance deep-link: an evidence row opens the Audit Log pre-filtered by the enforcing rule (?rule=<rule_id>).
  const [rule, setRule] = useState(searchParams.get("rule") ?? "");

  // STALE-6: the /audit route stays MOUNTED across query-string changes (React Router doesn't remount it),
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
      namespace: searchParams.get("namespace")
    };
    const prev = lastParamsRef.current;
    const firstRun = "init" in prev; // mount: seeds already applied via useState — only adopt namespace
    if (!firstRun && cur.decision !== prev.decision && cur.decision)
      setDecision(DEC.includes(cur.decision as DecisionFilter) ? (cur.decision as DecisionFilter) : "all");
    if (!firstRun && cur.tool_name !== prev.tool_name && cur.tool_name != null) setTool(cur.tool_name);
    if (!firstRun && cur.agent !== prev.agent && cur.agent != null) setAgentFilter(cur.agent);
    if (!firstRun && cur.rule !== prev.rule && cur.rule != null) setRule(cur.rule);
    // Namespace deep-link (Asset Graph inspector) applies on mount too — switch the global scope to the agent's ns.
    if (cur.namespace && cur.namespace !== prev.namespace) setNamespace(cur.namespace);
    lastParamsRef.current = cur;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const base = useApi<AuditRecord[]>(
    () =>
      fetchAuditRecords({
        range: timeRange,
        namespace: selectedNamespace,
        decision: decision === "all" ? undefined : decision,
        tool_name: debouncedTool || undefined,
        agent: debouncedAgent || undefined,
        rule_id: rule || undefined,
        limit: pageSize,
        offset: page * pageSize
      }),
    [timeRange, selectedNamespace, decision, debouncedTool, debouncedAgent, rule, page]
  );
  const totalRecords = useApi<AuditRecord[]>(
    () =>
      fetchAuditRecords({
        range: timeRange,
        namespace: selectedNamespace,
        decision: decision === "all" ? undefined : decision,
        tool_name: debouncedTool || undefined,
        agent: debouncedAgent || undefined,
        rule_id: rule || undefined,
        limit: 500,
        offset: 0
      }),
    [timeRange, selectedNamespace, decision, debouncedTool, debouncedAgent, rule]
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
  // F-63: the total-count probe is server-capped at limit=500 (audit/records enforces le=500), so records
  // PAST offset 500 used to be unreachable — totalPages maxed at 10 and Next was disabled at page 10 even
  // though the server offset has no upper bound. When the probe comes back full there are likely more rows
  // than it can see, so fall back to "there IS a next page iff the current page returned a full pageSize"
  // and keep the page/record totals honest (show a trailing "+") once we're past what the probe can count.
  const countCapped = totalCount >= 500;
  const pageFull = (base.data?.length ?? 0) === pageSize;
  const knownPages = Math.max(1, Math.ceil(totalCount / pageSize));
  const totalPages = Math.max(knownPages, page + 1);
  const canNext = page < knownPages - 1 || (countCapped && pageFull);
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
    { key: "rule_id", title: "Rule", render: (v) => {
      const rid = (v as string) || "";
      // TGT-POSTURE-01: a Monitor-mode softened row (monitor_would_block:<orig>) reads clearly as observe-mode.
      if (rid.startsWith("monitor_would_block:")) {
        return <span className="mono muted" title={rid}>Would-block (monitor) · {rid.slice("monitor_would_block:".length)}</span>;
      }
      return <span className="mono muted">{rid || "—"}</span>;
    } },
    { key: "agent_class", title: "Agent Class" },
    // OBS-2: decision source so sidecar-enforced calls are distinguishable from API/console-originated ones.
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
        </div>

        {/* F-36 + F-53: visible count + an explicit no-results state (was: an empty table with no explanation). */}
        <div className="muted" style={{ fontSize: 12, minHeight: 16 }}>
          {loading
            ? "Loading…"
            : `Showing ${rows.length} of ${totalCount}${countCapped ? "+" : ""} record${totalCount === 1 ? "" : "s"} in range (${timeRange})${
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
              // MUT-3: the record's agent_class is AUTHORITATIVE for the class — it is what the table
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
                    <DetailRow label="Params">
                      {hasParams ? (
                        <pre className="json" style={{ margin: 0, fontSize: 12 }}>
                          {JSON.stringify(selected.tool_params, null, 2)}
                        </pre>
                      ) : (
                        <span className="muted">—</span>
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
