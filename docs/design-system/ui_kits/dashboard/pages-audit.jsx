// ============================================================================
// NORVIQ UI KIT — pages-audit.jsx
// Filterable, live-streaming audit log with expandable JSON event detail.
// ============================================================================
function StatTile({ label, value, color }) {
  return (
    <div className="panel panel-pad">
      <div className="kpi-label">{label}</div>
      <div style={{ fontSize: 24, fontWeight: 600, marginTop: 6, color: color || "var(--text-primary)" }}>{value.toLocaleString()}</div>
    </div>
  );
}

function AuditLog({ namespace = "chatbot-prod" }) {
  const [decision, setDecision] = useState("all");
  const [tool, setTool] = useState("");
  const [agent, setAgent] = useState("");
  const [live, setLive] = useState(true);
  const [selected, setSelected] = useState(null);
  const [streamed, setStreamed] = useState([]);
  const tick = useRef(0);

  // Simulated WebSocket: prepend a synthetic record every ~2.6s while live.
  useEffect(() => {
    if (!live) return;
    const id = setInterval(() => {
      const src = AUDIT_RECORDS[tick.current % AUDIT_RECORDS.length];
      tick.current += 1;
      setStreamed((prev) => [{ ...src, id: "live_" + Date.now(), timestamp: new Date(), _live: true }, ...prev].slice(0, 6));
    }, 2600);
    return () => clearInterval(id);
  }, [live]);

  const all = useMemo(() => [...streamed, ...AUDIT_RECORDS], [streamed]);
  const rows = useMemo(() => all.filter((r) => {
    if (decision !== "all" && r.decision !== decision) return false;
    if (tool && !r.tool_name.toLowerCase().includes(tool.toLowerCase())) return false;
    if (agent && !r.agent_id.toLowerCase().includes(agent.toLowerCase())) return false;
    return true;
  }).slice(0, 40), [all, decision, tool, agent]);

  const volume = useMemo(() => buildVolume(AUDIT_RECORDS), []);

  const columns = [
    { key: "timestamp", title: "Time", render: (v, r) => <span className="mono muted">{fmtTime(v)}{r._live && <span style={{ color: "#00e5a0", marginLeft: 6 }}>●</span>}</span> },
    { key: "tool_name", title: "Tool" },
    { key: "decision", title: "Decision", render: (v) => <DecisionBadge decision={v} /> },
    { key: "rule_id", title: "Rule", render: (v) => <span className="mono muted">{v}</span> },
    { key: "agent_class", title: "Agent Class" },
    { key: "trust_score", title: "Trust", render: (v) => <TrustBadge category={trustCategory(v)} /> },
    { key: "latency_ms", title: "Latency", render: (v) => <span className="mono">{v}ms</span> }
  ];

  const DEC = ["all", "allow", "block", "escalate", "audit"];

  return (
    <div className="page-enter">
      <PageHead title="Audit Log" subtitle={`Showing: ${namespace}`}
        actions={<Button variant={live ? "secondary" : "outline"} onClick={() => setLive((v) => !v)}>
          <span className={live ? "live-on" : "muted"}>{live ? "● Live" : "○ Paused"}</span>
        </Button>} />
      <div className="stack">
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <div className="tabs">
            {DEC.map((d) => <button key={d} className={`tab${decision === d ? " active" : ""}`} onClick={() => setDecision(d)}>{d === "all" ? "All" : d[0].toUpperCase() + d.slice(1)}</button>)}
          </div>
          <input className="input" style={{ maxWidth: 180 }} placeholder="Tool name" value={tool} onChange={(e) => setTool(e.target.value)} />
          <input className="input" style={{ maxWidth: 200 }} placeholder="Agent SPIFFE contains…" value={agent} onChange={(e) => setAgent(e.target.value)} />
          <input className="input" type="date" style={{ maxWidth: 160, colorScheme: "dark" }} title="Time range" />
        </div>

        <div className="grid g4">
          <StatTile label="Total (window)" value={AUDIT_STATS.window_total} />
          <StatTile label="Blocked" value={AUDIT_STATS.window_blocked} color="#ff3b5c" />
          <StatTile label="Allowed" value={AUDIT_STATS.window_allowed} color="#00e5a0" />
          <StatTile label="Streaming" value={streamed.length} color="#3b7bf7" />
        </div>

        <VolumeChart data={volume} />

        <DataTable columns={columns} rows={rows} rowKey="id" selectedKey={selected ? selected.id : null}
          onRowClick={(r) => setSelected(r)} placeholder="Quick filter rows…" />

        {selected && (
          <Panel title="Event Detail" sub={selected.id}
            action={<Button variant="ghost" size="sm" icon="x" onClick={() => setSelected(null)}>Close</Button>}>
            <pre className="json">{JSON.stringify({
              id: selected.id, timestamp: selected.timestamp.toISOString(), tool_name: selected.tool_name,
              decision: selected.decision, rule_id: selected.rule_id, reason: selected.reason,
              agent_id: selected.agent_id, agent_class: selected.agent_class, namespace: selected.namespace,
              session_id: selected.session_id, trust_score: selected.trust_score, latency_ms: selected.latency_ms
            }, null, 2)}</pre>
          </Panel>
        )}
      </div>
    </div>
  );
}

Object.assign(window, { AuditLog, StatTile });
