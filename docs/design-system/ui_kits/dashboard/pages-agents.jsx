// ============================================================================
// NORVIQ UI KIT — pages-agents.jsx
// SPIFFE-identified agents with trust scores, violations, and freeze/reset.
// ============================================================================
function AgentMonitor({ namespace = "chatbot-prod" }) {
  const [selected, setSelected] = useState(null);
  const [agents, setAgents] = useState(AGENTS);
  const trust = useMemo(() => trustDistribution(agents), [agents]);

  const setTrust = (id, score) => setAgents((prev) => prev.map((a) =>
    a.spiffe_id === id ? { ...a, score, category: score === 0 ? "frozen" : trustCategory(score) } : a));

  const columns = [
    { key: "spiffe_id", title: "SPIFFE ID", render: (v) => <span className="mono" style={{ fontSize: 12 }}>{v}</span> },
    { key: "agent_class", title: "Class" },
    { key: "score", title: "Trust Score", render: (v) => <span className="mono">{v.toFixed(2)}</span> },
    { key: "category", title: "Tier", render: (v) => <TrustBadge category={v} pulse={v === "low"} /> },
    { key: "behavior", title: "Behavior", thTitle: "Behavioral anomaly detection · coming in Phase 3",
      render: () => <span className="behavior normal"><span className="bdot"></span><span className="muted">Normal</span></span> },
    { key: "violation_count", title: "Violations", render: (v) => <span style={{ color: v > 8 ? "#ff3b5c" : v > 3 ? "#ffb020" : "var(--text-secondary)" }}>{v}</span> },
    { key: "last_seen", title: "Last Seen", render: (v) => <span className="mono muted">{v}</span> }
  ];

  const sel = selected ? agents.find((a) => a.spiffe_id === selected.spiffe_id) : null;
  const trustHistory = useMemo(() => Array.from({ length: 7 }, (_, i) => {
    const cur = sel ? sel.score : 0.8;
    const t = Math.max(0, Math.min(1, cur - (6 - i) * 0.04 + (i % 2 ? 0.02 : -0.01)));
    return { time: `D${i + 1}`, allow: Math.round(t * 100), block: Math.round((1 - t) * 100) };
  }), [sel]);
  const toolUsage = [
    { category: "read_file", score: 88 }, { category: "db_query", score: 72 },
    { category: "http_request", score: 54 }, { category: "exec_shell", score: 22 }, { category: "send_email", score: 41 }
  ];

  return (
    <div className="page-enter">
      <PageHead title="Agent Monitor" subtitle={`Showing: ${namespace}`} />
      <div className="stack">
        <div className="grid g3">
          <div style={{ gridColumn: "span 1" }}><DonutChart data={trust} title="Trust Distribution" /></div>
          <div className="grid g2" style={{ gridColumn: "span 2", gridTemplateColumns: "1fr 1fr", alignContent: "start" }}>
            <StatTile label="Agents Tracked" value={agents.length} color="#3b7bf7" />
            <StatTile label="Frozen" value={agents.filter((a) => a.category === "frozen").length} color="#4a5a78" />
            <StatTile label="Low Trust" value={agents.filter((a) => a.category === "low").length} color="#ff3b5c" />
            <StatTile label="High Trust" value={agents.filter((a) => a.category === "high").length} color="#00e5a0" />
          </div>
        </div>

        <DataTable columns={columns} rows={agents} rowKey="spiffe_id" selectedKey={sel ? sel.spiffe_id : null}
          onRowClick={(r) => setSelected(r)} placeholder="Search SPIFFE ID, class, tier…" />

        {sel && (
          <div className="grid g3">
            <VolumeChart data={trustHistory} title="Trust History · 7d" labels={["Trust", "Risk"]} />
            <CategoryBars data={toolUsage} title="Tool Usage" />
            <Panel title="Agent Actions">
              <div className="mono" style={{ fontSize: 12, color: "var(--text-secondary)", wordBreak: "break-all", marginBottom: 14 }}>{sel.spiffe_id}</div>
              <div className="kv"><span className="k">Class</span><span>{sel.agent_class}</span></div>
              <div className="kv"><span className="k">Namespace</span><span className="mono">{sel.namespace}</span></div>
              <div className="kv"><span className="k">Current trust</span><span><TrustBadge category={sel.category} /> <span className="mono">{sel.score.toFixed(2)}</span></span></div>
              <div className="kv"><span className="k">Violations</span><span>{sel.violation_count}</span></div>
              <div style={{ display: "flex", gap: 8, marginTop: 16 }}>
                <Button variant="primary" icon="rotate-ccw" onClick={() => setTrust(sel.spiffe_id, 0.8)}>Reset Trust</Button>
                <Button variant="destructive" icon="snowflake" onClick={() => setTrust(sel.spiffe_id, 0)}>Freeze Agent</Button>
              </div>
            </Panel>
          </div>
        )}
      </div>
    </div>
  );
}

Object.assign(window, { AgentMonitor });
