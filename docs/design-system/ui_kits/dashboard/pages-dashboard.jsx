// ============================================================================
// NORVIQ UI KIT — pages-dashboard.jsx
// ============================================================================
function buildVolume(records) {
  return Array.from({ length: 24 }, (_, i) => {
    const hour = i.toString().padStart(2, "0");
    const hourRows = records.filter((r) => r.timestamp.getHours() === i);
    return {
      time: `${hour}:00`,
      allow: hourRows.filter((r) => r.decision === "allow").length + Math.max(0, 8 - Math.abs(13 - i)),
      block: hourRows.filter((r) => r.decision === "block").length + (i % 5 === 0 ? 2 : 0)
    };
  });
}
function trustDistribution(agents) {
  return ["high", "medium", "low", "frozen"].map((name) => ({
    name, value: agents.filter((a) => a.category === name).length
  }));
}

function TopBlockedTools({ data }) {
  const max = Math.max(...data.map((d) => d.count), 1);
  return (
    <Panel title="Top blocked tools" sub="Most-blocked, last 24h">
      <div style={{ display: "flex", flexDirection: "column", gap: 13, marginTop: 4 }}>
        {data.map((d) => (
          <div key={d.tool} style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="mono" style={{ fontSize: 13, color: "var(--text-secondary)", width: 104, flex: "none", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{d.tool}</span>
            <div style={{ flex: 1, height: 10, borderRadius: 3, background: "#111d35", overflow: "hidden" }}>
              <div style={{ width: `${d.count / max * 100}%`, height: "100%", background: "#ff3b5c", borderRadius: 3 }}></div>
            </div>
            <span style={{ fontSize: 13, color: "var(--text-primary)", width: 24, textAlign: "right", flex: "none" }}>{d.count}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

function Dashboard({ namespace = "chatbot-prod" }) {
  const records = AUDIT_RECORDS;
  const blocked = records.filter((r) => r.decision === "block").slice(0, 10);
  const volume = useMemo(() => buildVolume(records), []);
  const trust = useMemo(() => trustDistribution(AGENTS), []);
  const topBlocked = [
    { tool: "execute_sql", count: 23 }, { tool: "delete_record", count: 12 },
    { tool: "spawn_pod", count: 8 }, { tool: "exec_shell", count: 6 }, { tool: "get_customer", count: 4 }
  ];

  return (
    <div className="page-enter">
      <PageHead title="Overview" subtitle={`Showing: ${namespace}`}
        actions={<>
          <Button variant="primary" icon="file-text">Generate Report</Button>
          <Button variant="outline" icon="download">Export</Button>
        </>} />
      <div className="stack" style={{ gap: 20 }}>
        <div className="grid g4" style={{ gap: 20 }}>
          <KPICard label="Total Calls 24h" value={12480} trend="↑12% vs yesterday" color="#3b7bf7" />
          <KPICard label="Blocked Today" value={318} trend="↓8% false positives" color="#ff3b5c" />
          <KPICard label="Block Rate %" value={3} trend="↓ healthier traffic" color="#ffb020" />
          <KPICard label="Avg Latency ms" value={19} trend="↑ fast path stable" color="#00e5a0" />
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1.5fr 1.5fr", gap: 20 }}>
          <ScoreGauge score={87} />
          <DonutChart data={trust} />
          <TopBlockedTools data={topBlocked} />
        </div>
        <VolumeChart data={volume} />
        <Panel title="Recent Blocked" sub="Last 10 blocked tool calls" style={{ paddingBottom: 6 }}>
          <div style={{ overflowX: "auto" }}>
            {blocked.length === 0 ? (
              <div style={{ textAlign: "center", color: "var(--text-muted)", padding: "32px 0", fontSize: 13 }}>No blocked tool calls in the last 24 hours</div>
            ) : (
              <table className="tbl">
                <thead><tr><th>Time</th><th>Tool</th><th>Decision</th><th>Rule</th><th>Namespace</th></tr></thead>
                <tbody>
                  {blocked.map((r) => (
                    <tr key={r.id}>
                      <td className="mono muted">{fmtTime(r.timestamp)}</td>
                      <td>{r.tool_name}</td>
                      <td><DecisionBadge decision={r.decision} /></td>
                      <td className="mono muted">{r.rule_id}</td>
                      <td className="mono">{namespace}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}

Object.assign(window, { Dashboard, buildVolume, trustDistribution, TopBlockedTools });
