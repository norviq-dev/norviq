// ============================================================================
// NORVIQ UI KIT — pages-misc.jsx  (Settings)
// ============================================================================
function SettingsSection({ label, children }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.08em", color: "#4a5a78", textTransform: "uppercase", marginBottom: 10 }}>{label}</div>
      {children}
    </div>
  );
}
function Field({ label, hint, children }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 20, padding: "12px 0", borderBottom: "1px solid var(--border)" }}>
      <div>
        <div style={{ fontSize: 13.5, color: "var(--text-primary)" }}>{label}</div>
        {hint && <div style={{ fontSize: 12, color: "var(--text-secondary)", marginTop: 2 }}>{hint}</div>}
      </div>
      <div style={{ flex: "none" }}>{children}</div>
    </div>
  );
}
function Settings() {
  const [mode, setMode] = useState("block");
  const conns = [
    { name: "Redis", conn: "redis://:****@127.0.0.1:6379", ok: true, ms: "2ms" },
    { name: "PostgreSQL", conn: "postgresql://****@127.0.0.1:5432", ok: true, ms: "3ms" },
    { name: "OTel", conn: "http://127.0.0.1:4317", ok: true, ms: "1ms" }
  ];
  const keys = [
    { name: "ci-pipeline", key: "nrvq_live_****8f3a", created: "Apr 12, 2026" },
    { name: "grafana-readonly", key: "nrvq_live_****b71c", created: "Mar 28, 2026" }
  ];
  return (
    <div className="page-enter" style={{ maxWidth: 760, position: "relative", paddingBottom: 72 }}>
      <PageHead title="Settings" />
      <div className="stack">
        <Panel pad={true}>
          <SettingsSection label="General">
            <Field label="Enforcement Mode" hint="Default action when a policy matches">
              <div className="tabs">
                {["block", "audit"].map((m) => <button key={m} className={`tab${mode === m ? " active" : ""}`} onClick={() => setMode(m)} style={{ textTransform: "capitalize" }}>{m}</button>)}
              </div>
            </Field>
            <Field label="Trust Threshold" hint="Score below this triggers escalation">
              <input className="input mono" defaultValue="0.7" style={{ width: 90, textAlign: "right" }} />
            </Field>
            <Field label="Violation Penalty" hint="Trust deducted per blocked call">
              <input className="input mono" defaultValue="0.05" style={{ width: 90, textAlign: "right" }} />
            </Field>
            <Field label="Rate Limit" hint="Max tool calls per agent per minute">
              <input className="input mono" defaultValue="60" style={{ width: 90, textAlign: "right" }} />
            </Field>
          </SettingsSection>
        </Panel>

        <Panel pad={true}>
          <SettingsSection label="Connections">
            <div style={{ overflowX: "auto" }}>
              <table className="tbl">
                <tbody>
                  {conns.map((c) => (
                    <tr key={c.name} style={{ cursor: "default" }}>
                      <td style={{ fontWeight: 500 }}>{c.name}</td>
                      <td className="mono muted" style={{ fontSize: 12 }}>{c.conn}</td>
                      <td><span style={{ display: "inline-flex", alignItems: "center", gap: 7, color: c.ok ? "#00e5a0" : "#ff3b5c", fontSize: 13 }}><span style={{ width: 8, height: 8, borderRadius: 99, background: "currentColor" }}></span>{c.ok ? "Connected" : "Disconnected"}</span></td>
                      <td className="mono muted">{c.ms}</td>
                      <td><Button variant="outline" size="sm">Test</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </SettingsSection>
        </Panel>

        <Panel pad={true}>
          <SettingsSection label="API">
            <div style={{ overflowX: "auto" }}>
              <table className="tbl">
                <thead><tr><th>Name</th><th>Key</th><th>Created</th><th></th></tr></thead>
                <tbody>
                  {keys.map((k) => (
                    <tr key={k.name} style={{ cursor: "default" }}>
                      <td style={{ fontWeight: 500 }}>{k.name}</td>
                      <td className="mono muted">{k.key}</td>
                      <td className="muted">{k.created}</td>
                      <td><Button variant="ghost" size="sm" className="revoke">Revoke</Button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div style={{ marginTop: 14 }}><Button variant="primary" icon="plus">Create API Key</Button></div>
          </SettingsSection>
        </Panel>

        <Panel pad={true}>
          <SettingsSection label="About">
            <div className="kv"><span className="k">Version</span><span className="mono">0.1.0</span></div>
            <div className="kv"><span className="k">License</span><span>Apache 2.0</span></div>
            <div className="kv"><span className="k">GitHub</span><a href="https://github.com/norviq-dev/norviq" target="_blank" rel="noreferrer" style={{ color: "var(--accent)", textDecoration: "none" }}>github.com/norviq-dev/norviq ↗</a></div>
            <div className="kv"><span className="k">Documentation</span><a href="https://norviq.dev/docs" target="_blank" rel="noreferrer" style={{ color: "var(--accent)", textDecoration: "none" }}>norviq.dev/docs ↗</a></div>
          </SettingsSection>
        </Panel>
      </div>

      <div style={{ position: "sticky", bottom: 0, marginTop: 16, padding: "12px 0", display: "flex", justifyContent: "flex-end", background: "linear-gradient(transparent, var(--bg-void) 40%)" }}>
        <Button variant="primary" icon="check">Save Changes</Button>
      </div>
    </div>
  );
}

Object.assign(window, { Settings });
