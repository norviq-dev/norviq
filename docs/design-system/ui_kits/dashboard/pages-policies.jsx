// ============================================================================
// NORVIQ UI KIT — pages-policies.jsx
// Catalog (grouped by priority tier) · Rego editor · version history.
// Detail sheet uses the label-based Policy Target control.
// ============================================================================

// --- Rego editor (Monaco-style static highlighter) ------------------------
function renderRegoLine(line, i) {
  const cls = { str: "tk-str", num: "tk-num", key: "tk-key", fn: "tk-fn", plain: "" };
  if (line.t === "blank") return <div key={i}>&nbsp;</div>;
  if (line.t === "com") return <div key={i} className="tk-com">{line.s}</div>;
  if (line.t === "plain") return <div key={i}>{line.s}</div>;
  if (line.t === "key") return <div key={i}><span className="tk-key">{line.s}</span>{line.x}</div>;
  const pad = line.t === "indent" ? "  " : "";
  return <div key={i}>{pad}{line.parts.map((p, j) => <span key={j} className={cls[p[0]]}>{p[1]}</span>)}</div>;
}
function RegoEditor({ label = "checkout.rego", lines = REGO_SAMPLE, height = 420 }) {
  return (
    <div className="editor" style={{ height }}>
      <div className="editor-head"><Icon name="file-code" size={14} /> {label} <span style={{ marginLeft: "auto", color: "var(--text-muted)" }}>Rego · OPA</span></div>
      <div className="editor-body">
        <div className="editor-gutter">{lines.map((_, i) => <div key={i}>{i + 1}</div>)}</div>
        <div className="editor-code">{lines.map(renderRegoLine)}</div>
      </div>
    </div>
  );
}

// --- Label-based Policy Target control (used inside the sheet) -------------
function PolicyTarget({ policy }) {
  const initial = policy ? policy.target_type : "class";
  const [mode, setMode] = useState(initial);
  const [agentClass, setAgentClass] = useState(policy && policy.agent_class ? policy.agent_class : "customer-support");
  useEffect(() => { setMode(policy ? policy.target_type : "class"); if (policy && policy.agent_class) setAgentClass(policy.agent_class); }, [policy]);
  const matches = DEPLOYMENTS.filter((d) => d.agent_class === agentClass);

  const Seg = ({ id, label }) => (
    <button className={`tab${mode === id ? " active" : ""}`} onClick={() => setMode(id)} style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
      <span style={{ width: 12, height: 12, borderRadius: 99, border: `1.5px solid ${mode === id ? "var(--accent)" : "var(--text-muted)"}`, position: "relative", display: "inline-block" }}>
        {mode === id && <span style={{ position: "absolute", inset: 2, borderRadius: 99, background: "var(--accent)" }}></span>}
      </span>{label}
    </button>
  );
  const PrioBadge = ({ tier }) => {
    const p = PRIORITY[tier];
    return <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 14, paddingTop: 12, borderTop: "1px solid var(--border)", fontSize: 12 }}>
      <span style={{ display: "inline-flex", gap: 3, alignItems: "flex-end", height: 14 }}>
        {[1, 2, 3].map((r) => <i key={r} style={{ width: 4, borderRadius: 1, height: [14, 11, 8][r - 1], background: p.rank === r ? p.color : "var(--text-muted)", display: "inline-block" }}></i>)}
      </span>
      <span style={{ color: p.color, fontWeight: 600 }}>{tier === "class" ? "Agent-class" : tier === "workload" ? "Workload" : "Namespace"} policy</span>
      <span className="muted">· {p.label} priority</span>
    </div>;
  };

  return (
    <div>
      <div className="section-label">Target by</div>
      <div className="tabs" style={{ marginBottom: 16 }}>
        <Seg id="class" label="Agent Class" /><Seg id="workload" label="Workload" /><Seg id="namespace" label="Namespace" />
      </div>

      {mode === "class" && (<div>
        <div className="field"><label className="field-label">Agent Class · recommended</label>
          <div className="input select-trigger"><span>{agentClass}</span><Icon name="chevron-down" /></div></div>
        <div className="panel-sub" style={{ marginBottom: 8 }}>Applies to all deployments labeled</div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "#00e5a0", background: "#00e5a012", border: "1px solid #00e5a028", borderRadius: 6, padding: "6px 10px", display: "inline-block" }}>norviq.io/agent-class={agentClass}</span>
        <div style={{ marginTop: 14 }}>
          <div className="muted" style={{ fontSize: 11, display: "flex", alignItems: "center", gap: 6 }}><Icon name="radar" size={13} /> Matching deployments · auto-discovered</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 10 }}>
            {matches.map((d) => <span key={d.name} style={{ display: "inline-flex", alignItems: "center", gap: 6, fontFamily: "var(--font-mono)", fontSize: 12, background: "var(--bg-surface)", border: "1px solid var(--border)", borderRadius: 99, padding: "4px 11px" }}>
              <span style={{ width: 6, height: 6, borderRadius: 99, background: "#00e5a0", boxShadow: "0 0 6px #00e5a0" }}></span>{d.name}</span>)}
          </div>
        </div>
        <PrioBadge tier="class" />
      </div>)}

      {mode === "workload" && (<div>
        <div className="field"><label className="field-label">Kind</label><div className="input select-trigger"><span>Deployment</span><Icon name="chevron-down" /></div></div>
        <div className="field"><label className="field-label">Name</label><input className="input" defaultValue="smartsales-agent" /></div>
        <div className="field"><label className="field-label">Namespace</label><div className="input select-trigger"><span>chatbot-prod</span><Icon name="chevron-down" /></div></div>
        <div style={{ fontSize: 12, color: "var(--text-secondary)", display: "flex", alignItems: "center", gap: 7, marginTop: 4 }}><Icon name="arrow-up-circle" size={14} style={{ color: "#3b7bf7" }} />Overrides any agent-class policy for this workload</div>
        <PrioBadge tier="workload" />
      </div>)}

      {mode === "namespace" && (<div>
        <div className="field"><label className="field-label">Namespace</label><div className="input select-trigger"><span>chatbot-prod</span><Icon name="chevron-down" /></div></div>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-start", background: "#ffb02010", border: "1px solid #ffb02030", borderRadius: "var(--radius-md)", padding: "11px 13px", marginTop: 6 }}>
          <Icon name="triangle-alert" size={16} style={{ color: "#ffb020", flex: "none", marginTop: 1 }} />
          <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.5, color: "#ffcf7a" }}>Applies to <strong>ALL</strong> norviq-enabled workloads in this namespace. Use agent-class for precision.</p>
        </div>
        <PrioBadge tier="namespace" />
      </div>)}
    </div>
  );
}

// --- Policy detail sheet ("Configure Policy") ------------------------------
const MODE_DECISION = { block: "block", audit: "audit", escalate: "escalate" };
function RadioPill({ active, label, onClick }) {
  return (
    <button className={`tab${active ? " active" : ""}`} onClick={onClick} style={{ display: "inline-flex", alignItems: "center", gap: 7, textTransform: "capitalize" }}>
      <span style={{ width: 12, height: 12, borderRadius: 99, border: `1.5px solid ${active ? "var(--accent)" : "var(--text-muted)"}`, position: "relative", display: "inline-block" }}>
        {active && <span style={{ position: "absolute", inset: 2, borderRadius: 99, background: "var(--accent)" }}></span>}
      </span>{label}
    </button>
  );
}
function PolicySheet({ policy, onClose }) {
  const [enforcement, setEnforcement] = useState(policy.mode);
  const [paramsOpen, setParamsOpen] = useState(false);
  const [dryRun, setDryRun] = useState(false);
  return (
    <React.Fragment>
      <div className="sheet-overlay" onClick={onClose}></div>
      <div className="sheet">
        <div className="sheet-head">
          <div>
            <div className="sheet-title">Configure Policy</div>
            <div className="panel-sub mono" style={{ marginTop: 3 }}>{policy.target} · v{policy.current_version}</div>
          </div>
          <button className="icon-btn" onClick={onClose}><Icon name="x" size={18} /></button>
        </div>

        <PolicyTarget policy={policy} />

        <div className="section-label" style={{ marginTop: 20 }}>Enforcement Mode</div>
        <div className="tabs" style={{ display: "flex", marginBottom: 6 }}>
          {["block", "audit", "escalate"].map((m) => <RadioPill key={m} active={enforcement === m} label={m} onClick={() => setEnforcement(m)} />)}
        </div>

        <div className="section-label collapse-head" style={{ marginTop: 18 }} onClick={() => setParamsOpen((v) => !v)}>
          <span>Custom Parameters</span><Icon name={paramsOpen ? "chevron-up" : "chevron-down"} size={15} />
        </div>
        {paramsOpen && <div style={{ marginTop: 8 }}>
          <div className="field"><label className="field-label">Rate limit (calls/min)</label><input className="input mono" defaultValue="10" /></div>
          <div className="field"><label className="field-label">Block keywords</label><input className="input mono" defaultValue="secret,token,password" /></div>
          <div className="field"><label className="field-label">Trust threshold override</label><input className="input mono" defaultValue="0.7" /></div>
        </div>}

        <div className="section-label" style={{ marginTop: 18 }}>Generated YAML</div>
        <div className="editor" style={{ marginBottom: 10 }}>
          <div className="editor-head"><Icon name="file-code" size={14} /> NrvqPolicy <span style={{ marginLeft: "auto", color: "var(--text-muted)" }}>read-only</span></div>
          <div className="editor-body">
            <div className="editor-code" style={{ paddingLeft: 16 }}>
              <div><span className="tk-key">apiVersion</span>: <span className="tk-str">norviq.io/v1</span></div>
              <div><span className="tk-key">kind</span>: <span className="tk-str">NrvqPolicy</span></div>
              <div><span className="tk-key">spec</span>:</div>
              <div>{"  "}<span className="tk-key">targetType</span>: <span className="tk-str">{policy.target_type}</span></div>
              <div>{"  "}<span className="tk-key">target</span>: <span className="tk-str">{policy.target}</span></div>
              <div>{"  "}<span className="tk-key">enforcement</span>: <span className="tk-str">{enforcement}</span></div>
              <div>{"  "}<span className="tk-key">rateLimit</span>: <span className="tk-num">10</span></div>
              <div>{"  "}<span className="tk-key">keywords</span>: [<span className="tk-str">secret</span>, <span className="tk-str">token</span>, <span className="tk-str">password</span>]</div>
            </div>
          </div>
        </div>

        {dryRun && <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12.5, color: "#ffb020", background: "#ffb02010", border: "1px solid #ffb02030", borderRadius: "var(--radius-md)", padding: "9px 12px", marginBottom: 10 }}>
          <Icon name="info" size={14} /> Would have blocked <strong style={{ color: "#ffcf7a" }}>23 calls</strong> in the last 24h.
        </div>}

        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          <Button variant="primary" icon="check">Apply</Button>
          <Button variant="outline" icon="play" onClick={() => setDryRun(true)}>Dry-Run</Button>
          <Button variant="outline" icon="copy">Copy YAML</Button>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
        </div>
      </div>
    </React.Fragment>
  );
}

// --- Category coverage bars (moved from dashboard) -------------------------
const CATEGORY_SCORES = [
  { category: "OWASP LLM", score: 92 }, { category: "Data Protection", score: 88 },
  { category: "Tool Safety", score: 74 }, { category: "Rate Limiting", score: 63 }, { category: "Trust", score: 81 }
];
function CategoryCoverage() {
  const col = (s) => s > 80 ? "#00e5a0" : s >= 60 ? "#ffb020" : "#ff3b5c";
  return (
    <Panel title="Policy Coverage by Category" sub="Strength of enforcement across risk categories">
      <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 4 }}>
        {CATEGORY_SCORES.map((c) => (
          <div key={c.category} style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 13, color: "var(--text-secondary)", width: 130, flex: "none" }}>{c.category}</span>
            <div style={{ flex: 1, height: 10, borderRadius: 3, background: "#111d35", overflow: "hidden" }}>
              <div style={{ width: `${c.score}%`, height: "100%", background: col(c.score), borderRadius: 3 }}></div>
            </div>
            <span style={{ fontSize: 13, fontWeight: 600, color: col(c.score), width: 28, textAlign: "right", flex: "none" }}>{c.score}</span>
          </div>
        ))}
      </div>
    </Panel>
  );
}

// --- Catalog + tabs --------------------------------------------------------
const TIERS = [
  { type: "workload",  title: "Workload Policies",   sub: "Specific deployments · highest priority" },
  { type: "class",     title: "Agent-Class Policies", sub: "Groups of agents by label · medium priority" },
  { type: "namespace", title: "Namespace Policies",   sub: "Catch-all fallback · lowest priority" }
];
function PolicyCatalog() {
  const [tab, setTab] = useState("catalog");
  const [selected, setSelected] = useState(null);
  const [restoreV, setRestoreV] = useState(null);
  const [activeFile, setActiveFile] = useState("customer-support");

  return (
    <div className="page-enter">
      <PageHead title="Policy Catalog"
        actions={<Button variant="primary" icon="plus" onClick={() => setSelected(POLICIES[1])}>New Policy</Button>} />
      <div className="stack">
        <CategoryCoverage />

        <div className="tabs" style={{ alignSelf: "flex-start" }}>
          <button className={`tab${tab === "catalog" ? " active" : ""}`} onClick={() => setTab("catalog")}>Catalog</button>
          <button className={`tab${tab === "editor" ? " active" : ""}`} onClick={() => setTab("editor")}>Editor</button>
          <button className={`tab${tab === "versions" ? " active" : ""}`} onClick={() => setTab("versions")}>Versions</button>
        </div>

        {tab === "catalog" && <div className="stack">
          {TIERS.map((tier) => {
            const items = POLICIES.filter((p) => p.target_type === tier.type);
            return (
              <Panel key={tier.type} title={tier.title} sub={tier.sub}
                action={<span style={{ display: "inline-flex", gap: 3, alignItems: "flex-end", height: 14 }}>
                  {[1, 2, 3].map((r) => <i key={r} style={{ width: 4, borderRadius: 1, height: [14, 11, 8][r - 1], background: PRIORITY[tier.type].rank === r ? PRIORITY[tier.type].color : "var(--text-muted)", display: "inline-block" }}></i>)}
                </span>}>
                <div className="grid g3">
                  {items.map((p) => (
                    <button key={p.id} className="policy-item" onClick={() => setSelected(p)}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                        <span className="policy-name mono">{p.target}</span>
                        <DecisionBadge decision={MODE_DECISION[p.mode]} />
                      </div>
                      <div className="policy-meta">v{p.current_version} · {p.rego_length.toLocaleString()} chars · {p.matches} match{p.matches !== 1 ? "es" : ""}</div>
                    </button>
                  ))}
                </div>
              </Panel>
            );
          })}
        </div>}

        {tab === "editor" && <Panel pad={true}>
          <div style={{ display: "flex", gap: 0, border: "1px solid var(--border)", borderRadius: "var(--radius-md)", overflow: "hidden" }}>
            <div style={{ width: 200, flex: "none", background: "var(--bg-surface)", borderRight: "1px solid var(--border)", padding: 8 }}>
              <div className="section-label" style={{ padding: "4px 8px" }}>Policies</div>
              {POLICIES.filter((p) => p.target_type === "class").map((p) => (
                <button key={p.id} className={`sb-link${activeFile === p.target ? " active" : ""}`} onClick={() => setActiveFile(p.target)} style={{ fontSize: 12.5 }}>
                  <Icon name="file-code" size={14} /><span className="mono" style={{ fontSize: 12 }}>{p.target}.rego</span>
                </button>
              ))}
            </div>
            <div style={{ flex: 1, minWidth: 0, display: "flex", flexDirection: "column" }}>
              <RegoEditor label={`${activeFile}.rego`} height={400} />
              <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 14px", borderTop: "1px solid var(--border)", background: "var(--bg-surface)" }}>
                <span style={{ color: "#00e5a0", fontSize: 12.5, display: "inline-flex", alignItems: "center", gap: 6 }}><Icon name="check-circle" size={14} /> Valid Rego</span>
                <div style={{ flex: 1 }}></div>
                <Button variant="primary" size="sm" icon="check">Save</Button>
                <Button variant="outline" size="sm" icon="play">Dry-Run</Button>
              </div>
            </div>
          </div>
        </Panel>}

        {tab === "versions" && <Panel title="Version History" sub="customer-support · agent-class" style={{ paddingBottom: 6 }}>
          <div style={{ overflowX: "auto" }}>
            <table className="tbl">
              <thead><tr><th>Version</th><th>Saved By</th><th>Saved At</th><th>Rego Size</th><th></th></tr></thead>
              <tbody>
                {POLICY_VERSIONS.map((v, i) => (
                  <tr key={v.version} style={{ cursor: "default" }}>
                    <td><span className="mono">v{v.version}</span>{i === 0 && <span className="pill" style={{ marginLeft: 8, color: "#00e5a0", borderColor: "#00e5a040" }}>current</span>}</td>
                    <td className="mono muted">{v.saved_by}</td>
                    <td className="muted">{v.saved_at.toLocaleString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" })}</td>
                    <td className="mono muted">{(900 + v.version * 180).toLocaleString()} B</td>
                    <td>{i !== 0 && <Button variant="outline" size="sm" icon="rotate-ccw" onClick={() => setRestoreV(v.version)}>Restore</Button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>}
      </div>

      {selected && <PolicySheet policy={selected} onClose={() => setSelected(null)} />}

      {restoreV != null && (
        <React.Fragment>
          <div className="sheet-overlay" onClick={() => setRestoreV(null)}></div>
          <div className="confirm-modal">
            <div className="sheet-title">Restore version v{restoreV}?</div>
            <p style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.5, margin: "10px 0 18px" }}>This rolls the active policy back to v{restoreV}. The current version is preserved in history.</p>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <Button variant="ghost" onClick={() => setRestoreV(null)}>Cancel</Button>
              <Button variant="primary" icon="rotate-ccw" onClick={() => setRestoreV(null)}>Confirm Restore</Button>
            </div>
          </div>
        </React.Fragment>
      )}
    </div>
  );
}

Object.assign(window, { PolicyCatalog, PolicySheet, PolicyTarget, RegoEditor });
