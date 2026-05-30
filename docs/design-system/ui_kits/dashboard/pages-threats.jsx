// ============================================================================
// NORVIQ UI KIT — pages-threats.jsx
// Threat Modeling: attack-path graph (agents → tools → data) + ranked paths,
// MITRE ATLAS coverage, filters. KubeHound-style topology for agent tool calls.
// ============================================================================

// --- Graph model — 3-column Sankey layout (viewBox 760×460) ----------------
const COL = { agent: 120, tool: 380, data: 648 };
const ROW = [110, 230, 350];
const TM_NODES = {
  "customer-support": { x: COL.agent, y: ROW[0], type: "agent", label: "customer-support", sub: "agent",       risk: "high" },
  "agent-b":          { x: COL.agent, y: ROW[1], type: "agent", label: "agent-b",          sub: "agent",       risk: "med"  },
  "data-analyst":     { x: COL.agent, y: ROW[2], type: "agent", label: "data-analyst",     sub: "agent",       risk: "med"  },
  "search_kb":        { x: COL.tool,  y: ROW[0], type: "tool",  label: "search_kb",        sub: "tool",        risk: "safe" },
  "execute_sql":      { x: COL.tool,  y: ROW[1], type: "tool",  label: "execute_sql",      sub: "tool",        risk: "high" },
  "delete_record":    { x: COL.tool,  y: ROW[2], type: "tool",  label: "delete_record",    sub: "tool",        risk: "high" },
  "user_sessions":    { x: COL.data,  y: ROW[0], type: "data",  label: "user_sessions",    sub: "data source", risk: "safe" },
  "customers_db":     { x: COL.data,  y: ROW[1], type: "data",  label: "customers_db",     sub: "data source", risk: "high" },
  "orders_db":        { x: COL.data,  y: ROW[2], type: "data",  label: "orders_db",        sub: "data source", risk: "med"  }
};
const TM_EDGES = [
  { a: "customer-support", b: "search_kb",     kind: "calls",     risk: "safe" },
  { a: "customer-support", b: "execute_sql",   kind: "calls",     risk: "high" },
  { a: "customer-support", b: "agent-b",       kind: "delegates", risk: "med"  },
  { a: "agent-b",          b: "execute_sql",   kind: "calls",     risk: "med"  },
  { a: "data-analyst",     b: "delete_record", kind: "calls",     risk: "med"  },
  { a: "execute_sql",      b: "customers_db",  kind: "accesses",  risk: "high" },
  { a: "delete_record",    b: "orders_db",     kind: "accesses",  risk: "med"  },
  { a: "search_kb",        b: "user_sessions", kind: "accesses",  risk: "safe" }
];
const TYPE_COLOR = { agent: "#3b7bf7", data: "#7c5cfc" };
const RISK_COLOR = { high: "#ff3b5c", med: "#ffb020", safe: "#00e5a0" };
const DASH = { calls: "none", accesses: "6 5", delegates: "1.5 6" };
// edge color: delegates always amber; otherwise red when high-risk, muted when not
const edgeColor = (e) => e.kind === "delegates" ? "#ffb020" : (e.risk === "high" ? "#ff3b5c" : "#8494b2");
const edgeMarker = (e) => { const c = edgeColor(e); return c === "#ff3b5c" ? "ah-red" : c === "#ffb020" ? "ah-amber" : "ah-muted"; };
const NODE_R = { agent: 23, tool: 28, data: 24 };

// Lucide-style glyphs (24-grid), rendered with non-scaling stroke
function Glyph({ d, cx, cy, size, circle }) {
  const s = size / 24;
  return (
    <g transform={`translate(${cx - size / 2} ${cy - size / 2}) scale(${s})`} fill="none" stroke="#e8edf5"
       strokeWidth={1.7 / s} strokeLinecap="round" strokeLinejoin="round" style={{ pointerEvents: "none" }}>
      {circle && <circle cx={circle[0]} cy={circle[1]} r={circle[2]} />}
      {d && <path d={d} />}
    </g>
  );
}
const ICON_WRENCH = "M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z";
const ICON_USER_BODY = "M5.5 20a6.5 6.5 0 0 1 13 0";

function ThreatGraphCanvas({ highRiskOnly, selected, onSelect }) {
  const dimEl = (risk) => highRiskOnly && risk !== "high";
  // trim an edge to node borders so arrowheads sit just outside the shape
  function seg(e) {
    const A = TM_NODES[e.a], B = TM_NODES[e.b];
    const dx = B.x - A.x, dy = B.y - A.y, L = Math.hypot(dx, dy) || 1, ux = dx / L, uy = dy / L;
    return { x1: A.x + ux * (NODE_R[A.type] + 2), y1: A.y + uy * (NODE_R[A.type] + 2),
             x2: B.x - ux * (NODE_R[B.type] + 11), y2: B.y - uy * (NODE_R[B.type] + 11) };
  }
  return (
    <div className="graph-wrap">
      <svg viewBox="0 0 760 460" preserveAspectRatio="xMidYMid meet">
        <defs>
          <pattern id="tm-grid" width="28" height="28" patternUnits="userSpaceOnUse">
            <path d="M28 0 H0 V28" fill="none" stroke="#0f1a2e" strokeWidth="1" />
          </pattern>
          {[["ah-muted", "#8494b2"], ["ah-red", "#ff3b5c"], ["ah-amber", "#ffb020"]].map(([id, c]) => (
            <marker key={id} id={id} markerWidth="9" markerHeight="9" refX="7" refY="3.5" orient="auto" markerUnits="userSpaceOnUse">
              <path d="M0 0 L7 3.5 L0 7 Z" fill={c} />
            </marker>
          ))}
        </defs>
        <rect x="0" y="0" width="760" height="460" fill="url(#tm-grid)" />

        {/* column captions */}
        {[["AGENTS", COL.agent], ["TOOLS", COL.tool], ["DATA SOURCES", COL.data]].map(([t, x]) => (
          <text key={t} x={x} y="34" textAnchor="middle" fill="#4a5a78" style={{ fontSize: 11, fontFamily: "var(--font-mono)", letterSpacing: "1.5px" }}>{t}</text>
        ))}

        {/* edges */}
        {TM_EDGES.map((e, i) => {
          const s = seg(e), col = edgeColor(e), dim = dimEl(e.risk), hi = e.risk === "high" && e.kind !== "delegates";
          return (
            <line key={i} x1={s.x1} y1={s.y1} x2={s.x2} y2={s.y2} stroke={col} strokeWidth="1.6"
              strokeDasharray={DASH[e.kind]} strokeLinecap="round" markerEnd={`url(#${edgeMarker(e)})`}
              className={`gedge${dim ? " dim" : ""}${hi ? " edge-pulse" : ""}`} />
          );
        })}

        {/* nodes */}
        {Object.entries(TM_NODES).map(([id, n]) => {
          const sel = selected === id, dim = dimEl(n.risk);
          const ring = n.type === "tool" ? RISK_COLOR[n.risk] : TYPE_COLOR[n.type];
          const showGlow = sel || (n.type === "tool" && n.risk === "high");
          const W = 48, Hh = 36;
          return (
            <g key={id} className={`gnode${dim ? " dim" : ""}`} onClick={() => onSelect(sel ? null : id)}>
              {showGlow && n.type === "agent" && <circle cx={n.x} cy={n.y} r="30" fill={ring} opacity={sel ? 0.22 : 0.12} />}
              {showGlow && n.type === "tool" && <rect x={n.x - W / 2 - 8} y={n.y - Hh / 2 - 8} width={W + 16} height={Hh + 16} rx="16" fill={ring} opacity={sel ? 0.22 : 0.12} />}
              {showGlow && n.type === "data" && <ellipse cx={n.x} cy={n.y} rx="30" ry="24" fill={ring} opacity={sel ? 0.22 : 0.12} />}

              {n.type === "agent" && <>
                <circle cx={n.x} cy={n.y} r="22" fill="#1a2744" stroke={TYPE_COLOR.agent} strokeWidth={sel ? 2.6 : 2} />
                <Glyph cx={n.x} cy={n.y} size={20} d={ICON_USER_BODY} circle={[12, 8.5, 3.3]} />
              </>}
              {n.type === "tool" && <>
                <rect x={n.x - W / 2} y={n.y - Hh / 2} width={W} height={Hh} rx="8" fill="#0c1425" stroke={RISK_COLOR[n.risk]} strokeWidth={sel ? 2.6 : 2} />
                <Glyph cx={n.x} cy={n.y} size={18} d={ICON_WRENCH} />
              </>}
              {n.type === "data" && (() => {
                const rx = 21, ry = 6, top = n.y - 15, bot = n.y + 15;
                return <>
                  <path d={`M${n.x - rx} ${top} V${bot} A${rx} ${ry} 0 0 0 ${n.x + rx} ${bot} V${top}`} fill="#0c1425" stroke={TYPE_COLOR.data} strokeWidth={sel ? 2.6 : 2} />
                  <path d={`M${n.x - rx} ${n.y - 1} A${rx} ${ry} 0 0 0 ${n.x + rx} ${n.y - 1}`} fill="none" stroke={TYPE_COLOR.data} strokeWidth="1.4" opacity="0.55" />
                  <ellipse cx={n.x} cy={top} rx={rx} ry={ry} fill="#101b33" stroke={TYPE_COLOR.data} strokeWidth={sel ? 2.6 : 2} />
                </>;
              })()}

              <text x={n.x} y={n.y + (n.type === "tool" ? 36 : 42)} textAnchor="middle">{n.label}</text>
            </g>
          );
        })}
      </svg>

      {selected && (() => {
        const n = TM_NODES[selected];
        const c = n.type === "tool" ? RISK_COLOR[n.risk] : TYPE_COLOR[n.type];
        return (
          <div className="node-detail">
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <span className="section-label" style={{ margin: 0 }}>{n.sub}</span>
              <span style={{ width: 9, height: 9, borderRadius: 99, background: c }}></span>
            </div>
            <div className="mono" style={{ fontSize: 14, marginTop: 6 }}>{n.label}</div>
            <div className="kv"><span className="k">Type</span><span style={{ textTransform: "capitalize" }}>{n.type}</span></div>
            <div className="kv"><span className="k">Risk</span><span style={{ color: RISK_COLOR[n.risk], fontWeight: 600, textTransform: "uppercase" }}>{n.risk === "med" ? "medium" : n.risk}</span></div>
            <div className="kv"><span className="k">Edges</span><span>{TM_EDGES.filter((e) => e.a === selected || e.b === selected).length}</span></div>
          </div>
        );
      })()}

      <div className="glegend">
        <span><svg width="22" height="22" viewBox="0 0 24 24" style={{ overflow: "visible" }}><circle cx="12" cy="12" r="9" fill="#1a2744" stroke="#3b7bf7" strokeWidth="2" /><circle cx="12" cy="10.5" r="2.4" fill="none" stroke="#e8edf5" strokeWidth="1.4" /><path d="M7.5 16a4.5 4.5 0 0 1 9 0" fill="none" stroke="#e8edf5" strokeWidth="1.4" /></svg>Agent</span>
        <span><svg width="26" height="20" viewBox="0 0 26 20"><rect x="2" y="2" width="22" height="16" rx="4" fill="#0c1425" stroke="#00e5a0" strokeWidth="2" /></svg>Tool</span>
        <span><svg width="20" height="22" viewBox="0 0 20 22"><path d="M2 5 V17 A8 3 0 0 0 18 17 V5" fill="#0c1425" stroke="#7c5cfc" strokeWidth="2" /><ellipse cx="10" cy="5" rx="8" ry="3" fill="#101b33" stroke="#7c5cfc" strokeWidth="2" /></svg>Data source</span>
        <span style={{ marginLeft: 8 }}><span className="lg-line" style={{ borderColor: "#8494b2" }}></span>calls →</span>
        <span><span className="lg-line" style={{ borderColor: "#8494b2", borderTopStyle: "dashed" }}></span>accesses →</span>
        <span><span className="lg-line" style={{ borderColor: "#ffb020", borderTopStyle: "dotted" }}></span>delegates →</span>
        <span><span className="lg-line" style={{ borderColor: "#ff3b5c" }}></span>high-risk</span>
      </div>
    </div>
  );
}

// --- Attack paths ----------------------------------------------------------
const ATTACK_PATHS = [
  { rank: 1, risk: 8.5, chain: ["customer-support", "execute_sql", "customers_db"], threat: "SQL injection can access all customer records.", atlas: "AML.T0048", atlasName: "Prompt Injection to Tool Misuse", mitigation: "deny_sql_injection", enabled: true },
  { rank: 2, risk: 7.2, chain: ["data-analyst", "delete_record(*)", "orders_db"], threat: "Wildcard delete can wipe order history.", atlas: "AML.T0051", atlasName: "Excessive Agency", mitigation: "deny_wildcard_delete", enabled: true },
  { rank: 3, risk: 6.1, chain: ["customer-support", "agent-b", "execute_sql"], threat: "Multi-hop delegation bypasses direct agent policy.", atlas: "AML.T0049", atlasName: "Agent Chain Manipulation", mitigation: "trust_propagation", enabled: false }
];
function riskColor(r) { return r > 7 ? "#ff3b5c" : r >= 5 ? "#ffb020" : "#00e5a0"; }
function AttackPathTable() {
  const [open, setOpen] = useState(null);
  return (
    <div className="panel" style={{ paddingBottom: 6 }}>
      <div style={{ overflowX: "auto" }}>
        <table className="tbl">
          <thead><tr><th style={{ width: 54 }}>Risk</th><th>Path</th><th style={{ width: 104 }}>MITRE</th><th style={{ width: 120 }}>Status</th></tr></thead>
          <tbody>
            {ATTACK_PATHS.map((p, i) => (
              <React.Fragment key={p.rank}>
                <tr onClick={() => setOpen(open === i ? null : i)}>
                  <td><span style={{ fontWeight: 600, color: riskColor(p.risk) }}>{p.risk.toFixed(1)}</span></td>
                  <td className="mono" style={{ fontSize: 12.5, whiteSpace: "normal" }}>
                    {p.chain.map((h, j) => <span key={j}>{j > 0 && <span style={{ color: "var(--text-muted)" }}> → </span>}{h}</span>)}
                  </td>
                  <td><span className="atlas-tag">{p.atlas}</span></td>
                  <td><span className={`cov ${p.enabled ? "yes" : "no"}`}>{p.enabled ? "✓ Covered" : "⚠ Not covered"}</span></td>
                </tr>
                {open === i && (
                  <tr style={{ cursor: "default" }}>
                    <td colSpan={4} style={{ background: "var(--bg-surface-hover)" }}>
                      <div style={{ padding: "2px 2px 8px" }}>
                        <div style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.5, marginBottom: 8 }}>{p.threat}</div>
                        <div className="apath-row"><span className="atlas-tag">{p.atlas}</span><span className="muted" style={{ fontSize: 12 }}>{p.atlasName}</span></div>
                        <div className="apath-row" style={{ marginTop: 6 }}>
                          <Icon name="shield-check" size={14} style={{ color: p.enabled ? "#00e5a0" : "#ff3b5c" }} />
                          <span className="mono" style={{ fontSize: 12 }}>{p.mitigation}</span>
                          <span className={`cov ${p.enabled ? "yes" : "no"}`}>{p.enabled ? "ENABLED" : "NOT ENABLED"}</span>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// --- MITRE ATLAS coverage --------------------------------------------------
const ATLAS_TECHNIQUES = [
  { id: "AML.T0048", name: "Prompt Injection to Tool Misuse", covered: true },
  { id: "AML.T0049", name: "Agent Chain Manipulation", covered: false },
  { id: "AML.T0051", name: "Excessive Agency", covered: true },
  { id: "AML.T0053", name: "LLM Plugin Compromise", covered: true },
  { id: "AML.T0054", name: "LLM Jailbreak", covered: true },
  { id: "AML.T0057", name: "Data Exfiltration via Tool", covered: true },
  { id: "AML.T0024", name: "Exfiltration via ML Inference", covered: true },
  { id: "AML.T0061", name: "Unsafe Tool Output Handling", covered: false }
];
function MitreCoverage() {
  const covered = 8, total = 12, pct = Math.round(covered / total * 100);
  return (
    <div className="stack">
      <Panel title="MITRE ATLAS Coverage" sub={`${covered}/${total} techniques covered · ${pct}%`}>
        <div style={{ display: "flex", height: 8, borderRadius: 999, overflow: "hidden", border: "1px solid var(--border)", marginTop: 4 }}>
          <div style={{ width: `${pct}%`, background: "#00e5a0" }}></div>
          <div style={{ flex: 1, background: "#ff3b5c" }}></div>
        </div>
        <div style={{ marginTop: 16 }}>
          {ATLAS_TECHNIQUES.map((t) => (
            <div key={t.id} className="atlas-row">
              <span className="id">{t.id}</span>
              <span className="nm">{t.name}</span>
              <span className={`cov ${t.covered ? "yes" : "no"}`}>{t.covered ? "COVERED" : "UNCOVERED"}</span>
            </div>
          ))}
        </div>
      </Panel>
      <Panel pad={true} className="predictions">
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <Icon name="sparkles" size={22} style={{ color: "#4a5a78" }} />
          <div>
            <div className="panel-title">Threat Predictions</div>
            <div className="panel-sub">AI-powered threat prediction coming in Phase 3</div>
          </div>
        </div>
      </Panel>
    </div>
  );
}

// --- Page ------------------------------------------------------------------
function ThreatModeling() {
  const [tab, setTab] = useState("graph");
  const [selected, setSelected] = useState(null);
  const [highRiskOnly, setHighRiskOnly] = useState(false);

  return (
    <div className="page-enter">
      <PageHead title="Threat Modeling"
        actions={<div className="tabs">
          <button className={`tab${tab === "graph" ? " active" : ""}`} onClick={() => setTab("graph")}>Attack Graph</button>
          <button className={`tab${tab === "mitre" ? " active" : ""}`} onClick={() => setTab("mitre")}>MITRE Coverage</button>
        </div>} />

      {tab === "graph" && (
        <div className="stack">
          <div className="grid g3">
            <KPICard label="Attack Paths Detected" value={7} trend="2 critical · 3 medium" color="#ff3b5c" />
            <KPICard label="Highest Risk Score" value={8.5} trend="customer-support → execute_sql" color="#ffb020" />
            <KPICard label="Agents at Risk" value={3} trend="of 14 monitored" color="#3b7bf7" />
          </div>

          <div style={{ display: "flex", gap: 16, alignItems: "stretch", flexWrap: "wrap" }}>
            <div style={{ flex: "3 1 540px", minWidth: 0 }}>
              <Panel title="Attack-Path Graph" sub="Agents → tools → data sources · click a node"
                action={<span className="panel-sub">{Object.keys(TM_NODES).length} nodes · {TM_EDGES.length} edges</span>}>
                <ThreatGraphCanvas highRiskOnly={highRiskOnly} selected={selected} onSelect={setSelected} />
              </Panel>
            </div>
            <div style={{ flex: "2 1 360px", minWidth: 0 }}>
              <Panel title="Attack Paths" sub="Ranked by risk · click a row to expand">
                <AttackPathTable />
              </Panel>
            </div>
          </div>

          <Panel pad={true}>
            <div style={{ display: "flex", gap: 14, alignItems: "center", flexWrap: "wrap" }}>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <div className="input select-trigger" style={{ width: 160 }}><span className="muted">Agent Class</span><Icon name="chevron-down" /></div>
                <div className="input select-trigger" style={{ width: 140 }}><span className="muted">Risk Level</span><Icon name="chevron-down" /></div>
              </div>
              <div className={`switch${highRiskOnly ? " on" : ""}`} onClick={() => setHighRiskOnly((v) => !v)}>
                <span className="track"><span className="knob"></span></span>Show only high-risk paths
              </div>
              <div style={{ flex: 1 }}></div>
              <Button variant="primary" icon="refresh-cw">Recalculate Paths</Button>
              <Button variant="outline" icon="download">Export Report</Button>
            </div>
          </Panel>
        </div>
      )}

      {tab === "mitre" && <MitreCoverage />}
    </div>
  );
}

Object.assign(window, { ThreatModeling });
