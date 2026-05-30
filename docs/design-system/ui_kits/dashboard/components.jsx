// ============================================================================
// NORVIQ UI KIT — components.jsx
// Shared primitives: Icon, Pill (decision/trust), KPICard, Button, Panel,
// Sidebar, Header, DataTable. Exported to window for the page scripts.
// ============================================================================
const { useState, useEffect, useRef, useMemo } = React;

// --- Lucide icon wrapper (React-safe: manages its own inner DOM) -----------
function Icon({ name, size = 16, className, style }) {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current;
    if (!el || !window.lucide) return;
    el.innerHTML = `<i data-lucide="${name}"></i>`;
    window.lucide.createIcons();
    const svg = el.querySelector("svg");
    if (svg) { svg.setAttribute("width", size); svg.setAttribute("height", size); }
  }, [name, size]);
  return <span ref={ref} className={className} style={{ display: "inline-flex", alignItems: "center", ...style }} />;
}

// --- Decision + trust pills ------------------------------------------------
const DECISION_STYLE = {
  allow:    { background: "#00e5a015", color: "#00e5a0", borderColor: "#00e5a030" },
  block:    { background: "#ff3b5c15", color: "#ff3b5c", borderColor: "#ff3b5c30" },
  escalate: { background: "#ffb02015", color: "#ffb020", borderColor: "#ffb02030" },
  audit:    { background: "#7c5cfc15", color: "#7c5cfc", borderColor: "#7c5cfc30" }
};
const TRUST_COLOR = { high: "#00e5a0", medium: "#ffb020", low: "#ff3b5c", frozen: "#4a5a78" };

function DecisionBadge({ decision }) {
  return <span className="pill hoverable" style={DECISION_STYLE[decision]}>{decision}</span>;
}
function TrustBadge({ category, pulse }) {
  const c = TRUST_COLOR[category] || TRUST_COLOR.frozen;
  return <span className={`pill${pulse ? " pulse-low" : ""}`} style={{ color: c, borderColor: c + "40" }}>{category}</span>;
}

// --- Button ----------------------------------------------------------------
function Button({ variant = "primary", size, icon, children, className = "", ...props }) {
  return (
    <button className={`btn btn-${variant}${size === "sm" ? " btn-sm" : ""}${className ? " " + className : ""}`} {...props}>
      {icon && <Icon name={icon} size={15} />}
      {children}
    </button>
  );
}

// --- Panel -----------------------------------------------------------------
function Panel({ title, sub, action, pad = true, className = "", style, children }) {
  return (
    <div className={`panel ${pad ? "panel-pad" : ""} ${className}`} style={style}>
      {(title || action) && (
        <div className="panel-head">
          <div>
            <div className="panel-title">{title}</div>
            {sub && <div className="panel-sub">{sub}</div>}
          </div>
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

// --- KPI card --------------------------------------------------------------
function useCountUp(value, ms = 500) {
  const [v, setV] = useState(0);
  useEffect(() => {
    let raf; const start = performance.now();
    const tick = (now) => {
      const p = Math.min((now - start) / ms, 1);
      setV(Math.round(value * p));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);
  return v;
}
function KPICard({ label, value, trend, color = "var(--accent)" }) {
  const display = useCountUp(value);
  return (
    <div className="panel kpi" style={{ boxShadow: `0 0 20px ${color}20` }}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{display.toLocaleString()}</div>
      <div className="kpi-trend" style={{ color }}>{trend}</div>
    </div>
  );
}

// --- Brand mark (inline SVG, tints via currentColor) -----------------------
function NorviqMark({ size = 22, style }) {
  return (
    <svg viewBox="0 0 166 200" width={size * 0.83} height={size} fill="currentColor" style={style} aria-label="Norviq">
      <path d="M0 0 L77.5 72.3 L77.5 200 L74.3 197.2 L57.3 181 L57.3 87.4 L0 34.4 L0 0.4 Z" />
      <path d="M165.6 0 L166 34 L108.3 87.4 L108.3 180.6 L88.1 200 L88.1 72.3 L165.2 0.4 Z" />
    </svg>
  );
}

// --- Page header (title + subtitle + actions, rendered inside each page) ---
function PageHead({ title, subtitle, actions }) {
  return (
    <div className="page-head">
      <div>
        <h1 className="page-title">{title}</h1>
        {subtitle && <div className="page-sub">{subtitle}</div>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  );
}

// --- Sidebar (dual rail: 48px icon rail + sectioned panel) -----------------
const NAV_SECTIONS = [
  { id: "monitoring", label: "Monitoring", items: [
    { id: "dashboard", label: "Dashboard", icon: "layout-dashboard" },
    { id: "audit",     label: "Audit Log", icon: "bar-chart-3" },
    { id: "agents",    label: "Agents",    icon: "users" }
  ]},
  { id: "enforcement", label: "Enforcement", items: [
    { id: "policies",  label: "Policies",  icon: "shield-check" },
    { id: "threats",   label: "Threats",   icon: "network" }
  ]}
];
const SETTINGS_ITEM = { id: "settings", label: "Settings", icon: "settings" };
const PAGE_SECTION = { dashboard: "monitoring", audit: "monitoring", agents: "monitoring", policies: "enforcement", threats: "enforcement", settings: "settings" };
const RAIL = [
  { icon: "shield", section: "enforcement", go: "policies", title: "Enforcement" },
  { icon: "bar-chart-3", section: "monitoring", go: "dashboard", title: "Monitoring" },
  { icon: "settings", section: "settings", go: "settings", title: "Settings" }
];

function Sidebar({ page, onNavigate }) {
  const section = PAGE_SECTION[page];
  const NavItem = (n) => (
    <button key={n.id} className={`sb-link${page === n.id ? " active" : ""}`} onClick={() => onNavigate(n.id)}>
      <Icon name={n.icon} size={16} />
      <span>{n.label}</span>
    </button>
  );
  return (
    <aside className="sidebar2">
      <div className="icon-rail">
        <div className="rail-top">
          <div className="rail-logo"><NorviqMark size={22} style={{ color: "var(--text-primary)" }} /></div>
          {RAIL.map((r) => (
            <button key={r.icon} className={`rail-icon${section === r.section ? " active" : ""}`} title={r.title} onClick={() => onNavigate(r.go)}>
              <Icon name={r.icon} size={18} />
            </button>
          ))}
        </div>
        <div className="rail-bottom">
          {["circle-help", "message-circle", "book-open"].map((ic) => (
            <button key={ic} className="rail-icon muted-rail" title={ic}><Icon name={ic} size={17} /></button>
          ))}
        </div>
      </div>
      <div className="sb-panel">
        <div className="sb-brand">NORVIQ SECURITY</div>
        <nav className="sb-nav">
          {NAV_SECTIONS.map((sec) => (
            <div key={sec.id} className="nav-group">
              <div className="nav-section">{sec.label}</div>
              {sec.items.map(NavItem)}
            </div>
          ))}
          <div className="nav-group" style={{ marginTop: 4 }}>{NavItem(SETTINGS_ITEM)}</div>
        </nav>
        <div className="sb-foot">
          © 2026 Norviq Contributors<br />All rights reserved.<br /><span style={{ color: "var(--text-muted)" }}>Version 0.1.0</span>
        </div>
      </div>
    </aside>
  );
}

// --- Top bar: cluster selector · search · bell · user menu -----------------
const CLUSTERS = ["production-aks", "staging-aks", "dev-aks"];
const NS_BY_CLUSTER = {
  "production-aks": ["chatbot-prod", "payments", "analytics", "platform"],
  "staging-aks": ["staging-default", "qa"],
  "dev-aks": ["dev-default"]
};
const PAGE_TITLE = {
  dashboard: "Overview", policies: "Policy Catalog", audit: "Audit Log",
  agents: "Agent Monitor", threats: "Threat Modeling", settings: "Settings"
};

function Header({ cluster, namespace, onSelectCluster, onSelectNamespace }) {
  const [open, setOpen] = useState(null); // "cluster" | "user" | null
  const close = () => setOpen(null);
  return (
    <header className="topbar">
      <div className="tb-left">
        <button className="cluster-sel" onClick={() => setOpen(open === "cluster" ? null : "cluster")}>
          <Icon name="box" size={15} style={{ color: "var(--accent)" }} />
          <span className="mono">{cluster} / <span style={{ color: "var(--text-primary)" }}>{namespace}</span></span>
          <Icon name="chevron-down" size={14} style={{ color: "var(--text-secondary)" }} />
        </button>
        {open === "cluster" && (
          <div className="dropdown cluster-dd">
            <div className="cluster-col">
              <div className="dd-head">CLUSTERS</div>
              {CLUSTERS.map((c) => (
                <button key={c} className={`dd-item${c === cluster ? " sel" : ""}`} onClick={() => { onSelectCluster(c); }}>
                  <span>{c}</span>{c === cluster && <Icon name="check" size={14} style={{ color: "var(--allow)" }} />}
                </button>
              ))}
            </div>
            <div className="cluster-col" style={{ borderLeft: "1px solid var(--border)" }}>
              <div className="dd-head">NAMESPACES</div>
              {(NS_BY_CLUSTER[cluster] || []).map((ns) => (
                <button key={ns} className={`dd-item${ns === namespace ? " sel" : ""}`} onClick={() => { onSelectNamespace(ns); close(); }}>
                  <span>{ns}</span>{ns === namespace && <Icon name="check" size={14} style={{ color: "var(--allow)" }} />}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      <div className="tb-search">
        <Icon name="search" size={14} style={{ color: "var(--text-secondary)" }} />
        <span style={{ flex: 1 }}>Search tools, agents, rules…</span>
        <span className="kbd">⌘K</span>
      </div>

      <div className="tb-right">
        <button className="icon-btn" title="Alerts"><Icon name="bell" size={18} /><span className="bell-badge">3</span></button>
        <button className="avatar" onClick={() => setOpen(open === "user" ? null : "user")}>SP</button>
        {open === "user" && (
          <div className="dropdown user-dd">
            <div className="user-head">
              <div style={{ fontSize: 14, fontWeight: 500, color: "var(--text-primary)" }}>Santosh Puppala</div>
              <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>admin</div>
            </div>
            <div className="dd-divider"></div>
            <button className="dd-item"><Icon name="user" size={14} /> Account Settings</button>
            <button className="dd-item"><Icon name="key" size={14} /> API Keys</button>
            <button className="dd-item"><Icon name="external-link" size={14} /> Documentation</button>
            <div className="dd-divider"></div>
            <button className="dd-item logout"><Icon name="log-out" size={14} /> Logout</button>
          </div>
        )}
      </div>

      {open && <div className="dd-catch" onClick={close}></div>}
    </header>
  );
}

// --- DataTable -------------------------------------------------------------
function DataTable({ columns, rows, onRowClick, selectedKey, rowKey, filterable = true, placeholder = "Filter rows…" }) {
  const [q, setQ] = useState("");
  const filtered = useMemo(() => {
    if (!q) return rows;
    const needle = q.toLowerCase();
    return rows.filter((r) => JSON.stringify(r).toLowerCase().includes(needle));
  }, [q, rows]);
  return (
    <div className="panel" style={{ paddingBottom: 6 }}>
      {filterable && (
        <div className="tbl-toolbar">
          <input className="input" placeholder={placeholder} value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      )}
      <div style={{ overflowX: "auto", marginTop: filterable ? 12 : 0 }}>
        <table className="tbl">
          <thead><tr>{columns.map((c) => <th key={c.key} style={c.thStyle} title={c.thTitle}>{c.title}</th>)}</tr></thead>
          <tbody>
            {filtered.map((row, i) => {
              const key = rowKey ? row[rowKey] : i;
              return (
                <tr key={key} className={selectedKey != null && selectedKey === key ? "selected" : ""} onClick={() => onRowClick && onRowClick(row)}>
                  {columns.map((c) => (
                    <td key={c.key} style={c.tdStyle}>{c.render ? c.render(row[c.key], row) : (row[c.key] != null ? String(row[c.key]) : "—")}</td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

Object.assign(window, {
  Icon, NorviqMark, DecisionBadge, TrustBadge, Button, Panel, KPICard, useCountUp, PageHead,
  Sidebar, Header, DataTable, NAV_SECTIONS, PAGE_TITLE, PAGE_SECTION, DECISION_STYLE, TRUST_COLOR,
  CLUSTERS, NS_BY_CLUSTER
});
