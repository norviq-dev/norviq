// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Asset Graph filter bar: custom dark dropdown menus (Namespace,
// Agent class, Cluster — the Cluster menu exists ONLY in a multi-cluster install via the existing
// fleetEnabled signal — and Range), a node-name search, and Type / Risk chips. Single-select menus
// that close on outside click (the page renders the click-away overlay via onCloseMenus).

import { NODE_COLORS, RISK_COLORS } from "../../lib/d3-helpers";

export type TypeKey = "agent" | "tool" | "data";
export type RiskKey = "low" | "medium" | "high" | "critical";

export interface DropdownOption {
  value: string;
  label: string;
}

export interface DropdownSpec {
  key: string;
  title: string;
  value: string;
  options: DropdownOption[];
  onSelect: (value: string) => void;
}

interface Props {
  dropdowns: DropdownSpec[];
  openMenu: string | null;
  onToggleMenu: (key: string) => void;
  search: string;
  onSearch: (value: string) => void;
  types: Record<TypeKey, boolean>;
  onToggleType: (key: TypeKey) => void;
  risks: Record<RiskKey, boolean>;
  onToggleRisk: (key: RiskKey) => void;
}

const TYPE_META: Array<{ key: TypeKey; label: string; dot: string }> = [
  { key: "agent", label: "Agent", dot: NODE_COLORS.agent },
  { key: "tool", label: "Tool", dot: NODE_COLORS.tool },
  { key: "data", label: "Data", dot: NODE_COLORS.data }
];
const RISK_META: Array<{ key: RiskKey; label: string; dot: string }> = [
  { key: "low", label: "Low", dot: RISK_COLORS.low },
  { key: "medium", label: "Medium", dot: RISK_COLORS.medium },
  { key: "high", label: "High", dot: RISK_COLORS.high },
  { key: "critical", label: "Critical", dot: RISK_COLORS.critical }
];

function Chip({ on, dot, label, round, onClick }: { on: boolean; dot: string; label: string; round?: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={on}
      style={{
        display: "inline-flex", alignItems: "center", gap: 7, height: 30, padding: "0 11px", borderRadius: 8,
        border: `1px solid ${on ? "var(--graph-border)" : "var(--graph-border-soft)"}`, background: on ? "var(--bg-graph-panel)" : "transparent",
        color: on ? "#e8edf5" : "#6e6e6e", fontFamily: "inherit", fontSize: 12.5, fontWeight: 600,
        cursor: "pointer", transition: "120ms ease"
      }}
    >
      <span style={{ width: round ? 9 : 7, height: round ? 9 : 7, borderRadius: round ? "50%" : 2, background: on ? dot : "#3a4252" }} />
      {label}
    </button>
  );
}

export function AssetGraphFilters({
  dropdowns, openMenu, onToggleMenu, search, onSearch, types, onToggleType, risks, onToggleRisk
}: Props) {
  return (
    <div>
      {/* dropdown row */}
      <div style={{ display: "flex", alignItems: "flex-end", gap: 14, flexWrap: "wrap", padding: "14px 20px 12px", borderBottom: "1px solid var(--graph-border-soft)" }}>
        {dropdowns.map((d) => {
          const cur = d.options.find((o) => o.value === d.value) ?? d.options[0];
          const open = openMenu === d.key;
          return (
            <div key={d.key} data-ag-menu style={{ position: "relative", display: "flex", flexDirection: "column", gap: 5 }}>
              <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.08em", color: "#6e6e6e", textTransform: "uppercase", paddingLeft: 2 }}>
                {d.title}
              </span>
              <button
                type="button"
                onClick={() => onToggleMenu(d.key)}
                aria-haspopup="listbox"
                aria-expanded={open}
                aria-label={d.title}
                style={{
                  display: "flex", alignItems: "center", gap: 10, height: 34, padding: "0 11px", minWidth: 152,
                  background: "var(--bg-graph-card)", border: `1px solid ${open ? "#00e5a0" : "var(--graph-border-soft)"}`, borderRadius: 9,
                  color: "#e8edf5", fontFamily: "inherit", fontSize: 13, fontWeight: 500, cursor: "pointer"
                }}
              >
                <span style={{ flex: 1, textAlign: "left", whiteSpace: "nowrap" }}>{cur?.label}</span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#5b6577" strokeWidth="2"><path d="M6 9l6 6 6-6" /></svg>
              </button>
              {open && (
                <div
                  role="listbox"
                  aria-label={d.title}
                  style={{
                    position: "absolute", top: 62, left: 0, zIndex: 50, minWidth: 190, padding: 5,
                    background: "var(--bg-graph-card)", border: "1px solid var(--graph-border)", borderRadius: 10,
                    boxShadow: "0 18px 40px -14px rgba(0,0,0,0.8)"
                  }}
                >
                  {d.options.map((o) => (
                    <div
                      key={o.value}
                      role="option"
                      aria-selected={o.value === d.value}
                      onClick={() => d.onSelect(o.value)}
                      style={{
                        display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10,
                        padding: "8px 10px", borderRadius: 7, fontSize: 13,
                        color: o.value === d.value ? "#e8edf5" : "#a0a0a0", cursor: "pointer"
                      }}
                    >
                      <span>{o.label}</span>
                      {o.value === d.value && <span style={{ color: "#00e5a0", fontWeight: 700 }}>✓</span>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* search + chips row */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", padding: "14px 20px", borderBottom: "1px solid var(--graph-border-soft)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, height: 34, padding: "0 12px", background: "var(--bg-graph-card)", border: "1px solid var(--graph-border-soft)", borderRadius: 9, width: 210 }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#6e6e6e" strokeWidth="1.8"><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></svg>
          <input
            value={search}
            onChange={(e) => onSearch(e.target.value)}
            placeholder="Search node name"
            aria-label="Search node name"
            style={{ flex: 1, minWidth: 0, background: "transparent", border: "none", outline: "none", color: "#e8edf5", fontFamily: "inherit", fontSize: 13 }}
          />
        </div>
        <div style={{ width: 1, height: 22, background: "var(--graph-border-soft)" }} />
        <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.06em", color: "#6e6e6e" }}>TYPE</span>
        <div style={{ display: "flex", gap: 7 }}>
          {TYPE_META.map((m) => (
            <Chip key={m.key} on={types[m.key]} dot={m.dot} label={m.label} round onClick={() => onToggleType(m.key)} />
          ))}
        </div>
        <div style={{ width: 1, height: 22, background: "var(--graph-border-soft)" }} />
        <span style={{ fontSize: 11, fontWeight: 600, letterSpacing: "0.06em", color: "#6e6e6e" }}>RISK</span>
        <div style={{ display: "flex", gap: 7 }}>
          {RISK_META.map((m) => (
            <Chip key={m.key} on={risks[m.key]} dot={m.dot} label={m.label} onClick={() => onToggleRisk(m.key)} />
          ))}
        </div>
      </div>
    </div>
  );
}
