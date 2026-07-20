// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Asset Graph legend: floating glass card inside the canvas — node
// types, edge decisions, and risk rings. `side` flips it away from the inspector.

import { NODE_COLORS, RISK_COLORS } from "../../lib/d3-helpers";

const item: React.CSSProperties = { display: "flex", alignItems: "center", gap: 7 };
const label: React.CSSProperties = { fontSize: 11.5, color: "#b8c2d6" };

export function AssetGraphLegend({ side = "left" }: { side?: "left" | "right" }) {
  return (
    <div
      style={{
        position: "absolute", bottom: 16,
        left: side === "left" ? 16 : "auto", right: side === "left" ? "auto" : 16,
        display: "flex", flexDirection: "column", gap: 10, padding: "13px 15px",
        background: "rgba(20,20,20,0.85)", backdropFilter: "blur(10px)",
        border: "1px solid var(--graph-border-soft)", borderRadius: 11, zIndex: 5
      }}
    >
      <div style={{ display: "flex", gap: 16 }}>
        <div style={item}><span style={{ width: 11, height: 11, borderRadius: "50%", background: NODE_COLORS.agent }} /><span style={label}>Agent</span></div>
        <div style={item}><span style={{ width: 11, height: 11, borderRadius: "50%", background: NODE_COLORS.tool }} /><span style={label}>Tool</span></div>
        <div style={item}><span style={{ width: 11, height: 11, borderRadius: "50%", background: NODE_COLORS.data }} /><span style={label}>Data</span></div>
      </div>
      <div style={{ height: 1, background: "var(--graph-border-soft)" }} />
      <div style={{ display: "flex", gap: 16, flexWrap: "wrap" }}>
        <div style={item}><span style={{ width: 16, height: 2.5, borderRadius: 2, background: "#33405c" }} /><span style={label}>Call</span></div>
        <div style={item}><span style={{ width: 16, height: 2.5, borderRadius: 2, background: RISK_COLORS.critical }} /><span style={label}>Blocked</span></div>
        <div style={item}><span style={{ width: 12, height: 12, borderRadius: "50%", border: `1.7px solid ${RISK_COLORS.medium}` }} /><span style={label}>Med</span></div>
        <div style={item}><span style={{ width: 12, height: 12, borderRadius: "50%", border: `1.7px solid ${RISK_COLORS.high}` }} /><span style={label}>High</span></div>
        <div style={item}><span style={{ width: 12, height: 12, borderRadius: "50%", border: `1.7px solid ${RISK_COLORS.critical}`, boxShadow: "0 0 0 3px #FF3B5C33" }} /><span style={{ fontSize: 11.5, color: "#ff7088", fontWeight: 600 }}>Critical</span></div>
      </div>
    </div>
  );
}
