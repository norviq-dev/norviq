// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Attack Graph KEY strip: the floating legend over the kill-chain canvas.
// Node kinds (Agent/Tool/Data), the sensitive-asset diamond, and the per-hop decision line colors —
// all pulled from the shared palette so nothing drifts from the canvas.

import { KIND_COLORS, STEP_DECISION_COLORS } from "./constants";

export function AttackGraphLegend() {
  return (
    <div style={{ position: "absolute", left: 20, right: 20, bottom: 16, display: "flex", alignItems: "center", flexWrap: "wrap", gap: "8px 14px", padding: "10px 14px", background: "rgba(20,20,20,0.86)", backdropFilter: "blur(10px)", border: "1px solid var(--graph-border-soft)", borderRadius: 11, zIndex: 4 }}>
      <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.12em", color: "#6e6e6e" }}>KEY</span>
      <Dot color={KIND_COLORS.agent} label="Agent" />
      <Dot color={KIND_COLORS.tool} label="Tool" />
      <Dot color={KIND_COLORS.data} label="Data" />
      <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
        <span style={{ color: "#ff8fa3", fontSize: 12, lineHeight: 1 }}>⬥</span>
        <span style={{ fontSize: 11.5, color: "#ff9fb0" }}>Sensitive</span>
      </div>
      <div style={{ width: 1, height: 16, background: "var(--graph-border-soft)" }} />
      <Line color={STEP_DECISION_COLORS.allow} label="Allowed" labelColor="#b8c2d6" />
      <Line color={STEP_DECISION_COLORS.mixed} label="Partial" labelColor="#b8c2d6" />
      <Line color={STEP_DECISION_COLORS.would_block} label="Would block · monitor" labelColor="#b8c2d6" dashed />
      <Line color={STEP_DECISION_COLORS.block} label="Blocked" labelColor="#ff7088" dashed />
    </div>
  );
}

function Dot({ color, label }: { color: string; label: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
      <span style={{ width: 11, height: 11, borderRadius: "50%", background: color }} />
      <span style={{ fontSize: 11.5, color: "#b8c2d6" }}>{label}</span>
    </div>
  );
}

function Line({ color, label, labelColor, dashed }: { color: string; label: string; labelColor: string; dashed?: boolean }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
      {dashed ? (
        // Dashed swatch matches the canvas: a stopped hop (enforced block OR monitor would-block) dashes.
        <span style={{ display: "flex", gap: 2.5 }}>
          <span style={{ width: 6, height: 2.5, borderRadius: 2, background: color }} />
          <span style={{ width: 6, height: 2.5, borderRadius: 2, background: color }} />
        </span>
      ) : (
        <span style={{ width: 16, height: 2.5, borderRadius: 2, background: color }} />
      )}
      <span style={{ fontSize: 11.5, color: labelColor }}>{label}</span>
    </div>
  );
}

export default AttackGraphLegend;
