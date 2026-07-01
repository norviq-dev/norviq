// SPDX-License-Identifier: Apache-2.0
// F-32: legend for the attack graph — node color = path severity, edge color = policy decision. Keeps the colors
// in sync with AttackGraphCanvas (PATH_COLORS / SEVERITY_COLORS).
const NODE_SEVERITY: [string, string][] = [
  ["critical", "#FF3B5C"],
  ["high", "#FF7A1A"],
  ["medium", "#FFB020"],
  ["low", "#888"],
  ["off-path", "#666"]
];
const EDGE_DECISION: [string, string][] = [
  ["would block", "#00E5A0"],
  ["would allow", "#FF3B5C"],
  ["no policy", "#FFB020"]
];

function Swatch({ color, shape }: { color: string; shape: "dot" | "line" }) {
  return shape === "dot" ? (
    <span style={{ width: 10, height: 10, borderRadius: 5, background: color, display: "inline-block" }} />
  ) : (
    <span style={{ width: 16, height: 3, background: color, display: "inline-block", borderRadius: 2 }} />
  );
}

export function AttackGraphLegend() {
  return (
    <div
      style={{
        display: "flex",
        gap: 18,
        flexWrap: "wrap",
        fontSize: 12,
        color: "var(--text-secondary)",
        marginBottom: 8
      }}
    >
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span style={{ color: "var(--text-primary)" }}>Node (severity):</span>
        {NODE_SEVERITY.map(([label, color]) => (
          <span key={label} style={{ display: "inline-flex", gap: 4, alignItems: "center" }}>
            <Swatch color={color} shape="dot" /> {label}
          </span>
        ))}
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
        <span style={{ color: "var(--text-primary)" }}>Edge (decision):</span>
        {EDGE_DECISION.map(([label, color]) => (
          <span key={label} style={{ display: "inline-flex", gap: 4, alignItems: "center" }}>
            <Swatch color={color} shape="line" /> {label}
          </span>
        ))}
      </div>
    </div>
  );
}

export default AttackGraphLegend;
