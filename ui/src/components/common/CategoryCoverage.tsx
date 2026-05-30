import { Panel } from "./Panel";

const DEFAULT_SCORES = [
  { category: "OWASP LLM", score: 92 },
  { category: "Data Protection", score: 88 },
  { category: "Tool Safety", score: 74 },
  { category: "Rate Limiting", score: 63 },
  { category: "Trust", score: 81 }
];

export function CategoryCoverage({ data = DEFAULT_SCORES }: { data?: Array<{ category: string; score: number }> }) {
  const color = (s: number) => (s > 80 ? "#00e5a0" : s >= 60 ? "#ffb020" : "#ff3b5c");
  return (
    <Panel title="Policy Coverage by Category" sub="Strength of enforcement across risk categories">
      <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 4 }}>
        {data.map((c) => (
          <div key={c.category} style={{ display: "flex", alignItems: "center", gap: 12 }}>
            <span style={{ fontSize: 13, color: "var(--text-secondary)", width: 130, flex: "none" }}>
              {c.category}
            </span>
            <div style={{ flex: 1, height: 10, borderRadius: 3, background: "#1f1f1f", overflow: "hidden" }}>
              <div
                style={{
                  width: `${c.score}%`,
                  height: "100%",
                  background: color(c.score),
                  borderRadius: 3
                }}
              />
            </div>
            <span
              style={{
                fontSize: 13,
                fontWeight: 600,
                color: color(c.score),
                width: 28,
                textAlign: "right",
                flex: "none"
              }}
            >
              {c.score}
            </span>
          </div>
        ))}
      </div>
    </Panel>
  );
}
