export type TrustCategory = "high" | "medium" | "low" | "frozen";

const TRUST_COLOR: Record<TrustCategory, string> = {
  high: "#00e5a0",
  medium: "#ffb020",
  low: "#ff3b5c",
  frozen: "#666666"
};

export function trustCategory(score: number): TrustCategory {
  if (score >= 0.7) return "high";
  if (score >= 0.4) return "medium";
  if (score > 0) return "low";
  return "frozen";
}

// Neither a band nor a freeze: "unscored" (a lifted freeze, before the agent's next call) or a category the
// console does not know. Shown as itself, in a neutral colour. It used to fall back to "frozen", so an agent
// whose freeze had just been lifted was labelled frozen.
const OTHER_COLOR = "#8a8f98";

export function TrustBadge({ category, pulse = false }: { category: string; pulse?: boolean }) {
  const lower = (category ?? "").toLowerCase();
  const known = lower in TRUST_COLOR;
  const label = known ? lower : lower || "unknown";
  const color = known ? TRUST_COLOR[lower as TrustCategory] : OTHER_COLOR;
  return (
    <span className={`pill${pulse ? " pulse-low" : ""}`} style={{ color, borderColor: `${color}40` }}>
      {label}
    </span>
  );
}
