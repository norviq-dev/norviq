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

export function TrustBadge({ category, pulse = false }: { category: string; pulse?: boolean }) {
  const key = (category?.toLowerCase() as TrustCategory) in TRUST_COLOR
    ? (category.toLowerCase() as TrustCategory)
    : "frozen";
  const color = TRUST_COLOR[key];
  return (
    <span className={`pill${pulse ? " pulse-low" : ""}`} style={{ color, borderColor: `${color}40` }}>
      {key}
    </span>
  );
}
