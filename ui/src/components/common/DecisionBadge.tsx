import { CSSProperties } from "react";

export type Decision = "allow" | "block" | "escalate" | "audit";

const STYLE_MAP: Record<Decision, CSSProperties> = {
  allow: { background: "#00E5A015", color: "#00E5A0", borderColor: "#00E5A030" },
  block: { background: "#FF3B5C15", color: "#FF3B5C", borderColor: "#FF3B5C30" },
  escalate: { background: "#FFB02015", color: "#FFB020", borderColor: "#FFB02030" },
  audit: { background: "#7C5CFC15", color: "#7C5CFC", borderColor: "#7C5CFC30" }
};

export function DecisionBadge({ decision }: { decision: Decision }) {
  const style = STYLE_MAP[decision] ?? STYLE_MAP.audit;
  return (
    <span className="pill hoverable" style={style}>
      {decision}
    </span>
  );
}
