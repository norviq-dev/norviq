import { Link } from "react-router-dom";
import { timeAgo } from "../../lib/d3-helpers";
import type { AssetNode } from "./types";

type Props = { node: AssetNode; onClose: () => void };

function trustCategory(score?: number): string {
  if (score === undefined) return "-";
  if (score >= 0.75) return "high";
  if (score >= 0.5) return "medium";
  return "low";
}

export function AssetNodeDetail({ node, onClose }: Props) {
  const riskColor = node.properties.risk_level === "critical" || node.properties.risk_level === "high" ? "#FF3B5C" : "#DDD";
  return (
    <aside style={{ border: "1px solid #333", borderRadius: 8, padding: 12 }}>
      <button onClick={onClose}>x</button>
      <div>{node.type.toUpperCase()}</div>
      <h3>{node.name}</h3>
      {node.properties.trust_score !== undefined && <div>{node.properties.trust_score.toFixed(2)}</div>}
      {node.properties.trust_score !== undefined && <div>{trustCategory(node.properties.trust_score)}</div>}
      {node.properties.tool_call_count !== undefined && <div>{node.properties.tool_call_count}</div>}
      {node.properties.risk_level && <div style={{ color: riskColor }}>{node.properties.risk_level}</div>}
      {node.properties.spiffe_id && (
        <div>
          <strong>SPIFFE</strong> {node.properties.spiffe_id}
        </div>
      )}
      {node.properties.last_seen && <div>Last seen: {timeAgo(node.properties.last_seen)}</div>}
      {node.properties.spiffe_id && <Link to={`/audit?spiffe_id=${encodeURIComponent(node.properties.spiffe_id)}`}>View in Audit Log</Link>}
    </aside>
  );
}
