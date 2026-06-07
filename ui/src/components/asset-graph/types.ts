// SPDX-License-Identifier: Apache-2.0

export interface AssetNode {
  id: string;
  type: "agent" | "tool" | "data" | "namespace";
  name: string;
  properties: {
    namespace?: string;
    agent_class?: string;
    spiffe_id?: string;
    trust_score?: number;
    risk_level?: "low" | "medium" | "high" | "critical";
    tool_call_count?: number;
    last_seen?: string;
  };
}

export interface AssetEdge {
  source: string;
  target: string;
  type: "calls" | "accesses" | "belongs_to" | "owns";
  weight: number;
  properties: {
    last_call?: string;
    decision_history?: { allow: number; block: number; escalate: number };
  };
}

export interface AssetGraphResponse {
  nodes: AssetNode[];
  edges: AssetEdge[];
}
