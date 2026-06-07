// SPDX-License-Identifier: Apache-2.0

import type { AssetNode } from "../asset-graph/types";

export interface AttackStep {
  step_num: number;
  node_id: string;
  action: string;
  policy_check: "would_block" | "would_allow" | "no_policy";
}

export interface AttackPath {
  path_id: string;
  source_id: string;
  target_id: string;
  steps: AttackStep[];
  risk_score: number;
  severity: "low" | "medium" | "high" | "critical";
  mitre_techniques: string[];
  blocked_by_policy: boolean;
}

export interface AttackPathsResponse {
  paths: AttackPath[];
  nodes: AssetNode[];
}
