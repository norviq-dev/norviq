// SPDX-License-Identifier: Apache-2.0

import * as d3 from "d3";

export const NODE_COLORS = {
  agent: "#7C5CFC",
  tool: "#00E5A0",
  data: "#FFB020",
  namespace: "#666666"
} as const;

export const NODE_RADIUS = {
  agent: 14,
  tool: 10,
  data: 8,
  namespace: 16
} as const;

// Asset Graph palette. Distinct 4-step risk gradient: slate → yellow → amber → red. High is
// AMBER, clearly different from the red Critical.
export const RISK_COLORS = {
  low: "#6e6e6e",
  medium: "#FFCC33",
  high: "#FF9500",
  critical: "#FF3B5C"
} as const;

export const DECISION_COLORS = {
  allow: "#00E5A0",
  mixed: "#FFB020",
  blocked: "#FF3B5C"
} as const;

// Namespace hull palette (mapped to real namespaces by sorted index).
export const NS_HULL_COLORS = ["#5aa0ff", "#f78fb3", "#b58cff", "#f5b342", "#7ce0c3", "#ff9d76", "#9db8ff", "#f2c14e"] as const;

export function edgeColor(h?: { allow: number; block: number; escalate: number }): string {
  if (!h) return "#444";
  const total = h.allow + h.block + h.escalate;
  if (total === 0) return "#444";
  const blockRatio = h.block / total;
  if (blockRatio > 0.5) return "#FF3B5C";
  if (blockRatio > 0.1) return "#FFB020";
  return "#00E5A0";
}


export function timeAgo(iso?: string): string {
  if (!iso) return "-";
  const ms = Date.now() - new Date(iso).getTime();
  const min = Math.floor(ms / 60000);
  if (min < 1) return "just now";
  if (min < 60) return `${min} min ago`;
  if (min < 1440) return `${Math.floor(min / 60)} hr ago`;
  return `${Math.floor(min / 1440)} days ago`;
}
