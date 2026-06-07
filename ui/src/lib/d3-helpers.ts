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

export function edgeColor(h?: { allow: number; block: number; escalate: number }): string {
  if (!h) return "#444";
  const total = h.allow + h.block + h.escalate;
  if (total === 0) return "#444";
  const blockRatio = h.block / total;
  if (blockRatio > 0.5) return "#FF3B5C";
  if (blockRatio > 0.1) return "#FFB020";
  return "#00E5A0";
}

export function attachZoom(svg: d3.Selection<SVGSVGElement, unknown, null, undefined>, container: d3.Selection<SVGGElement, unknown, null, undefined>): void {
  svg.call(
    d3.zoom<SVGSVGElement, unknown>().scaleExtent([0.2, 4]).on("zoom", (event) => {
      container.attr("transform", event.transform.toString());
    })
  );
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
