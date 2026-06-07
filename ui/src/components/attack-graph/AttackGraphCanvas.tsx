// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { useEffect, useRef } from "react";
import * as d3 from "d3";
import { attachZoom } from "../../lib/d3-helpers";
import type { AssetNode } from "../asset-graph/types";
import type { AttackPath } from "./types";

interface Props {
  paths: AttackPath[];
  nodes: AssetNode[];
  selectedPathId?: string;
  onSelectPath: (path: AttackPath) => void;
}

const PATH_COLORS = {
  would_block: "#00E5A0",
  would_allow: "#FF3B5C",
  no_policy: "#FFB020"
} as const;

const SEVERITY_COLORS = {
  low: "#888",
  medium: "#FFB020",
  high: "#FF7A1A",
  critical: "#FF3B5C"
} as const;

export function AttackGraphCanvas({ paths, nodes, selectedPathId, onSelectPath }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current || paths.length === 0) return;
    const svg = d3.select(svgRef.current);
    const width = svgRef.current.clientWidth || 800;
    const height = svgRef.current.clientHeight || 600;
    svg.selectAll("*").remove();

    const container = svg.append("g").attr("class", "zoom-container");
    attachZoom(svg as any, container as any);

    const nodeMap = new Map<string, AssetNode>();
    nodes.forEach((n) => nodeMap.set(n.id, { ...n }));

    const edges: Array<{
      source: string;
      target: string;
      path_id: string;
      policy_check: "would_block" | "would_allow" | "no_policy";
      severity: "low" | "medium" | "high" | "critical";
    }> = [];

    paths.forEach((path) => {
      const sequence = [path.source_id, ...path.steps.map((s) => s.node_id), path.target_id];
      sequence.forEach((id) => {
        if (!nodeMap.has(id)) {
          nodeMap.set(id, { id, type: "data", name: id, properties: {} });
        }
      });
      for (let i = 0; i < sequence.length - 1; i += 1) {
        const step = path.steps[i];
        edges.push({
          source: sequence[i],
          target: sequence[i + 1],
          path_id: path.path_id,
          policy_check: step?.policy_check || "no_policy",
          severity: path.severity
        });
      }
    });

    const simNodes = Array.from(nodeMap.values()).map((n) => ({ ...n }));

    const simulation = d3
      .forceSimulation(simNodes as any)
      .force("link", d3.forceLink(edges as any).id((d: any) => d.id).distance(120))
      .force("charge", d3.forceManyBody().strength(-500))
      .force(
        "x",
        d3
          .forceX((d: any) => {
            for (const p of paths) {
              if (d.id === p.source_id) return width * 0.1;
              if (d.id === p.target_id) return width * 0.9;
              const step = p.steps.find((s) => s.node_id === d.id);
              if (step) return width * (0.2 + (0.6 * step.step_num) / (p.steps.length + 1));
            }
            return width / 2;
          })
          .strength(0.4)
      )
      .force("y", d3.forceY(height / 2).strength(0.05))
      .force("collision", d3.forceCollide().radius(30));

    const link = container
      .append("g")
      .selectAll("line")
      .data(edges)
      .join("line")
      .attr("stroke", (d: any) => PATH_COLORS[d.policy_check as keyof typeof PATH_COLORS] || "#666")
      .attr("stroke-width", (d: any) => (d.path_id === selectedPathId ? 4 : 2))
      .attr("stroke-opacity", (d: any) => (d.path_id === selectedPathId ? 1 : 0.5))
      .style("cursor", "pointer")
      .on("click", (_: any, d: any) => {
        const p = paths.find((path) => path.path_id === d.path_id);
        if (p) onSelectPath(p);
      });

    const node = container.append("g").selectAll("g").data(simNodes).join("g").style("cursor", "pointer");

    node
      .append("circle")
      .attr("r", 12)
      .attr("fill", (d: any) => {
        const onPath = paths.find((p) => p.source_id === d.id || p.target_id === d.id || p.steps.some((s) => s.node_id === d.id));
        return onPath ? SEVERITY_COLORS[onPath.severity as keyof typeof SEVERITY_COLORS] : "#666";
      })
      .attr("stroke", "#111")
      .attr("stroke-width", 1.5);

    node
      .append("text")
      .text((d: any) => d.name || d.id)
      .attr("x", 16)
      .attr("y", 4)
      .attr("fill", "#FFF")
      .attr("font-size", "11px")
      .style("pointer-events", "none");

    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);
      node.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

    return () => {
      simulation.stop();
    };
  }, [paths, nodes, selectedPathId, onSelectPath]);

  return <svg ref={svgRef} style={{ width: "100%", height: "100%", minHeight: 600 }} />;
}
