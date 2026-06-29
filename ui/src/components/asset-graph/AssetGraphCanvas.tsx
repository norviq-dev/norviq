// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { useEffect, useRef } from "react";
import * as d3 from "d3";
import { NODE_COLORS, NODE_RADIUS, edgeColor, attachZoom } from "../../lib/d3-helpers";
import type { AssetNode, AssetEdge } from "./types";

interface Props {
  nodes: AssetNode[];
  edges: AssetEdge[];
  selectedNodeId?: string;
  onSelectNode: (node: AssetNode) => void;
}

export function AssetGraphCanvas({ nodes, edges, selectedNodeId, onSelectNode }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    if (!svgRef.current) return;
    const svg = d3.select(svgRef.current);
    const width = svgRef.current.clientWidth || 800;
    const height = svgRef.current.clientHeight || 600;
    svg.selectAll("*").remove();

    const container = svg.append("g").attr("class", "zoom-container");
    attachZoom(svg as any, container as any);

    const simNodes = nodes.map((n) => ({ ...n }));
    const simEdges = edges.map((e) => ({ ...e }));

    const simulation = d3
      .forceSimulation(simNodes as any)
      .force("link", d3.forceLink(simEdges as any).id((d: any) => d.id).distance(100))
      .force("charge", d3.forceManyBody().strength(-400))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius(60));

    const link = container
      .append("g")
      .selectAll("line")
      .data(simEdges)
      .join("line")
      .attr("stroke", (d: any) => {
        // Real per-edge decision counts from the API (audit_log-derived). No fabricated fallback:
        // an edge with no recorded decisions renders with the neutral/zero edgeColor.
        const dh = d.properties?.decision_history ?? { allow: 0, block: 0, escalate: 0 };
        return edgeColor(dh);
      })
      .attr("stroke-width", (d: any) => Math.max(1, Math.log((d.weight || 1) + 1) * 1.5))
      .attr("stroke-opacity", 0.7);

    const dragBehavior = d3
      .drag<SVGGElement, any>()
      .on("start", (e: any, d: any) => {
        if (!e.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on("drag", (e: any, d: any) => {
        d.fx = e.x;
        d.fy = e.y;
      })
      .on("end", (e: any, d: any) => {
        if (!e.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });

    const node = container
      .append("g")
      .selectAll("g")
      .data(simNodes)
      .join("g")
      .style("cursor", "pointer")
      .on("click", (_: any, d: any) => onSelectNode(d as AssetNode))
      .call(dragBehavior as any);

    node
      .filter((d: any) => ["high", "critical"].includes(d.properties?.risk_level))
      .append("circle")
      .attr("r", (d: any) => (NODE_RADIUS[d.type as keyof typeof NODE_RADIUS] || 10) + 4)
      .attr("fill", "none")
      .attr("stroke", "#FF3B5C")
      .attr("stroke-width", 2)
      .attr("stroke-dasharray", "3,2")
      .attr("opacity", 0.6);

    node
      .append("circle")
      .attr("r", (d: any) => NODE_RADIUS[d.type as keyof typeof NODE_RADIUS] || 10)
      .attr("fill", (d: any) => NODE_COLORS[d.type as keyof typeof NODE_COLORS] || "#888")
      .attr("stroke", (d: any) => (d.id === selectedNodeId ? "#FFF" : "#2A2A2A"))
      .attr("stroke-width", (d: any) => (d.id === selectedNodeId ? 3 : 1.5));

    node
      .append("text")
      .text((d: any) => d.name)
      .attr("x", 0)
      .attr("y", (d: any) => (NODE_RADIUS[d.type as keyof typeof NODE_RADIUS] || 10) + 14)
      .attr("text-anchor", "middle")
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
  }, [nodes, edges, selectedNodeId, onSelectNode]);

  return <svg ref={svgRef} style={{ width: "100%", height: "100%", minHeight: 600 }} />;
}
