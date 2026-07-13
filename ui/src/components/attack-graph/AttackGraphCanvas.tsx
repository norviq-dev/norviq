// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Attack Graph kill-chain canvas (design_handoff_attackgraph): d3 v7 HORIZONTAL kill-chain of the
// SELECTED path — agent → tool(s) → data crown-jewel, with a blast-radius fan of reach[] satellites
// around the crown jewel (sensitive s=1 as bright-red diamonds). Per-hop edges are colored by the
// live decision (DECISION_COLORS allow/mixed/block) and carry a "<deny> denied · <allow> ok" count.
// Ported from the handoff mock's d3 code: fixed virtual layout, draggable nodes (satellites follow
// the crown jewel), zoom +/−/reset with clickDistance(10), crown-jewel pulse, node-click scope card,
// and click-a-hop what-if block (flips the effective status to blocked). Crisp-render guardrails match
// the asset-graph fix: NO stroke halo (drop-shadow instead), geometricPrecision, viewBox fit so cold
// loads never clip, labels >= 9px.

import { useEffect, useImperativeHandle, useRef, forwardRef } from "react";
import * as d3 from "d3";
import { DECISION_COLORS, NODE_COLORS } from "../../lib/d3-helpers";
import { SEVERITY_COLORS } from "./constants";
import type { ThreatPath, ThreatStep } from "./types";

/** Classification-lifecycle caption for a tool hop: resolved verb (+ "learned" when admin-promoted),
 *  the observation state with its evidence counts, or the unclassified-observing fallback. */
function opCaption(st: ThreatStep): { text: string; color: string } | null {
  if (st.kind !== "tool") return null;
  if (st.op) {
    return {
      text: st.op + (st.op_src === "learned" ? " · learned" : ""),
      color: SEVERITY_COLORS[st.op_risk ?? "low"] ?? "#6ee7b7",
    };
  }
  if (st.inferred_verb) return { text: `observing · ${st.inferred_verb} ${st.inferred_count}/${st.observed_calls}`, color: "#ffcf82" };
  return { text: "unclassified · observing", color: "#a0a0a0" };
}

type HopDec = "allow" | "mixed" | "block" | "would_block";
// EVERY StepDecision needs an entry: an unmapped decision renders stroke:undefined — an invisible edge
// (the report-gen→execute_sql hop vanished when Monitor would-block history made its dec "would_block").
const DEC: Record<HopDec, string> = {
  allow: DECISION_COLORS.allow,
  mixed: DECISION_COLORS.mixed,
  block: DECISION_COLORS.blocked,
  would_block: DECISION_COLORS.mixed
};

export interface AttackCanvasHandle {
  zoomBy(k: number): void;
  fitView(): void;
}

interface ChainNode {
  id: string;
  kind: "agent" | "tool" | "data";
  role: "source" | "step" | "target";
  x: number;
  y: number;
  /** Classification-lifecycle line for tool nodes: the resolved op ("delete · learned") or the
   *  observation state ("observing · delete 12/14" / "unclassified · observing"). */
  opText?: string;
  opColor?: string;
}
interface Satellite {
  name: string;
  sensitive: boolean;
  x: number;
  y: number;
  ox: number;
  oy: number;
}
interface Edge {
  from: string;
  to: string;
  dec: HopDec;
  wb: number;
  deny: number;
  allow: number;
  i: number;
  sn: ChainNode;
  tn: ChainNode;
  _label?: string;
}

/** The scope-card payload (computed across ALL paths, not just the selected one). */
export interface ScopeCard {
  id: string;
  kindLabel: string;
  kindColor: string;
  rows: Array<{ k: string; v: string }>;
}

interface Props {
  path: ThreatPath;
  /** Every path — the scope card computes "what can this node actually touch" across all of them. */
  allPaths: ThreatPath[];
  /** Which hop index is what-if blocked on this path (-1 = none). */
  whatIfIndex: number;
  animateBlockedEdges?: boolean;
  onToggleWhatIf: (index: number) => void;
  onScope: (card: ScopeCard | null) => void;
}

const rOf = (d: ChainNode) => (d.role === "target" ? 24 : d.role === "source" ? 20 : 18);

function buildScope(nodeId: string, allPaths: ThreatPath[]): ScopeCard | null {
  const inPaths = allPaths.filter((p) => p.src === nodeId || p.steps.some((st) => st.to === nodeId));
  if (!inPaths.length) return null;
  let kind: "agent" | "tool" | "data" = "agent";
  for (const p of inPaths) {
    const st = p.steps.find((x) => x.to === nodeId);
    if (st) { kind = st.kind; break; }
  }
  const agents = [...new Set(inPaths.map((p) => p.src))].filter((a) => a !== nodeId);
  const targets = [...new Set(inPaths.map((p) => p.tgt))].filter((t) => t !== nodeId);
  const sens = new Set(inPaths.flatMap((p) => (p.reach || []).filter((r) => r.s).map((r) => r.n))).size;
  const denies = inPaths.reduce(
    (t, p) => t + p.steps.filter((st) => st.to === nodeId).reduce((x, st) => x + st.deny, 0),
    0
  );
  const expl = inPaths.filter((p) => p.status === "exploitable").length;
  const rows: Array<{ k: string; v: string }> = [];
  if (kind === "data") {
    rows.push({ k: "Reached by", v: agents.join(", ") || "—" });
    rows.push({ k: "Exposes", v: [...new Set(inPaths.flatMap((p) => (p.reach || []).map((r) => r.n)))].slice(0, 5).join(", ") || "—" });
  } else if (kind === "tool") {
    // Classification lifecycle: what this tool DOES (or its observation state) — from the hop that
    // resolved it (promoted override → registry → observed evidence).
    const toolStep = inPaths.flatMap((p) => p.steps).find((st) => st.to === nodeId && st.kind === "tool");
    if (toolStep) {
      const oc = opCaption(toolStep);
      if (oc) rows.push({ k: "Operation", v: oc.text + (toolStep.op && toolStep.op_risk ? ` · ${toolStep.op_risk} risk` : "") });
    }
    rows.push({ k: "Granted to", v: agents.join(", ") || "—" });
    rows.push({ k: "Reaches", v: targets.join(", ") || "—" });
  } else {
    rows.push({
      k: "Calls",
      v: [...new Set(inPaths.filter((p) => p.src === nodeId).flatMap((p) => p.steps.filter((st) => st.kind === "tool").map((st) => st.to)))].join(", ") || "—"
    });
    rows.push({ k: "Reaches", v: targets.join(", ") || "—" });
  }
  rows.push({ k: "Attack paths", v: inPaths.length + (expl ? ` · ${expl} exploitable` : "") });
  rows.push({ k: "Sensitive downstream", v: String(sens) });
  if (denies) rows.push({ k: "Denials · 24h", v: String(denies) });
  return { id: nodeId, kindLabel: kind, kindColor: NODE_COLORS[kind], rows };
}

export const AttackGraphCanvas = forwardRef<AttackCanvasHandle, Props>(function AttackGraphCanvas(
  { path, allPaths, whatIfIndex, animateBlockedEdges = true, onToggleWhatIf, onScope },
  ref
) {
  const svgRef = useRef<SVGSVGElement>(null);
  const stateRef = useRef({ path, allPaths, whatIfIndex, animateBlockedEdges, onToggleWhatIf, onScope });
  stateRef.current = { path, allPaths, whatIfIndex, animateBlockedEdges, onToggleWhatIf, onScope };

  const world = useRef<{
    svg?: d3.Selection<SVGSVGElement, unknown, null, undefined>;
    g?: d3.Selection<SVGGElement, unknown, null, undefined>;
    edgeG?: d3.Selection<SVGGElement, unknown, null, undefined>;
    blastG?: d3.Selection<SVGGElement, unknown, null, undefined>;
    badgeG?: d3.Selection<SVGGElement, unknown, null, undefined>;
    nodeG?: d3.Selection<SVGGElement, unknown, null, undefined>;
    zoom?: d3.ZoomBehavior<SVGSVGElement, unknown>;
    nodes?: ChainNode[];
    sats?: Satellite[];
    edges?: Edge[];
    tgt?: ChainNode;
    edgeSel?: d3.Selection<SVGLineElement, Edge, SVGGElement, unknown>;
    hitSel?: d3.Selection<SVGLineElement, Edge, SVGGElement, unknown>;
    badgeSel?: d3.Selection<SVGGElement, Edge, SVGGElement, unknown>;
    satSel?: d3.Selection<SVGGElement, Satellite, SVGGElement, unknown>;
    blastLineSel?: d3.Selection<SVGLineElement, Satellite, SVGGElement, unknown>;
    fitPts?: Array<{ x: number; y: number }>;
    ro?: ResizeObserver;
  }>({});

  useImperativeHandle(ref, () => ({
    zoomBy(k: number) {
      const w = world.current;
      if (w.svg && w.zoom) w.svg.transition().duration(200).call(w.zoom.scaleBy, k);
    },
    fitView: () => fitView()
  }));

  function drawIcon(g: d3.Selection<SVGGElement, unknown, null, undefined>, kind: string, color: string) {
    g.selectAll("*").remove();
    const s = g.append("g").attr("fill", "none").attr("stroke", color).attr("stroke-width", 1.7).attr("stroke-linecap", "round").attr("stroke-linejoin", "round");
    if (kind === "agent") {
      s.append("rect").attr("x", -7).attr("y", -4).attr("width", 14).attr("height", 11).attr("rx", 3);
      s.append("line").attr("x1", 0).attr("y1", -4).attr("x2", 0).attr("y2", -8);
      s.append("circle").attr("cx", 0).attr("cy", -9).attr("r", 1.4).attr("fill", color).attr("stroke", "none");
      s.append("circle").attr("cx", -3).attr("cy", 1).attr("r", 1.3).attr("fill", color).attr("stroke", "none");
      s.append("circle").attr("cx", 3).attr("cy", 1).attr("r", 1.3).attr("fill", color).attr("stroke", "none");
    } else if (kind === "tool") {
      s.append("rect").attr("x", -8).attr("y", -6).attr("width", 16).attr("height", 12).attr("rx", 2.5);
      s.append("path").attr("d", "M-4 -2 L-1 1 L-4 4");
      s.append("line").attr("x1", 1).attr("y1", 4).attr("x2", 5).attr("y2", 4);
    } else {
      s.append("ellipse").attr("cx", 0).attr("cy", -5).attr("rx", 7).attr("ry", 2.6);
      s.append("path").attr("d", "M-7 -5 V5 C-7 6.4 -3.8 7.6 0 7.6 C3.8 7.6 7 6.4 7 5 V-5");
      s.append("path").attr("d", "M-7 0 C-7 1.4 -3.8 2.6 0 2.6 C3.8 2.6 7 1.4 7 0");
    }
  }

  function trim(a: ChainNode, b: ChainNode) {
    const dx = b.x - a.x, dy = b.y - a.y, L = Math.hypot(dx, dy) || 1;
    const ra = (a.role === "source" ? 20 : a.role === "target" ? 24 : 18) + 4;
    const rb = (b.role === "target" ? 24 : b.role === "source" ? 20 : 18) + 9;
    return { x1: a.x + (dx / L) * ra, y1: a.y + (dy / L) * ra, x2: b.x - (dx / L) * rb, y2: b.y - (dy / L) * rb };
  }

  function tick() {
    const w = world.current;
    if (!w.nodeG) return;
    w.nodeG.selectAll<SVGGElement, ChainNode>("g.ak-node").attr("transform", (d) => `translate(${d.x},${d.y})`);
    const T = (d: Edge) => trim(d.sn, d.tn);
    if (w.edgeSel) w.edgeSel.attr("x1", (d) => T(d).x1).attr("y1", (d) => T(d).y1).attr("x2", (d) => T(d).x2).attr("y2", (d) => T(d).y2);
    if (w.hitSel) w.hitSel.attr("x1", (d) => d.sn.x).attr("y1", (d) => d.sn.y).attr("x2", (d) => d.tn.x).attr("y2", (d) => d.tn.y);
    const mid = (d: Edge) => {
      const mx = (d.sn.x + d.tn.x) / 2, my = (d.sn.y + d.tn.y) / 2;
      const dx = d.tn.x - d.sn.x, dy = d.tn.y - d.sn.y;
      const L = Math.hypot(dx, dy) || 1;
      return { mx, my, nx: -dy / L, ny: dx / L };
    };
    if (w.badgeSel) w.badgeSel.attr("transform", (d) => {
      const o = mid(d);
      const hw = ((d._label || "").length * 5.9) / 2 + 12;
      return `translate(${o.mx + o.nx * hw},${o.my + o.ny * hw})`;
    });
    if (w.satSel && w.tgt) {
      const t = w.tgt;
      w.satSel.attr("transform", (d) => `translate(${t.x + d.ox},${t.y + d.oy})`);
      if (w.blastLineSel) w.blastLineSel.attr("x1", t.x).attr("y1", t.y).attr("x2", (d) => t.x + d.ox).attr("y2", (d) => t.y + d.oy);
    }
  }

  function fitView() {
    const w = world.current;
    if (!w.svg || !w.g || !svgRef.current) return;
    const pts = w.fitPts && w.fitPts.length ? w.fitPts : (w.nodes ?? []);
    if (!pts.length) return;
    let minX: number, maxX: number, minY: number, maxY: number;
    let bb: SVGRect | null = null;
    try { bb = (w.g.node() as SVGGElement).getBBox(); } catch { bb = null; }
    if (bb && bb.width && bb.height) {
      const pad = 16;
      minX = bb.x - pad; maxX = bb.x + bb.width + pad;
      minY = bb.y - pad; maxY = bb.y + bb.height + pad;
    } else {
      const xs = pts.map((n) => n.x), ys = pts.map((n) => n.y), pad = 30;
      minX = Math.min(...xs) - pad; maxX = Math.max(...xs) + pad;
      minY = Math.min(...ys) - pad; maxY = Math.max(...ys) + pad;
    }
    // Base fit via viewBox: the browser scales/letterboxes NATIVELY on every layout, so a cold load
    // never clips regardless of JS timing. Reset any layered zoom transform.
    svgRef.current.setAttribute("viewBox", `${minX} ${minY} ${maxX - minX} ${maxY - minY}`);
    svgRef.current.setAttribute("preserveAspectRatio", "xMidYMid meet");
    w.g.attr("transform", null);
    try { w.svg.call(w.zoom!.transform, d3.zoomIdentity); } catch { /* zoom not ready */ }
  }

  function draw() {
    const w = world.current;
    if (!w.edgeG || !w.blastG || !w.badgeG || !w.nodeG) return;
    const { path: p, whatIfIndex: wf, animateBlockedEdges: anim } = stateRef.current;

    w.edgeG.selectAll("*").remove();
    w.blastG.selectAll("*").remove();
    w.badgeG.selectAll("*").remove();
    w.nodeG.selectAll("*").remove();

    // Fixed VIRTUAL layout (independent of container width); fitView scales it to the canvas.
    // HORIZONTAL kill-chain: agent (left) → tool(s) → crown jewel (right). fitView's viewBox scales the
    // whole chain to the canvas so it is always fully on-screen (no overflow), regardless of hop count.
    const nodes: ChainNode[] = [{ id: p.src, kind: "agent", role: "source", x: 0, y: 0 }];
    p.steps.forEach((st, i) => {
      const oc = opCaption(st);
      nodes.push({
        id: st.to, kind: st.kind, role: i === p.steps.length - 1 ? "target" : "step", x: 0, y: 0,
        opText: oc?.text, opColor: oc?.color,
      });
    });
    const n = nodes.length;
    const cy = 210, startX = 100, stepX = Math.max(168, Math.min(250, 780 / Math.max(1, n)));
    nodes.forEach((nd, i) => { nd.x = startX + i * stepX; nd.y = cy; });
    const tgt = nodes[n - 1];
    w.nodes = nodes;
    w.tgt = tgt;

    const effDec = (e: Edge): HopDec => (wf === e.i ? "block" : e.dec);
    const edges: Edge[] = p.steps.map((st, i) => ({
      from: st.from, to: st.to, dec: st.dec, deny: st.deny, allow: st.allow, wb: st.would_block ?? 0, i, sn: nodes[i], tn: nodes[i + 1]
    }));
    w.edges = edges;

    // ---- blast-radius satellites fanning off the crown jewel ----
    // Never re-draw a node that is already on the kill-chain as a satellite: reach[] can include chain
    // members (e.g. the chokepoint tool), and duplicating them drew a phantom twin with a dangling
    // dashed line next to the real node.
    const chainNames = new Set<string>([p.src, ...p.steps.map((st) => st.to)]);
    const reach = (p.reach || []).filter((it) => !chainNames.has(it.n)).slice(0, 6);
    const m = reach.length;
    const spreadDeg = Math.min(150, 30 * m), R = 116;
    const baseDeg = 0; // horizontal chain → fan the blast radius to the RIGHT of the crown jewel
    const sats: Satellite[] = reach.map((it, i) => {
      const t = m <= 1 ? 0 : -spreadDeg / 2 + spreadDeg * (i / (m - 1));
      const a = ((baseDeg + t) * Math.PI) / 180;
      const x = tgt.x + Math.cos(a) * R, y = tgt.y + Math.sin(a) * R;
      return { name: it.n, sensitive: !!it.s, x, y, ox: x - tgt.x, oy: y - tgt.y };
    });
    w.sats = sats;
    // Include each satellite label's extent (labels sit to the RIGHT of the fan) so fitView never clips them.
    const labelPts = sats.map((s) => ({ x: s.x + 16 + s.name.length * 6.3, y: s.y }));
    w.fitPts = (nodes as Array<{ x: number; y: number }>).concat(sats, labelPts);

    w.blastLineSel = w.blastG.selectAll<SVGLineElement, Satellite>("line.bl").data(sats).enter().append("line").attr("class", "bl")
      .attr("stroke", (d) => (d.sensitive ? "#FF3B5C" : "#5a3a42")).attr("stroke-width", (d) => (d.sensitive ? 1.5 : 1))
      .attr("stroke-dasharray", "2 5").attr("opacity", (d) => (d.sensitive ? 0.55 : 0.3));
    const satG = w.blastG.selectAll<SVGGElement, Satellite>("g.sat").data(sats).enter().append("g").attr("class", "sat");
    w.satSel = satG;
    satG.filter((d) => d.sensitive).append("circle").attr("r", 10).attr("fill", "none").attr("stroke", "#FF3B5C").attr("stroke-width", 1).attr("opacity", 0.4);
    satG.append("circle").attr("r", (d) => (d.sensitive ? 6 : 4))
      .attr("fill", (d) => (d.sensitive ? "#FF3B5C" : "#20141a"))
      .attr("stroke", (d) => (d.sensitive ? "#ffb3c0" : "#6f4a52")).attr("stroke-width", (d) => (d.sensitive ? 1.6 : 1.2));
    satG.append("text").attr("font-family", "'Outfit', sans-serif").attr("font-size", (d) => (d.sensitive ? 11 : 10))
      .attr("font-weight", (d) => (d.sensitive ? 700 : 500)).attr("fill", (d) => (d.sensitive ? "#ffb3c0" : "#8a7a80")).attr("dy", "0.34em")
      .attr("text-anchor", (d) => (d.x < tgt.x - 4 ? "end" : "start"))
      .attr("dx", (d) => (d.x < tgt.x - 4 ? -11 : 11))
      .style("text-rendering", "geometricPrecision")
      .style("filter", "drop-shadow(0 1px 1.5px rgba(0,0,0,0.9))")
      .text((d) => (d.sensitive ? "⬥ " : "") + d.name);

    // ---- edges: invisible hit line (click a hop → what-if block) + visible line ----
    w.hitSel = w.edgeG.selectAll<SVGLineElement, Edge>("line.hit").data(edges).enter().append("line").attr("class", "hit")
      .attr("stroke", "transparent").attr("stroke-width", 28)
      .style("cursor", (d) => (d.dec === "block" ? "default" : "pointer"))
      .on("click", (_ev, d) => { if (d.dec !== "block") stateRef.current.onToggleWhatIf(d.i); })
      .on("mouseover", (_ev, d) => { if (d.dec !== "block" && w.edgeSel) w.edgeSel.filter((e) => e.i === d.i).attr("stroke-width", 4.6); })
      .on("mouseout", (_ev, d) => { if (w.edgeSel) w.edgeSel.filter((e) => e.i === d.i).attr("stroke-width", (e) => (effDec(e) === "block" ? 3.6 : 2.8)); });
    w.edgeSel = w.edgeG.selectAll<SVGLineElement, Edge>("line.ed").data(edges).enter().append("line")
      .attr("class", (d) => "ed" + (effDec(d) === "block" && anim ? " ak-flow" : ""))
      .style("pointer-events", "none")
      .attr("stroke", (d) => DEC[effDec(d)])
      .attr("stroke-width", (d) => (effDec(d) === "block" ? 3.6 : 2.8))
      .attr("stroke-linecap", "round")
      .attr("marker-end", (d) => `url(#ak${effDec(d)})`)
      // Dashed = the hop is (or would be) stopped: enforced block AND monitor would-block both dash;
      // would-block stays amber so "covered but not enforcing" never reads as an enforced red block.
      .attr("stroke-dasharray", (d) => (effDec(d) === "block" || effDec(d) === "would_block" ? "7 6" : null));

    // ---- count label on EVERY hop (denied vs allowed) ----
    const cText = (e: Edge) => {
      if (effDec(e) === "block") return wf === e.i ? "⚠ what-if block" : "⚠ " + e.deny + " denied";
      if (effDec(e) === "would_block") return "⚠ " + e.wb + " would block" + (e.allow > 0 ? " · " + e.allow + " ok" : " · monitor");
      if (e.dec === "mixed") return e.deny + " denied · " + e.allow + " ok";
      return e.allow + " allowed";
    };
    const cColor = (e: Edge) => (effDec(e) === "block" ? "#ff7089" : effDec(e) === "would_block" || e.dec === "mixed" ? "#f5b544" : "#5fd6ab");
    const bEnter = w.badgeG.selectAll<SVGGElement, Edge>("g.bd").data(edges).enter().append("g").attr("class", "bd").style("pointer-events", "none")
      .each(function (d) { d._label = cText(d); });
    // K3: the edge count label ("N allowed" / "N denied" / mixed) renders REGULAR weight with NO stroke halo —
    // the previous 700 weight + dark outline read as a heavy bordered badge. Just the colored text, matching the
    // node-label treatment. (Applies to every attack-graph edge label; the asset graph has no such label.)
    bEnter.append("text").attr("text-anchor", "middle").attr("dy", "0.34em").attr("font-size", 10.5).attr("font-weight", 450).attr("font-family", "'Outfit', sans-serif")
      .style("text-rendering", "geometricPrecision")
      .attr("fill", (d) => cColor(d)).text((d) => cText(d));
    w.badgeSel = bEnter;

    // ---- nodes ----
    const nEnter = w.nodeG.selectAll<SVGGElement, ChainNode>("g.ak-node").data(nodes).enter().append("g").attr("class", "ak-node");
    nEnter.append("circle").attr("class", "halo").attr("r", (d) => rOf(d) + 9).attr("fill", "none")
      .attr("stroke", (d) => (d.role === "target" ? "#FF3B5C" : NODE_COLORS[d.kind])).attr("stroke-width", 1)
      .attr("opacity", (d) => (d.role === "target" ? 0.4 : 0.14));
    nEnter.filter((d) => d.role === "target").append("circle").attr("class", "ak-pulse").attr("r", 24).attr("fill", "none").attr("stroke", "#FF3B5C").attr("stroke-width", 2);
    nEnter.append("circle").attr("class", "ring").attr("r", rOf)
      .attr("fill", (d) => (d.role === "target" ? "#25121a" : "#10131b"))
      .attr("stroke", (d) => (d.role === "target" ? "#FF3B5C" : NODE_COLORS[d.kind])).attr("stroke-width", 2.6)
      .attr("filter", (d) => (d.role === "target" ? "url(#akGlow)" : null));
    nEnter.append("g").attr("class", "ico").each(function (d) { drawIcon(d3.select(this) as d3.Selection<SVGGElement, unknown, null, undefined>, d.kind, d.role === "target" ? "#ff8296" : NODE_COLORS[d.kind]); });
    // Horizontal chain: labels BELOW the node (clear of the arrows). NORMAL weight (~450) so they read as
    // labels, not headings. NO stroke halo — a drop-shadow keeps them crisp over edges (asset-graph fix).
    nEnter.append("text").attr("class", "lbl").attr("text-anchor", "middle").attr("font-family", "'Outfit', sans-serif").attr("font-weight", 450).attr("font-size", 12.5).attr("fill", "#e8edf5")
      .attr("x", 0).attr("y", (d) => rOf(d) + 17)
      .style("text-rendering", "geometricPrecision").style("filter", "drop-shadow(0 1px 1.5px rgba(0,0,0,0.9))")
      .text((d) => d.id);
    // Role caption: only a DATA terminal is a "crown jewel" — a path can terminate at a TOOL (no data
    // reach observed yet), and calling that tool a sensitive crown jewel misstates what was proven.
    nEnter.append("text").attr("class", "role").attr("text-anchor", "middle").attr("font-family", "'Outfit', sans-serif").attr("font-size", 10).attr("fill", (d) => (d.role === "target" ? "#ff8fa3" : "#a0a0a0"))
      .attr("x", 0).attr("y", (d) => rOf(d) + 31)
      .style("text-rendering", "geometricPrecision")
      .text((d) => (d.role === "target" ? (d.kind === "data" ? "crown jewel · sensitive" : "target · " + d.kind) : d.role === "source" ? "entry · agent" : "hop · " + d.kind));
    // Classification-lifecycle line under TOOL nodes: what the tool DOES (verb, risk-coloured; "· learned"
    // when admin-promoted) or its observation state — the observe → infer → promote loop, on the canvas.
    nEnter.filter((d) => !!d.opText).append("text").attr("class", "oplbl").attr("text-anchor", "middle")
      .attr("font-family", "'Outfit', sans-serif").attr("font-size", 9.5).attr("font-weight", 650)
      .attr("fill", (d) => d.opColor ?? "#a0a0a0")
      .attr("x", 0).attr("y", (d) => rOf(d) + 44)
      .style("text-rendering", "geometricPrecision")
      .style("filter", "drop-shadow(0 1px 1.5px rgba(0,0,0,0.9))")
      .text((d) => d.opText!);

    nEnter.call(
      d3.drag<SVGGElement, ChainNode>()
        .clickDistance(10)
        // Raise only when a drag actually moves the node — raising on "start" re-appends the <g> on
        // mousedown, which swallows the subsequent click (breaking the node → scope-card open).
        .on("drag", function (ev, d) { d3.select(this).raise(); d.x = ev.x; d.y = ev.y; tick(); })
    );
    // click a node → scope card (what this identity/tool/asset can actually touch, across ALL paths)
    nEnter.style("cursor", "pointer")
      .on("click", (_ev, d) => stateRef.current.onScope(buildScope(d.id, stateRef.current.allPaths)));

    tick();
    fitView();
    requestAnimationFrame(() => fitView());
    setTimeout(() => fitView(), 140);
  }

  // init: build the d3 world once.
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const w = world.current;
    const svg = d3.select(el);
    svg.selectAll("*").remove();

    const defs = svg.append("defs");
    ([["akallow", DEC.allow], ["akmixed", DEC.mixed], ["akblock", DEC.block], ["akwould_block", DEC.would_block]] as const).forEach(([id, color]) => {
      defs.append("marker").attr("id", id).attr("viewBox", "0 0 10 10").attr("refX", 8).attr("refY", 5).attr("markerWidth", 6.5).attr("markerHeight", 6.5).attr("orient", "auto")
        .append("path").attr("d", "M0 0 L10 5 L0 10 z").attr("fill", color);
    });
    const flt = defs.append("filter").attr("id", "akGlow").attr("x", "-80%").attr("y", "-80%").attr("width", "260%").attr("height", "260%");
    flt.append("feGaussianBlur").attr("stdDeviation", 5).attr("result", "b");
    const mrg = flt.append("feMerge");
    mrg.append("feMergeNode").attr("in", "b");
    mrg.append("feMergeNode").attr("in", "SourceGraphic");

    const g = svg.append("g");
    w.svg = svg;
    w.g = g;
    w.edgeG = g.append("g");
    w.blastG = g.append("g");
    w.badgeG = g.append("g");
    w.nodeG = g.append("g");
    // clickDistance(10): real clicks jitter a few px — without this, d3.zoom treats them as pans and eats the click.
    // Mouse WHEEL zooms directly (map-style) when the cursor is over the canvas — the graph fills the view,
    // so this is the expected gesture; move off the graph to scroll the page. Left-drag pans; right-click
    // passes through. (Was modifier-gated, which felt broken — you shouldn't have to hold ⌘ to zoom.)
    w.zoom = d3.zoom<SVGSVGElement, unknown>().scaleExtent([0.3, 4]).clickDistance(10)
      .filter((ev: WheelEvent | MouseEvent) => ev.type === "wheel" || !(ev as MouseEvent).button)
      .on("zoom", (ev) => g.attr("transform", ev.transform));
    svg.call(w.zoom).on("dblclick.zoom", null);

    draw();
    try {
      let raf = 0;
      w.ro = new ResizeObserver(() => { cancelAnimationFrame(raf); raf = requestAnimationFrame(() => fitView()); });
      w.ro.observe(el);
    } catch { /* ResizeObserver unavailable (jsdom) */ }
    if (typeof document !== "undefined" && document.fonts && document.fonts.ready) {
      document.fonts.ready.then(() => fitView()).catch(() => { /* ignore */ });
    }
    return () => {
      if (w.ro) { try { w.ro.disconnect(); } catch { /* noop */ } }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // redraw whenever the selection, what-if, or graph props change.
  useEffect(() => {
    draw();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path.id, whatIfIndex, animateBlockedEdges]);

  return <svg ref={svgRef} style={{ width: "100%", height: "100%", minHeight: 520, display: "block" }} data-testid="attack-graph-canvas" />;
});
