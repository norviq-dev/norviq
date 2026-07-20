// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Asset Graph canvas: two layouts driven by context —
//   overview = one circular mesh per agent (agent centered, tools+data on one ring, dashed hull,
//              namespace-colored label above); focus = live force layout of one agent's subgraph.
// Ported from the handoff mock's d3 code: init-once simulation, restyle on state change, cluster
// drag (dragging an agent moves its whole circle), zoom/fit, directed arrowheads, blocked ⚠ badges.

import { useEffect, useImperativeHandle, useRef, useState, forwardRef } from "react";
import * as d3 from "d3";
import { NODE_COLORS, RISK_COLORS } from "../../lib/d3-helpers";
import type { FilterState, ViewEdge, ViewGroup, ViewModel, ViewNode } from "./model";
import { computeSets } from "./model";
import { HULL_PAD, clampFitScale, clusterGaps, overviewColumns, ringRadius } from "./layout";

const TYPE_R = { agent: 15, tool: 9, data: 8, namespace: 12 } as const;

type SimNode = ViewNode & d3.SimulationNodeDatum & {
  fx?: number | null; fy?: number | null;
  _ring?: number | null; _hx?: number | null; _hy?: number | null;
};
type SimLink = Omit<ViewEdge, "s" | "t"> & { source: SimNode; target: SimNode };

export interface CanvasHandle {
  zoomBy(k: number): void;
  fitView(): void;
  relayout(): void;
}

interface Props {
  model: ViewModel;
  filters: FilterState;
  nsColor: (ns: string) => string;
  onSelect: (id: string | null) => void;
  onFocusAgent: (groupKey: string) => void;
  /** Reported so the inspector can side-flip away from the selected node. */
  onSelectedSide?: (side: "left" | "right") => void;
}

export const AssetGraphCanvas = forwardRef<CanvasHandle, Props>(function AssetGraphCanvas(
  { model, filters, nsColor, onSelect, onFocusAgent, onSelectedSide },
  ref
) {
  const svgRef = useRef<SVGSVGElement>(null);
  const stateRef = useRef({ model, filters, nsColor, onSelect, onFocusAgent, onSelectedSide });
  stateRef.current = { model, filters, nsColor, onSelect, onFocusAgent, onSelectedSide };
  // d3 world, rebuilt only when the MODEL changes (filters/selection restyle in place so drag positions survive)
  const world = useRef<{
    sim?: d3.Simulation<SimNode, SimLink>;
    nodes?: SimNode[];
    links?: SimLink[];
    node?: d3.Selection<SVGGElement, SimNode, SVGGElement, unknown>;
    link?: d3.Selection<SVGLineElement, SimLink, SVGGElement, unknown>;
    hull?: d3.Selection<SVGPathElement, ViewGroup, SVGGElement, unknown>;
    hullLabel?: d3.Selection<SVGTextElement, ViewGroup, SVGGElement, unknown>;
    badgeG?: d3.Selection<SVGGElement, unknown, null, undefined>;
    badges?: Array<{ s: string; t: string; g: d3.Selection<SVGGElement, unknown, null, undefined> }>;
    zoom?: d3.ZoomBehavior<SVGSVGElement, unknown>;
    svgSel?: d3.Selection<SVGSVGElement, unknown, null, undefined>;
    byId?: Map<string, SimNode>;
    rings?: Array<{ key: string; cx: number; cy: number; r: number }>;
    vis?: Record<string, boolean>;
    lastFocus?: string | null;
    dragCluster?: string | null;
    dragBase?: Record<string, { x: number | null; y: number | null }>;
    dragStart?: { x: number; y: number };
    fitPending?: boolean;
    lastVisKey?: string;
  }>({});

  useImperativeHandle(ref, () => ({
    zoomBy(k: number) {
      const w = world.current;
      if (w.svgSel && w.zoom) w.svgSel.transition().duration(220).call(w.zoom.scaleBy, k);
    },
    fitView: () => fitView(),
    relayout() {
      const w = world.current;
      if (!w.sim || !w.nodes) return;
      if (stateRef.current.filters.focus) {
        applyLayout();
      } else {
        circleLayout();
      }
    }
  }));

  // The SVG can be measured before it is attached/laid out (imperative-handle calls, the pre-mount effect
  // pass, an offscreen route). Null-guard the ref and fall back to sane dims so a stray call never throws
  // "Cannot read properties of null (reading 'clientWidth')".
  function dims() {
    const el = svgRef.current;
    if (!el) return { W: 1000, H: 620 };
    return { W: el.clientWidth || 1000, H: el.clientHeight || 620 };
  }

  // Track whether the container has a RESOLVED non-zero size. d3 must not run its sizing (rects with
  // width="100%", scales over W/H) until the SVG viewport actually resolves — otherwise the browser throws
  // "SVGLength: Could not resolve relative length". A ResizeObserver flips this true once the box has size,
  // which re-runs the init effect below.
  const [sized, setSized] = useState(false);
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const check = () => {
      if (el.clientWidth > 0 && el.clientHeight > 0) setSized(true);
    };
    check(); // already laid out on mount?
    if (typeof ResizeObserver === "undefined") {
      // jsdom / older envs: no observer — assume the box will size and let the effect proceed.
      setSized(true);
      return;
    }
    const ro = new ResizeObserver(check);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  /** Sorted signature of namespaces that still have a visible node — re-fit only when this changes. */
  function visibleNamespaceKey(): string {
    const { model: m, filters: f } = stateRef.current;
    const { vis } = computeSets(m, f);
    const nss = new Set<string>();
    for (const n of m.nodes) if (vis[n.id] && n.ns) nss.add(n.ns);
    return [...nss].sort().join("|");
  }

  function fitView() {
    const w = world.current;
    if (!w.svgSel || !w.zoom || !w.nodes) return;
    const pts = w.nodes.filter((n) => (w.vis ?? {})[n.id]);
    if (!pts.length) return;
    const xs = pts.map((n) => n.x ?? 0);
    const ys = pts.map((n) => n.y ?? 0);
    const [minX, maxX, minY, maxY] = [Math.min(...xs), Math.max(...xs), Math.min(...ys), Math.max(...ys)];
    const { W, H } = dims();
    const insW = stateRef.current.filters.selectedId ? 320 : 0;
    // Frame the visible clusters comfortably (~92% fill), but NEVER below the legibility floor: at the
    // clamped minimum, content overflows and the existing d3.zoom drag pans it — labels stay >= ~9px.
    const padX = stateRef.current.filters.focus ? 120 : 160;
    const padY = stateRef.current.filters.focus ? 120 : 130;
    const raw = 0.92 / Math.max((maxX - minX + padX) / (W - insW), (maxY - minY + padY) / H);
    const { scale, clamped } = clampFitScale(raw);
    let tx: number;
    let ty: number;
    if (clamped) {
      // Overflow at the floor: align the first clusters into view (left/top + padding) and let the user pan.
      tx = 48 - scale * minX;
      ty = scale * (maxY - minY) > H ? 48 - scale * minY : H / 2 - (scale * (minY + maxY)) / 2;
    } else {
      tx = (W - insW) / 2 - (scale * (minX + maxX)) / 2;
      ty = H / 2 - (scale * (minY + maxY)) / 2;
    }
    w.svgSel.transition().duration(450).call(w.zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  }

  /** Overview: agent centered, its ring = tools each followed by their data (Goldpinger-style). */
  function circleLayout() {
    const w = world.current;
    if (!w.sim || !w.nodes) return;
    const { model: m } = stateRef.current;
    const { vis } = computeSets(m, { ...stateRef.current.filters, focus: null, selectedId: null });
    w.vis = vis;
    w.nodes.forEach((n) => { n.fx = null; n.fy = null; n._ring = null; n._hx = null; n._hy = null; });
    w.rings = [];
    // Only lay out groups with a visible node. Pass 1: build each ring + its radius so grid spacing can
    // key off the LARGEST ring (tight when rings are small). Grid columns adapt to the canvas aspect so
    // ~8 agents fill the width instead of stacking (Goldpinger-style, roomy).
    const groups = m.groups.filter((g) => w.nodes!.some((n) => n.g === g.key && vis[n.id]));
    const plans = groups.map((g) => {
      const arr = w.nodes!.filter((n) => n.g === g.key && vis[n.id]);
      const agent = arr.find((n) => n.kind === "agent" && (n.id === g.key || n.isIdentity));
      const others = arr.filter((n) => n !== agent);
      const tools = others.filter((n) => n.kind === "tool");
      const rest = others.filter((n) => n.kind !== "tool");
      const ring: SimNode[] = [];
      tools.forEach((t) => {
        ring.push(t);
        rest
          .filter((dn) => m.edges.some((e) => e.s === t.id && e.t === dn.id))
          .forEach((dn) => { if (!ring.includes(dn)) ring.push(dn); });
      });
      rest.forEach((dn) => { if (!ring.includes(dn)) ring.push(dn); });
      return { key: g.key, agent, ring, R: ringRadius(ring.length) };
    });
    const { W, H } = dims();
    const cols = overviewColumns(plans.length, W, H);
    const maxR = Math.max(0, ...plans.map((p) => p.R));
    const { colGap, rowGap } = clusterGaps(maxR);
    plans.forEach((p, gi) => {
      const col = gi % cols;
      const row = Math.floor(gi / cols);
      const ccx = 360 + col * colGap;
      const ccy = 300 + row * rowGap;
      const nR = p.ring.length;
      const R = p.R;
      if (p.agent) {
        p.agent.fx = p.agent.x = p.agent._hx = ccx;
        p.agent.fy = p.agent.y = p.agent._hy = ccy;
        p.agent._ring = null;
      }
      p.ring.forEach((nd, i) => {
        const a = -Math.PI / 2 + (i / Math.max(1, nR)) * 2 * Math.PI;
        nd._ring = a;
        nd.fx = nd.x = nd._hx = ccx + R * Math.cos(a);
        nd.fy = nd.y = nd._hy = ccy + R * Math.sin(a);
      });
      w.rings!.push({ key: p.key, cx: ccx, cy: ccy, r: R });
    });
    w.nodes.filter((n) => !vis[n.id]).forEach((n) => { n.fx = null; n.fy = null; });
    w.sim.force("x", null).force("y", null);
    w.sim.force("charge", d3.forceManyBody().strength(0));
    (w.sim.force("link") as d3.ForceLink<SimNode, SimLink>).strength(0);
    (w.sim.force("collide") as d3.ForceCollide<SimNode>).radius(0);
    w.fitPending = false;
    w.sim.alpha(0).stop();
    tick();
    fitView();
    requestAnimationFrame(() => fitView());
  }

  /** Focus: depth-column layout + gentle force for the focused agent's subgraph. */
  function applyLayout() {
    const w = world.current;
    if (!w.sim || !w.nodes) return;
    const { W, H } = dims();
    const fid = stateRef.current.filters.focus;
    w.nodes.forEach((n) => { n.fx = null; n.fy = null; });
    if (!fid) { circleLayout(); return; }
    const m = stateRef.current.model;
    const fset = new Set([fid]);
    const depth: Record<string, number> = { [fid]: 0 };
    let frontier = [fid];
    while (frontier.length) {
      const next: string[] = [];
      for (const cur of frontier) {
        for (const e of m.edges) {
          if (e.type === "belongs_to") {
            if (e.t === cur && !fset.has(e.s)) { fset.add(e.s); depth[e.s] = depth[cur] + 1; next.push(e.s); }
            continue;
          }
          if (e.s === cur && !fset.has(e.t)) { fset.add(e.t); depth[e.t] = depth[cur] + 1; next.push(e.t); }
        }
      }
      frontier = next;
    }
    const byD: Record<number, string[]> = {};
    fset.forEach((id) => { (byD[depth[id]] = byD[depth[id]] || []).push(id); });
    const maxD = Math.max(0, ...Object.keys(byD).map(Number));
    const colX = (dp: number) => (maxD === 0 ? W / 2 : 85 + dp * ((W - 200) / maxD));
    const rowY = (id: string) => {
      const arr = byD[depth[id]];
      const i = arr.indexOf(id);
      const gap = Math.min(116, (H - 96) / arr.length);
      return H / 2 + (i - (arr.length - 1) / 2) * gap;
    };
    w.nodes.forEach((n) => {
      if (fset.has(n.id)) { n.fx = n.x = colX(depth[n.id]); n.fy = n.y = rowY(n.id); }
      else { n.fx = null; n.fy = null; }
    });
    w.sim.force("x", null).force("y", null);
    w.sim.force("charge", d3.forceManyBody().strength(-60));
    (w.sim.force("link") as d3.ForceLink<SimNode, SimLink>).distance(70).strength(0);
    (w.sim.force("collide") as d3.ForceCollide<SimNode>).radius((d) => TYPE_R[d.kind] + 13);
    if (w.svgSel && w.zoom) w.svgSel.transition().duration(320).call(w.zoom.transform, d3.zoomIdentity);
    w.fitPending = false;
    w.sim.alphaTarget(0).alpha(0.3).restart();
    tick();
  }

  function tick() {
    const w = world.current;
    if (!w.link || !w.node) return;
    const sel = stateRef.current.filters.selectedId;
    const rOf = (d: SimNode) => TYPE_R[d.kind] + (d.id === sel ? 2 : 0);
    w.link
      .attr("x1", (d) => { const dx = (d.target.x ?? 0) - (d.source.x ?? 0), dy = (d.target.y ?? 0) - (d.source.y ?? 0), l = Math.hypot(dx, dy) || 1; return (d.source.x ?? 0) + (dx / l) * (rOf(d.source) + 3); })
      .attr("y1", (d) => { const dx = (d.target.x ?? 0) - (d.source.x ?? 0), dy = (d.target.y ?? 0) - (d.source.y ?? 0), l = Math.hypot(dx, dy) || 1; return (d.source.y ?? 0) + (dy / l) * (rOf(d.source) + 3); })
      .attr("x2", (d) => { const dx = (d.target.x ?? 0) - (d.source.x ?? 0), dy = (d.target.y ?? 0) - (d.source.y ?? 0), l = Math.hypot(dx, dy) || 1; return (d.target.x ?? 0) - (dx / l) * (rOf(d.target) + 9); })
      .attr("y2", (d) => { const dx = (d.target.x ?? 0) - (d.source.x ?? 0), dy = (d.target.y ?? 0) - (d.source.y ?? 0), l = Math.hypot(dx, dy) || 1; return (d.target.y ?? 0) - (dy / l) * (rOf(d.target) + 9); });
    w.node.attr("transform", (d) => `translate(${d.x},${d.y})`);

    // tick() runs every physics frame — it must ONLY rewrite POSITIONAL attributes (path
    // geometry + transforms). The hull's fill-opacity / stroke-opacity / stroke-dasharray and the label
    // opacity are constant per view mode and were previously re-set here every frame (measured ~240×3
    // redundant attribute writes per drag → the "line flicker"). They now live in styleHulls(), run only
    // on model/filter change.
    const vis = w.vis ?? {};
    const circleMode = !stateRef.current.filters.focus;
    if (w.hull && w.hullLabel) {
      if (circleMode && w.rings) {
        w.hull.attr("d", (gd) => {
          const r = w.rings!.find((x) => x.key === gd.key);
          if (!r || !r.r) return null;
          // Draw the hull at ringRadius + HULL_PAD so every ring node (radius) AND its outward label
          // sit inside the circle — nodes stay at r.r, only the enclosing hull grows.
          const hr = r.r + HULL_PAD;
          return `M ${r.cx - hr} ${r.cy} a ${hr} ${hr} 0 1 0 ${2 * hr} 0 a ${hr} ${hr} 0 1 0 ${-2 * hr} 0`;
        });
        w.hullLabel.attr("transform", (gd) => {
          const r = w.rings!.find((x) => x.key === gd.key);
          if (!r) return "translate(-9999,-9999)";
          // Keep the cluster label above the enlarged hull (r.r + HULL_PAD), not the bare ring.
          return `translate(${r.cx},${r.cy - r.r - HULL_PAD - 20})`;
        });
      } else {
        w.hull.attr("d", (gd) => {
          const pts = w.nodes!.filter((n) => n.g === gd.key && vis[n.id]).map((n) => [n.x ?? 0, n.y ?? 0] as [number, number]);
          if (pts.length < 3) return null;
          const h = d3.polygonHull(pts);
          if (!h) return null;
          const c = d3.polygonCentroid(h);
          const pad = h.map((p) => { const dx = p[0] - c[0], dy = p[1] - c[1], l = Math.hypot(dx, dy) || 1; return [p[0] + (dx / l) * 34, p[1] + (dy / l) * 34]; });
          return "M" + pad.map((p) => p.join(",")).join("L") + "Z";
        });
        w.hullLabel.attr("transform", (gd) => {
          const pts = w.nodes!.filter((n) => n.g === gd.key && vis[n.id]).map((n) => [n.x ?? 0, n.y ?? 0]);
          if (!pts.length) return "translate(-9999,-9999)";
          const minY = Math.min(...pts.map((p) => p[1]));
          const avgX = pts.reduce((a, p) => a + p[0], 0) / pts.length;
          return `translate(${avgX},${minY - 46})`;
        });
      }
    }
    if (w.badges && w.byId) {
      w.badges.forEach((b) => {
        const s = w.byId!.get(b.s);
        const t = w.byId!.get(b.t);
        if (s && t) b.g.attr("transform", `translate(${((s.x ?? 0) + (t.x ?? 0)) / 2},${((s.y ?? 0) + (t.y ?? 0)) / 2})`);
      });
    }
  }

  function restyle() {
    const w = world.current;
    if (!w.node || !w.link) return;
    const { model: m, filters: f, nsColor: nsc } = stateRef.current;
    const { vis, reach } = computeSets(m, f);
    w.vis = vis;
    const sel = f.selectedId;
    const circle = !f.focus;

    w.node
      .style("display", (d) => (vis[d.id] ? null : "none"))
      .attr("opacity", (d) => (sel && !reach.has(d.id) ? 0.16 : d.awaiting ? 0.5 : 1));
    w.node.select<SVGCircleElement>(".core")
      .attr("r", (d) => TYPE_R[d.kind] + (d.id === sel ? 2 : 0))
      .attr("fill", (d) => (d.awaiting ? "#1a1305" : NODE_COLORS[d.kind]))
      .attr("stroke", (d) => (d.id === sel ? "#fff" : d.awaiting ? nsc(d.ns) : "rgba(255,255,255,0.16)"))
      .attr("stroke-width", (d) => (d.id === sel ? 3 : 1.5))
      .attr("stroke-dasharray", (d) => (d.awaiting ? "4,3" : null));
    w.node.select<SVGCircleElement>(".glow")
      .attr("r", (d) => TYPE_R[d.kind] + (d.id === sel ? 2 : 0))
      .attr("fill", (d) => NODE_COLORS[d.kind])
      // Overview: glow only the agent centers (subtle), keep ring tool/data nodes crisp; force view keeps the mock's glow.
      .attr("opacity", (d) => (circle ? (d.kind === "agent" ? 0.22 : 0) : 0.85));
    w.node.select<SVGCircleElement>(".ring")
      .style("display", (d) => (circle ? (d.risk === "critical" ? null : "none") : d.risk === "high" || d.risk === "critical" ? null : "none"))
      .attr("class", (d) => (circle && d.risk === "critical" ? "ring ag-pulse" : "ring"))
      .attr("stroke", (d) => RISK_COLORS[d.risk])
      .attr("stroke-dasharray", (d) => (circle && d.risk === "critical" ? null : "3,3"))
      .attr("stroke-width", (d) => (circle && d.risk === "critical" ? 1.8 : 1.6))
      .attr("r", (d) => TYPE_R[d.kind] + (d.id === sel ? 2 : 0) + (circle ? 7 : 5));
    w.node.select<SVGCircleElement>(".hring")
      .style("display", (d) => (circle && d.risk !== "low" && !d.awaiting ? null : "none"))
      .attr("r", (d) => TYPE_R[d.kind] + (d.id === sel ? 2 : 0) + 4)
      .attr("stroke-width", (d) => (d.risk === "critical" ? 2.6 : 2.4))
      .attr("stroke", (d) => RISK_COLORS[d.risk])
      .attr("stroke-opacity", 1);
    w.node.select<SVGTextElement>(".lbl")
      .text((d) => (circle && d.kind === "agent" && !d.isIdentity && d.id === d.g ? "" : circle && d.name.includes("/") ? d.name.split("/").pop()! : d.name))
      .attr("text-anchor", (d) => (circle && d._ring != null ? (Math.cos(d._ring) > 0.12 ? "start" : Math.cos(d._ring) < -0.12 ? "end" : "middle") : "middle"))
      .attr("x", (d) => (circle && d._ring != null ? Math.cos(d._ring) * (TYPE_R[d.kind] + 15) : 0))
      .attr("y", (d) => (circle && d._ring != null ? Math.sin(d._ring) * (TYPE_R[d.kind] + 16) + 4 : TYPE_R[d.kind] + (circle ? 20 : 18)))
      // Regular weight + a soft (non-white) fill for node names; the selected node bumps to medium for emphasis.
      .attr("fill", (d) => (d.id === sel ? "#e8edf5" : "#9aa7bd"))
      .attr("font-weight", (d) => (d.id === sel ? 600 : 400));

    w.link
      .style("display", (d) => (vis[d.source.id] && vis[d.target.id] ? null : "none"))
      .attr("stroke", (d) => {
        if (d.type === "belongs_to") return "#3a4252";
        const hl = sel && reach.has(d.source.id) && reach.has(d.target.id);
        if (circle) return d.verdict === "blocked" ? "#FF3B5C" : hl ? "#5f6d86" : "#33405c";
        return d.verdict === "blocked" ? "#FF3B5C" : hl ? "#a0a0a0" : "#6e6e6e";
      })
      .attr("stroke-width", (d) => {
        const hl = sel && reach.has(d.source.id) && reach.has(d.target.id);
        if (circle) return d.verdict === "blocked" ? 2.6 : 1;
        return d.verdict === "blocked" ? d.w + 1 : hl ? d.w + 1.3 : d.w;
      })
      .attr("stroke-opacity", (d) => {
        if (d.type === "belongs_to") return 0.35;
        const hl = sel && reach.has(d.source.id) && reach.has(d.target.id);
        if (circle) return sel ? (hl ? 0.9 : 0.05) : d.verdict === "blocked" ? 1 : 0.34;
        return sel ? (hl ? 0.95 : 0.08) : d.verdict === "blocked" ? 0.95 : 0.5;
      })
      .attr("marker-end", (d) => {
        if (circle || d.type === "belongs_to") return null;
        const dim = sel && !(reach.has(d.source.id) && reach.has(d.target.id));
        return dim ? "url(#arrowdim)" : d.verdict === "blocked" ? "url(#arrowblocked)" : "url(#arrowcall)";
      })
      .attr("stroke-dasharray", (d) => (!circle && sel && reach.has(d.source.id) && reach.has(d.target.id) ? "7 7" : null))
      .attr("class", (d) => (!circle && sel && reach.has(d.source.id) && reach.has(d.target.id) ? "ag-flow" : null));

    // blocked ⚠ badges over visible blocked edges
    if (w.badges) w.badges.forEach((b) => b.g.remove());
    const blocked = m.edges.filter((e) => e.verdict === "blocked" && vis[e.s] && vis[e.t] && (!sel || (reach.has(e.s) && reach.has(e.t))));
    w.badges = blocked.map((e) => {
      const g = w.badgeG!.append("g").style("pointer-events", "none");
      g.append("rect").attr("x", -34).attr("y", -11).attr("width", 68).attr("height", 22).attr("rx", 7).attr("fill", "#1a0d12").attr("stroke", "#FF3B5C").attr("stroke-width", 1);
      g.append("path").attr("transform", "translate(-24,0)").attr("d", "M0 -5 L5 4 L-5 4 Z").attr("fill", "none").attr("stroke", "#FF3B5C").attr("stroke-width", 1.4).attr("stroke-linejoin", "round");
      g.append("text").attr("x", 5).attr("y", 3.5).attr("text-anchor", "middle").attr("fill", "#ff7088").attr("font-size", 11).attr("font-weight", 700).attr("font-family", "ui-monospace,monospace").text(e.block);
      return { s: e.s, t: e.t, g };
    });
    styleHulls();
    tick();
  }

  // The hull's constant, view-mode-dependent styling — set on model/filter change, NOT per
  // physics frame. (Geometry — the hull `d` path + label transforms — stays in tick().)
  function styleHulls() {
    const w = world.current;
    if (!w.hull || !w.hullLabel) return;
    const circleMode = !stateRef.current.filters.focus;
    const vis = w.vis ?? {};
    if (circleMode && w.rings) {
      w.hull
        .attr("stroke-dasharray", (gd) => (gd.awaiting ? "4,4" : null))
        .attr("fill-opacity", 0.025)
        .attr("stroke-opacity", 0.22);
      w.hullLabel.attr("opacity", (gd) => (w.rings!.some((x) => x.key === gd.key) ? 0.9 : 0));
    } else {
      w.hull
        .attr("stroke-dasharray", "5,5")
        .attr("fill-opacity", 0.05)
        .attr("stroke-opacity", 0.3);
      w.hullLabel.attr("opacity", (gd) => (w.nodes!.some((n) => n.g === gd.key && vis[n.id]) ? 0.85 : 0));
    }
  }

  // ── init: rebuild the d3 world when the MODEL changes ─────────────────────
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    // Do NOT run d3 sizing until the container has a resolved non-zero size (else rects with width="100%"
    // throw "SVGLength: Could not resolve relative length"). When it resolves, `sized` flips and re-runs this.
    if (el.clientWidth === 0 || el.clientHeight === 0) return;
    const w = world.current;
    const svg = d3.select(el);
    svg.selectAll("*").remove();
    const { W, H } = { W: el.clientWidth || 1000, H: el.clientHeight || 620 };

    // defs: glow, arrowheads (no grid — the panel background is a clean dark radial)
    const defs = svg.append("defs");
    const flt = defs.append("filter").attr("id", "agGlow").attr("x", "-80%").attr("y", "-80%").attr("width", "260%").attr("height", "260%");
    // Softer glow so node cores + labels stay sharp.
    flt.append("feGaussianBlur").attr("stdDeviation", 3.5).attr("result", "b");
    const mrg = flt.append("feMerge");
    mrg.append("feMergeNode").attr("in", "b");
    mrg.append("feMergeNode").attr("in", "SourceGraphic");
    ([["arrowcall", "#a0a0a0"], ["arrowblocked", "#FF3B5C"], ["arrowdim", "#2a3040"]] as const).forEach(([id, color]) => {
      defs.append("marker").attr("id", id).attr("viewBox", "0 0 10 10").attr("refX", 8).attr("refY", 5).attr("markerWidth", 6.5).attr("markerHeight", 6.5).attr("orient", "auto")
        .append("path").attr("d", "M0 0 L10 5 L0 10 z").attr("fill", color);
    });

    // Transparent hit-area rect so clicking empty canvas clears the selection (no visible grid).
    svg.append("rect").attr("width", "100%").attr("height", "100%").attr("fill", "transparent").on("click", () => stateRef.current.onSelect(null));

    const zoomG = svg.append("g");
    const hullG = zoomG.append("g");
    const linkG = zoomG.append("g");
    const badgeG = zoomG.append("g");
    const nodeG = zoomG.append("g");
    const topG = zoomG.append("g").style("pointer-events", "none");

    const groups = model.groups;
    const gi: Record<string, number> = {};
    groups.forEach((g, i) => (gi[g.key] = i));
    const COLS = 2;
    const ROWS = Math.max(1, Math.ceil(groups.length / COLS));
    const cx = (g: string) => W * (((gi[g] ?? 0) % COLS) + 0.5) / COLS;
    const cy = (g: string) => H * (Math.floor((gi[g] ?? 0) / COLS) + 0.5) / ROWS;

    const nodes: SimNode[] = model.nodes.map((n) => ({ ...n, x: cx(n.g) + (Math.random() - 0.5) * 90, y: cy(n.g) + (Math.random() - 0.5) * 90 }));
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const links: SimLink[] = model.edges
      .filter((e) => byId.has(e.s) && byId.has(e.t))
      .map((e) => ({ ...e, source: byId.get(e.s)!, target: byId.get(e.t)! }));

    const sim = d3.forceSimulation<SimNode>(nodes)
      .force("link", d3.forceLink<SimNode, SimLink>(links).id((d) => d.id).distance((d) => (d.source.kind === "agent" ? 78 : 54)).strength(0.7))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("collide", d3.forceCollide<SimNode>().radius((d) => TYPE_R[d.kind] + 20));

    const drag = d3.drag<SVGGElement, SimNode>()
      .on("start", (ev, d) => {
        if (!ev.active) sim.alphaTarget(0.3).restart();
        if (!stateRef.current.filters.focus && d.kind === "agent" && d.g === d.id) {
          w.dragCluster = d.g;
          w.dragBase = {};
          nodes.filter((n) => n.g === d.g).forEach((n) => (w.dragBase![n.id] = { x: n._hx ?? null, y: n._hy ?? null }));
          w.dragStart = { x: ev.x, y: ev.y };
        } else {
          d.fx = d.x;
          d.fy = d.y;
        }
      })
      .on("drag", (ev, d) => {
        if (w.dragCluster) {
          let dx = ev.x - w.dragStart!.x;
          let dy = ev.y - w.dragStart!.y;
          // AG-CLAMP: keep the dragged cluster inside the canvas — clamp the translation so the ring
          // (center + radius) never leaves [pad, W-pad] × [pad, H-pad]. Previously a cluster could be
          // dragged half-off-canvas and clip. Clamp dx/dy once (not per-node) so the cluster keeps shape.
          const ring = w.rings?.find((x) => x.key === w.dragCluster);
          const agBase = w.dragBase![w.dragCluster!];
          if (ring && agBase && agBase.x != null && agBase.y != null) {
            const pad = (ring.r || 60) + 24;
            const cx = agBase.x + dx;
            const cy = agBase.y + dy;
            const clampedCx = Math.max(pad, Math.min(W - pad, cx));
            const clampedCy = Math.max(pad, Math.min(H - pad, cy));
            dx += clampedCx - cx;
            dy += clampedCy - cy;
          }
          nodes.filter((n) => n.g === w.dragCluster).forEach((n) => {
            const b = w.dragBase![n.id];
            if (!b || b.x == null || b.y == null) return;
            n._hx = b.x + dx;
            n._hy = b.y + dy;
            n.fx = n.x = n._hx;
            n.fy = n.y = n._hy;
          });
          const r = w.rings?.find((x) => x.key === w.dragCluster);
          const ag = nodes.find((n) => n.g === w.dragCluster && n.kind === "agent" && n.id === n.g);
          if (r && ag) { r.cx = ag._hx ?? r.cx; r.cy = ag._hy ?? r.cy; }
          tick();
        } else {
          d.fx = ev.x;
          d.fy = ev.y;
        }
      })
      .on("end", (ev, d) => {
        if (!ev.active) sim.alphaTarget(0);
        if (w.dragCluster) {
          w.dragCluster = null;
          w.dragBase = undefined;
          tick();
        } else if (!stateRef.current.filters.focus && d._hx != null) {
          d.fx = d._hx;
          d.fy = d._hy;
          sim.alpha(0.15).restart();
        } else {
          d.fx = null;
          d.fy = null;
        }
      });

    w.link = linkG.selectAll<SVGLineElement, SimLink>("line").data(links).join("line").attr("stroke-linecap", "round");
    w.hull = hullG.selectAll<SVGPathElement, ViewGroup>("path").data(groups).join("path")
      .attr("fill", (d) => nsColor(d.ns)).attr("fill-opacity", 0.05)
      .attr("stroke", (d) => nsColor(d.ns)).attr("stroke-opacity", 0.3).attr("stroke-dasharray", "5,5").attr("stroke-width", 1.2);
    w.hullLabel = topG.selectAll<SVGTextElement, ViewGroup>("text").data(groups).join("text")
      .attr("fill", (d) => nsColor(d.ns)).attr("font-size", 12.5).attr("font-weight", 600)
      .attr("font-family", "'Outfit',sans-serif").attr("text-anchor", "middle").attr("opacity", 0.9)
      // Soft shadow instead of a thick outline (the 4.5px halo read as heavy/blurry).
      .style("filter", "drop-shadow(0 1px 1.5px rgba(0,0,0,0.9))")
      .style("text-rendering", "geometricPrecision")
      .text((d) => d.label);

    const nodeSel = nodeG.selectAll<SVGGElement, SimNode>("g").data(nodes).join("g")
      .attr("class", "ag-node")
      .call(drag)
      .on("click", (ev: MouseEvent, d) => {
        ev.stopPropagation();
        // Clicking an agent's anchor focuses its subgraph; when already focused, select it instead.
        if (d.kind === "agent" && d.g === d.id && stateRef.current.filters.focus !== d.id) {
          stateRef.current.onFocusAgent(d.id);
        } else {
          stateRef.current.onSelect(d.id);
          const { W: cw } = dims();
          stateRef.current.onSelectedSide?.((d.x ?? 0) > cw / 2 ? "left" : "right");
        }
      });
    nodeSel.append("circle").attr("class", "ring").attr("fill", "none");
    nodeSel.append("circle").attr("class", "glow").attr("filter", "url(#agGlow)");
    nodeSel.append("circle").attr("class", "hring").attr("fill", "none").style("display", "none");
    nodeSel.append("circle").attr("class", "core");
    nodeSel.append("text").attr("class", "lbl").attr("text-anchor", "middle").attr("font-size", 11.5).attr("font-weight", 400)
      .attr("font-family", "'Outfit',sans-serif")
      // NO stroke halo — a paint-order outline (even 2px) thickens the glyphs so 400-weight text reads as
      // bold. A soft drop-shadow keeps it legible over edges without adding weight.
      .style("filter", "drop-shadow(0 1px 1.5px rgba(0,0,0,0.9))")
      .style("text-rendering", "geometricPrecision").style("pointer-events", "none");
    w.node = nodeSel;
    w.badgeG = badgeG;
    w.badges = [];

    const zoom = d3.zoom<SVGSVGElement, unknown>().scaleExtent([0.35, 3])
      // Mouse WHEEL zooms directly (map-style) when the cursor is over the graph — the expected gesture;
      // move off the graph to scroll the page. Left-drag pans; the +/- buttons still zoom too. (Was
      // modifier-gated, which read as broken — zooming shouldn't require holding ⌘.)
      .filter((ev: WheelEvent | MouseEvent) => ev.type === "wheel" || !(ev as MouseEvent).button)
      .on("zoom", (ev) => zoomG.attr("transform", ev.transform));
    svg.call(zoom).on("dblclick.zoom", null);
    w.zoom = zoom;
    w.svgSel = svg;
    w.sim = sim;
    w.nodes = nodes;
    w.links = links;
    w.byId = byId;
    w.lastFocus = stateRef.current.filters.focus;
    w.lastVisKey = visibleNamespaceKey();

    sim.on("tick", () => tick());
    applyLayout();
    restyle();
    return () => { sim.stop(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model, sized]);

  // Focus change swaps the layout. Every other change (Type/Risk chips, class, blocked-only, search,
  // selection) restyles INSTANTLY — nodes hide/show in place, positions never move (matches the mock; the
  // previous debounced full re-layout made chips feel laggy and made the whole graph jump). We only re-fit
  // when the set of visible namespaces changes, so hiding a whole namespace re-frames the rest.
  useEffect(() => {
    const w = world.current;
    if (!w.sim) return;
    if (w.lastFocus !== filters.focus) {
      w.lastFocus = filters.focus;
      applyLayout();
      restyle();
      w.lastVisKey = visibleNamespaceKey();
      return;
    }
    restyle(); // instant
    if (!filters.focus) {
      const nsKey = visibleNamespaceKey();
      if (nsKey !== w.lastVisKey) {
        w.lastVisKey = nsKey;
        fitView();
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters]);

  return (
    <svg ref={svgRef} style={{ width: "100%", height: "100%", display: "block" }} data-testid="asset-graph-canvas" />
  );
});
