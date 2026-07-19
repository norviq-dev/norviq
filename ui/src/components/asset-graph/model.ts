// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Asset Graph view-model: maps the REAL /api/v1/asset-graph response onto the display
// model. The backend is authoritative — every display field that isn't in
// the API response is DERIVED here on the client, never faked:
//   kind        <- node.type
//   risk        <- properties.risk_level | data-node sensitivity | "low"
//   calls       <- tool properties.call_count | sum of incident call-edge call_counts
//   awaiting    <- properties.awaiting (server-synthesized) OR agent with zero outgoing calls
//   group (g)   <- the agent whose downstream chain (calls -> accesses) reaches the node
//   verdict     <- decision_history buckets: blocked | mixed | allow
//   lastSeen    <- max last_timestamp over incident call edges
// belongs_to edges (shared-SPIFFE identity sub-nodes) are structural: they group with their parent
// and never count toward blast radius.

import type { AssetEdge, AssetNode, CapabilityVerb, SourceCapability } from "./types";

export type Verdict = "allow" | "mixed" | "blocked";

export interface ViewNode {
  id: string;
  g: string; // group key = the owning agent's node id ("" = ungrouped)
  kind: "agent" | "tool" | "data" | "namespace";
  name: string;
  ns: string;
  agentClass: string;
  risk: "low" | "medium" | "high" | "critical";
  calls: number;
  trust?: number;
  spiffe?: string;
  lastSeen?: string; // ISO
  awaiting: boolean;
  isIdentity: boolean;
  // Source verb-capability posture (data nodes whose source type is in the registry).
  capability?: SourceCapability;
}

export interface ViewEdge {
  s: string;
  t: string;
  type: AssetEdge["type"];
  verdict: Verdict;
  allow: number;
  block: number;
  w: number;
  // Resolved operation of an accesses-edge (tool → data).
  verb?: CapabilityVerb;
}

export interface ViewGroup {
  key: string; // agent node id
  label: string; // agent display name
  ns: string;
  agentClass: string;
  awaiting: boolean;
}

export interface ViewModel {
  nodes: ViewNode[];
  edges: ViewEdge[];
  groups: ViewGroup[];
  namespaces: string[];
  agentClasses: string[];
}

const RISKS = new Set(["low", "medium", "high", "critical"]);

export function verdictOf(h?: { allow: number; block: number; escalate: number; would_block?: number }): Verdict {
  const allow = h?.allow ?? 0;
  const block = h?.block ?? 0;
  const escalate = h?.escalate ?? 0;
  // Monitor-mode would-block: the policy covers the edge (logged, not enforced). Treat it as covered so a
  // Monitor namespace's edges aren't shown as clean "allow" (which read as "no policy activity at all").
  const wouldBlock = h?.would_block ?? 0;
  if ((block > 0 || wouldBlock > 0) && allow === 0) return "blocked";
  if (block > 0 || escalate > 0 || wouldBlock > 0) return "mixed";
  return "allow";
}

function riskOf(node: AssetNode): ViewNode["risk"] {
  const raw = node.properties.risk_level as string | undefined;
  if (raw && RISKS.has(raw)) return raw as ViewNode["risk"];
  // Data nodes carry `sensitivity` instead of risk_level in builder snapshots — map it through.
  const sensitivity = (node.properties as Record<string, unknown>).sensitivity as string | undefined;
  if (node.type === "data" && sensitivity && RISKS.has(sensitivity)) return sensitivity as ViewNode["risk"];
  return "low";
}

/** Build the display model from the raw API response. Pure — unit-testable. */
export function buildModel(nodes: AssetNode[], edges: AssetEdge[]): ViewModel {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const out = new Map<string, AssetEdge[]>(); // source -> edges (calls/accesses only)
  const incident = new Map<string, AssetEdge[]>();
  const parentOf = new Map<string, string>(); // belongs_to: sub-node -> identity parent
  for (const e of edges) {
    if (e.type === "belongs_to") {
      parentOf.set(e.source, e.target);
      continue;
    }
    (out.get(e.source) ?? out.set(e.source, []).get(e.source)!).push(e);
    (incident.get(e.source) ?? incident.set(e.source, []).get(e.source)!).push(e);
    (incident.get(e.target) ?? incident.set(e.target, []).get(e.target)!).push(e);
  }

  const callCount = (e: AssetEdge) => Number((e.properties as Record<string, unknown>).call_count ?? 0);
  const history = (e: AssetEdge) => e.properties.decision_history;
  const callsOf = (n: AssetNode): number => {
    const own = Number((n.properties as Record<string, unknown>).call_count ?? n.properties.tool_call_count ?? 0);
    if (own > 0) return own;
    const inc = incident.get(n.id) ?? [];
    // agents: outgoing call totals; data: incoming (accesses carry no counts -> honest 0)
    const mine = n.type === "agent" ? inc.filter((e) => e.source === n.id) : inc.filter((e) => e.target === n.id);
    return mine.reduce((a, e) => {
      const h = history(e);
      // Include would_block (Monitor-mode) so a Monitor namespace's busy edges don't read as 0 calls.
      return a + (h ? h.allow + h.block + h.escalate + (h.would_block ?? 0) : callCount(e));
    }, 0);
  };
  const lastSeenOf = (n: AssetNode): string | undefined => {
    const stamps = (incident.get(n.id) ?? [])
      .map((e) => (e.properties as Record<string, unknown>).last_timestamp as string | undefined)
      .filter(Boolean) as string[];
    return stamps.sort().pop();
  };

  // Grouping: each traffic-bearing or awaiting AGENT anchors a group; everything its downstream
  // calls->accesses chain reaches joins that group (first agent wins on shared tools/data).
  const agents = nodes.filter(
    (n) => n.type === "agent" && !n.properties.is_identity && !parentOf.has(n.id)
  );
  // A shared-SPIFFE identity parent anchors the group for its class sub-nodes + its traffic.
  const identityParents = nodes.filter((n) => n.type === "agent" && n.properties.is_identity);
  const anchors = [...agents, ...identityParents];
  const groupOf = new Map<string, string>();
  for (const anchor of anchors) {
    if (groupOf.has(anchor.id)) continue;
    groupOf.set(anchor.id, anchor.id);
    const frontier = [anchor.id];
    while (frontier.length) {
      const cur = frontier.pop()!;
      for (const e of out.get(cur) ?? []) {
        if (!groupOf.has(e.target)) {
          groupOf.set(e.target, anchor.id);
          frontier.push(e.target);
        }
      }
    }
  }
  // identity sub-nodes ride with their parent's group
  for (const [sub, parent] of parentOf) groupOf.set(sub, groupOf.get(parent) ?? parent);

  const viewNodes: ViewNode[] = nodes.map((n) => ({
    id: n.id,
    g: groupOf.get(n.id) ?? "",
    kind: n.type,
    name: n.name,
    ns: n.properties.namespace ?? "",
    agentClass: n.properties.agent_class ?? "",
    risk: riskOf(n),
    calls: callsOf(n),
    trust: n.properties.trust_score,
    spiffe: n.properties.spiffe_id ?? (n.type === "agent" && n.id.includes("spiffe://") ? n.id.replace(/^.*?(spiffe:\/\/)/, "$1").replace(/#.*$/, "") : undefined),
    lastSeen: lastSeenOf(n),
    awaiting:
      Boolean(n.properties.awaiting) ||
      // fallback derivation: an agent with no outgoing calls and zero traffic
      (n.type === "agent" && !n.properties.is_identity && !parentOf.has(n.id) &&
        (out.get(n.id) ?? []).length === 0 && callsOf(n) === 0),
    isIdentity: Boolean(n.properties.is_identity),
    capability: n.properties.capability
  }));

  const viewEdges: ViewEdge[] = edges.map((e) => {
    const h = history(e);
    const cc = callCount(e);
    return {
      s: e.source,
      t: e.target,
      type: e.type,
      verdict: e.type === "belongs_to" ? "allow" : verdictOf(h),
      allow: h?.allow ?? 0,
      block: h?.block ?? 0,
      // stroke weight from real call volume (edge.weight is a constant 1 in builder snapshots)
      w: Math.min(3.2, 1.2 + Math.log((cc || (h ? h.allow + h.block + h.escalate + (h.would_block ?? 0) : 0)) + 1) * 0.55),
      verb: e.properties.verb
    };
  });

  const byIdView = new Map(viewNodes.map((n) => [n.id, n]));
  const groups: ViewGroup[] = anchors.map((a) => {
    const vn = byIdView.get(a.id)!;
    return { key: a.id, label: vn.name, ns: vn.ns, agentClass: vn.agentClass, awaiting: vn.awaiting };
  });

  const namespaces = [...new Set(viewNodes.map((n) => n.ns).filter(Boolean))].sort();
  const agentClasses = [...new Set(viewNodes.filter((n) => n.kind === "agent").map((n) => n.agentClass).filter(Boolean))].sort();
  void byId;
  return { nodes: viewNodes, edges: viewEdges, groups, namespaces, agentClasses };
}

export interface FilterState {
  search: string;
  types: Record<"agent" | "tool" | "data", boolean>;
  risks: Record<"low" | "medium" | "high" | "critical", boolean>;
  agentClass: string; // "all" or a class
  blockedOnly: boolean;
  focus: string | null; // focused agent group key
  selectedId: string | null;
}

/** Port of the mock's computeSets: visibility per filters + the selected node's reachable set. */
export function computeSets(model: ViewModel, s: FilterState): { vis: Record<string, boolean>; reach: Set<string> } {
  const vis: Record<string, boolean> = {};
  const groupMeta = new Map(model.groups.map((g) => [g.key, g]));
  for (const n of model.nodes) {
    const kindOk = n.kind === "namespace" ? true : s.types[n.kind as "agent" | "tool" | "data"];
    const g = groupMeta.get(n.g);
    vis[n.id] =
      kindOk &&
      s.risks[n.risk] &&
      (s.agentClass === "all" || (g?.agentClass ?? n.agentClass) === s.agentClass) &&
      (!s.search || n.name.toLowerCase().includes(s.search.toLowerCase()));
  }
  if (s.blockedOnly) {
    const keep = new Set<string>();
    for (const e of model.edges) if (e.verdict === "blocked") { keep.add(e.s); keep.add(e.t); }
    for (const n of model.nodes) if (!keep.has(n.id)) vis[n.id] = false;
  }
  if (s.focus) {
    const fset = new Set<string>([s.focus]);
    let frontier = [s.focus];
    while (frontier.length) {
      const next: string[] = [];
      for (const cur of frontier) {
        for (const e of model.edges) {
          if (e.type === "belongs_to") {
            // structural: subs join their focused parent (and vice versa)
            if (e.t === cur && !fset.has(e.s)) { fset.add(e.s); next.push(e.s); }
            continue;
          }
          if (e.s === cur && !fset.has(e.t)) { fset.add(e.t); next.push(e.t); }
        }
      }
      frontier = next;
    }
    for (const n of model.nodes) if (!fset.has(n.id)) vis[n.id] = false;
  }
  const reach = new Set<string>();
  const sel = model.nodes.find((n) => n.id === s.selectedId);
  if (sel) {
    const back = sel.kind === "data"; // data traces upstream (who can reach me)
    reach.add(sel.id);
    let frontier = [sel.id];
    while (frontier.length) {
      const next: string[] = [];
      for (const cur of frontier) {
        for (const e of model.edges) {
          if (e.type === "belongs_to") continue; // structural, not blast radius
          if (!back && e.s === cur && !reach.has(e.t)) { reach.add(e.t); next.push(e.t); }
          if (back && e.t === cur && !reach.has(e.s)) { reach.add(e.s); next.push(e.s); }
        }
      }
      frontier = next;
    }
  }
  return { vis, reach };
}
