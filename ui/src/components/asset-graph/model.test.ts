// SPDX-License-Identifier: Apache-2.0
// View-model derivation (mapping table): grouping by agent chains,
// verdict buckets from decision_history, awaiting derivation, risk mapping (sensitivity for data),
// belongs_to structural handling, and computeSets (filters, blocked-only, focus, reach BFS).
import { describe, expect, it } from "vitest";
import { buildModel, computeSets, verdictOf, type FilterState } from "./model";
import type { AssetEdge, AssetNode } from "./types";

const N = (id: string, type: AssetNode["type"], props: AssetNode["properties"] = {}): AssetNode => ({
  id, type, name: id, properties: props
});
const E = (source: string, target: string, type: AssetEdge["type"], props: AssetEdge["properties"] = {}): AssetEdge => ({
  source, target, type, weight: 1, properties: props
});

const NODES: AssetNode[] = [
  N("agentA", "agent", { namespace: "payments", agent_class: "payments-bot", trust_score: 0.82 }),
  N("tool:execute_sql", "tool", { namespace: "payments", risk_level: "critical", call_count: 10 } as AssetNode["properties"]),
  N("data:pg/orders", "data", { namespace: "payments", sensitivity: "high" } as AssetNode["properties"]),
  N("awaiting:hr-bot", "agent", { namespace: "hr", agent_class: "hr-bot", awaiting: true })
];
const EDGES: AssetEdge[] = [
  E("agentA", "tool:execute_sql", "calls", { decision_history: { allow: 5, block: 7, escalate: 0 } }),
  E("tool:execute_sql", "data:pg/orders", "accesses", {})
];

describe("verdictOf", () => {
  it("buckets decisions per the handoff formula", () => {
    expect(verdictOf({ allow: 5, block: 0, escalate: 0 })).toBe("allow");
    expect(verdictOf({ allow: 5, block: 2, escalate: 0 })).toBe("mixed");
    expect(verdictOf({ allow: 0, block: 3, escalate: 0 })).toBe("blocked");
    expect(verdictOf({ allow: 4, block: 0, escalate: 1 })).toBe("mixed");
    expect(verdictOf(undefined)).toBe("allow");
  });

  // A Monitor-mode namespace softens every block to decision="audit"; graphs.py reports that as
  // `would_block`. Nothing was stopped. Bucketing it as "blocked" made the canvas paint the edge
  // critical-red with a ⚠ badge that printed the enforced-block count — literally "0" — and put the
  // edge in the "Blocked · N edges" stat next to genuinely enforced ones.
  it("a Monitor-mode would-block is its OWN verdict, never 'blocked'", () => {
    expect(verdictOf({ allow: 0, block: 0, escalate: 0, would_block: 41 })).toBe("would_block");
    // and it is not laundered into a clean "allow" either — that was the original reason it was
    // folded into "blocked" in the first place.
    expect(verdictOf({ allow: 0, block: 0, escalate: 0, would_block: 41 })).not.toBe("allow");
  });

  it("an ENFORCED block with no allows is still 'blocked' even alongside would-blocks", () => {
    expect(verdictOf({ allow: 0, block: 41, escalate: 0 })).toBe("blocked");
    expect(verdictOf({ allow: 0, block: 3, escalate: 0, would_block: 7 })).toBe("blocked");
  });

  it("would-blocks mixed with real traffic stay 'mixed', not 'would_block'", () => {
    expect(verdictOf({ allow: 9, block: 0, escalate: 0, would_block: 4 })).toBe("mixed");
    expect(verdictOf({ allow: 0, block: 0, escalate: 2, would_block: 4 })).toBe("mixed");
  });
});

describe("buildModel", () => {
  const model = buildModel(NODES, EDGES);

  it("groups tools/data under the agent whose chain reaches them", () => {
    const byId = Object.fromEntries(model.nodes.map((n) => [n.id, n]));
    expect(byId["tool:execute_sql"].g).toBe("agentA");
    expect(byId["data:pg/orders"].g).toBe("agentA");
  });

  it("maps data-node sensitivity to risk and keeps tool risk_level", () => {
    const byId = Object.fromEntries(model.nodes.map((n) => [n.id, n]));
    expect(byId["data:pg/orders"].risk).toBe("high");
    expect(byId["tool:execute_sql"].risk).toBe("critical");
    expect(byId["agentA"].risk).toBe("low"); // missing -> low
  });

  it("derives calls: tools use call_count, agents sum outgoing decision history", () => {
    const byId = Object.fromEntries(model.nodes.map((n) => [n.id, n]));
    expect(byId["tool:execute_sql"].calls).toBe(10);
    expect(byId["agentA"].calls).toBe(12); // 5 allow + 7 block
  });

  it("marks awaiting from the server flag and creates a group for it", () => {
    const byId = Object.fromEntries(model.nodes.map((n) => [n.id, n]));
    expect(byId["awaiting:hr-bot"].awaiting).toBe(true);
    expect(model.groups.map((g) => g.key).sort()).toEqual(["agentA", "awaiting:hr-bot"]);
  });

  it("derives edge verdicts", () => {
    expect(model.edges[0].verdict).toBe("mixed");
    expect(model.edges[1].verdict).toBe("allow");
  });

  // The CRITICAL: a Monitor-mode namespace's edge is not an enforced block. Every renderer keys on
  // `verdict === "blocked"` — AssetGraphCanvas (stroke #FF3B5C, url(#arrowblocked), and the ⚠ badge
  // whose text is `e.block`), AssetNodeDetail (red dot + uppercase BLOCKED) and AssetGraph's
  // "Blocked · N edges" stat. Before this fix the badge over a bright-red edge printed the digit 0,
  // because the enforced-block count on a would-block edge really is zero.
  it("a Monitor-mode edge is not counted, coloured or badged as an enforced block", () => {
    const m = buildModel(NODES, [
      E("agentA", "tool:execute_sql", "calls", { decision_history: { allow: 0, block: 0, escalate: 0, would_block: 41 } })
    ]);
    const edge = m.edges[0];
    expect(edge.verdict).toBe("would_block");
    // the exact predicate every asset-graph renderer uses
    expect(edge.verdict === "blocked").toBe(false);
    // the counts stay separate: `block` is what was ENFORCED, `wouldBlock` what was merely observed
    expect(edge.block).toBe(0);
    expect(edge.wouldBlock).toBe(41);
    // AssetGraphCanvas builds its ⚠ badge list from this filter and labels each badge `e.block`;
    // an empty list is why the "0" badge over a red edge can no longer be drawn.
    expect(m.edges.filter((e) => e.verdict === "blocked")).toHaveLength(0);
    // AssetGraph's headline stat is the same filter — a Monitor namespace reports 0 enforced blocks.
    expect(m.edges.filter((e) => e.verdict === "blocked").length).toBe(0);
  });

  it("still counts a Monitor-mode edge's traffic (it is busy, not idle)", () => {
    const m = buildModel(NODES, [
      E("agentA", "tool:execute_sql", "calls", { decision_history: { allow: 0, block: 0, escalate: 0, would_block: 41 } })
    ]);
    const byId = Object.fromEntries(m.nodes.map((n) => [n.id, n]));
    expect(byId["agentA"].calls).toBe(41);
  });

  it("groups identity sub-nodes with their belongs_to parent", () => {
    const m = buildModel(
      [
        N("spiffe://svc", "agent", { namespace: "shared", is_identity: true, agent_classes: ["a", "b"] } as AssetNode["properties"]),
        N("spiffe://svc#a", "agent", { namespace: "shared", agent_class: "a" }),
        N("tool:t", "tool", { namespace: "shared" })
      ],
      [
        E("spiffe://svc#a", "spiffe://svc", "belongs_to", {}),
        E("spiffe://svc", "tool:t", "calls", { decision_history: { allow: 1, block: 0, escalate: 0 } })
      ]
    );
    const byId = Object.fromEntries(m.nodes.map((n) => [n.id, n]));
    expect(byId["spiffe://svc#a"].g).toBe("spiffe://svc");
    expect(byId["tool:t"].g).toBe("spiffe://svc");
  });
});

describe("computeSets", () => {
  const model = buildModel(NODES, EDGES);
  const base: FilterState = {
    search: "", types: { agent: true, tool: true, data: true },
    risks: { low: true, medium: true, high: true, critical: true },
    agentClass: "all", blockedOnly: false, focus: null, selectedId: null
  };

  it("filters by type, risk, class, and search", () => {
    expect(computeSets(model, base).vis["tool:execute_sql"]).toBe(true);
    expect(computeSets(model, { ...base, types: { ...base.types, tool: false } }).vis["tool:execute_sql"]).toBe(false);
    expect(computeSets(model, { ...base, risks: { ...base.risks, critical: false } }).vis["tool:execute_sql"]).toBe(false);
    expect(computeSets(model, { ...base, agentClass: "hr-bot" }).vis["agentA"]).toBe(false);
    expect(computeSets(model, { ...base, search: "orders" }).vis["agentA"]).toBe(false);
  });

  it("blockedOnly keeps only nodes on blocked edges", () => {
    const m = buildModel(NODES, [
      E("agentA", "tool:execute_sql", "calls", { decision_history: { allow: 0, block: 7, escalate: 0 } }),
      E("tool:execute_sql", "data:pg/orders", "accesses", {})
    ]);
    const { vis } = computeSets(m, { ...base, blockedOnly: true });
    expect(vis["agentA"]).toBe(true);
    expect(vis["tool:execute_sql"]).toBe(true);
    expect(vis["awaiting:hr-bot"]).toBe(false);
  });

  // The "Blocked" stat cell toggles blockedOnly, so the filter must select exactly what the cell
  // counts. A Monitor-mode edge belongs to neither.
  it("blockedOnly does not select a Monitor-mode would-block edge", () => {
    const m = buildModel(NODES, [
      E("agentA", "tool:execute_sql", "calls", { decision_history: { allow: 0, block: 0, escalate: 0, would_block: 41 } }),
      E("tool:execute_sql", "data:pg/orders", "accesses", {})
    ]);
    const { vis } = computeSets(m, { ...base, blockedOnly: true });
    expect(vis["agentA"]).toBe(false);
    expect(vis["tool:execute_sql"]).toBe(false);
  });

  it("focus narrows to the agent's downstream subgraph", () => {
    const { vis } = computeSets(model, { ...base, focus: "agentA" });
    expect(vis["agentA"]).toBe(true);
    expect(vis["tool:execute_sql"]).toBe(true);
    expect(vis["data:pg/orders"]).toBe(true);
    expect(vis["awaiting:hr-bot"]).toBe(false);
  });

  it("reach: agents trace downstream, data traces upstream", () => {
    expect([...computeSets(model, { ...base, selectedId: "agentA" }).reach].sort()).toEqual(
      ["agentA", "data:pg/orders", "tool:execute_sql"]
    );
    expect([...computeSets(model, { ...base, selectedId: "data:pg/orders" }).reach].sort()).toEqual(
      ["agentA", "data:pg/orders", "tool:execute_sql"]
    );
  });
});
