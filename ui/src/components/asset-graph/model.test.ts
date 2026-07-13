// SPDX-License-Identifier: Apache-2.0
// View-model derivation (design_handoff_assetgraph mapping table): grouping by agent chains,
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
