// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The MCP server node, at each of the six places a new node kind silently disappears.
//
// Every one of these failures renders as "there are no MCP servers" rather than as an error, which is
// why they are asserted rather than eyeballed: a node with no colour draws with an undefined fill, a
// node with no radius draws with a NaN radius, and a node with no filter chip is filtered out by a
// `Record` lookup that returns `undefined` — falsy, so invisible. The server sends it, the model
// carries it, and the screen shows nothing.

import { describe, expect, it } from "vitest";
import { NODE_COLORS, NODE_RADIUS } from "../../lib/d3-helpers";
import { STRUCTURAL_EDGE_TYPES, buildModel, computeSets, type FilterState } from "./model";
import type { AssetEdge, AssetNode } from "./types";

const NODES: AssetNode[] = [
  { id: "agentA", type: "agent", name: "support-agent",
    properties: { namespace: "agents", agent_class: "support-agent", trust_score: 0.8 } },
  { id: "tool:read_file", type: "tool", name: "read_file",
    properties: { namespace: "agents", risk_level: "medium", call_count: 3 } as AssetNode["properties"] },
  { id: "mcp:rugpull", type: "mcp_server", name: "rugpull",
    properties: { namespace: "agents", server_id: "rugpull", transport: "http" } as AssetNode["properties"] }
];
const EDGES: AssetEdge[] = [
  { source: "agentA", target: "tool:read_file", type: "calls", weight: 1,
    properties: { decision_history: { allow: 3, block: 0, escalate: 0 } } },
  { source: "mcp:rugpull", target: "tool:read_file", type: "serves", weight: 1, properties: {} }
];

const FILTERS: FilterState = {
  search: "",
  types: { agent: true, tool: true, data: true, mcp_server: true },
  risks: { low: true, medium: true, high: true, critical: true },
  agentClass: "all",
  blockedOnly: false,
  focus: null,
  selectedId: null
};

describe("the MCP server node survives the model", () => {
  it("keeps its kind rather than collapsing into a tool or a data node", () => {
    const model = buildModel(NODES, EDGES);
    expect(model.nodes.find((n) => n.id === "mcp:rugpull")?.kind).toBe("mcp_server");
  });

  it("carries the serves edge through", () => {
    const model = buildModel(NODES, EDGES);
    const serves = model.edges.find((e) => e.type === "serves");
    expect(serves).toBeTruthy();
    expect(serves?.s).toBe("mcp:rugpull");
    expect(serves?.t).toBe("tool:read_file");
  });

  it("is VISIBLE by default", () => {
    const { vis } = computeSets(buildModel(NODES, EDGES), FILTERS);
    expect(vis["mcp:rugpull"]).toBe(true);
  });

  it("its chip actually filters it", () => {
    const model = buildModel(NODES, EDGES);
    const off = { ...FILTERS, types: { ...FILTERS.types, mcp_server: false } };
    expect(computeSets(model, off).vis["mcp:rugpull"]).toBe(false);
    // …and only it. A chip that took the tools with it would be a different control.
    expect(computeSets(model, off).vis["tool:read_file"]).toBe(true);
  });

  it("a kind with NO chip at all defaults to visible rather than vanishing", () => {
    // The trap this whole file exists for. `s.types[k]` for an unrecognised `k` is `undefined`,
    // which is falsy — so the previous `kindOk` expression hid any future kind by default, with no
    // filter to turn it back on and no error anywhere. `namespace` had to be special-cased for
    // exactly this reason; the fix generalises that instead of adding a second special case.
    const model = buildModel(
      [...NODES, { id: "future:thing", type: "data", name: "thing", properties: {} }],
      EDGES
    );
    model.nodes.find((n) => n.id === "future:thing")!.kind = "quantum" as never;
    expect(computeSets(model, FILTERS).vis["future:thing"]).toBe(true);
  });
});

describe("it can actually be drawn", () => {
  it("has a colour", () => {
    expect(NODE_COLORS.mcp_server).toMatch(/^#[0-9A-Fa-f]{6}$/);
  });

  it("has a radius", () => {
    expect(NODE_RADIUS.mcp_server).toBeGreaterThan(0);
  });

  it("every kind in the union has both", () => {
    // The exhaustiveness check, so the NEXT kind fails here rather than on a customer's screen.
    for (const kind of ["agent", "tool", "data", "namespace", "mcp_server"] as const) {
      expect(NODE_COLORS[kind], `no colour for ${kind}`).toBeTruthy();
      expect(NODE_RADIUS[kind], `no radius for ${kind}`).toBeTruthy();
    }
  });
});

describe("the serves edge is scaffolding, not a permitted call", () => {
  it("is drawn structurally rather than as an allow decision", () => {
    // `verdictOf(undefined)` returns "allow", so an edge with no decision history would be painted in
    // the allow colour and read as "the engine let this through". Nothing was evaluated: the server
    // simply provides the definition. This canvas has been here before — a Monitor-mode would-block
    // painted as an enforced block, with a badge that printed "0".
    const model = buildModel(NODES, EDGES);
    expect(STRUCTURAL_EDGE_TYPES.has("serves")).toBe(true);
    expect(model.edges.find((e) => e.type === "serves")?.allow).toBe(0);
  });

  it("still counts for blast radius — that is the question an MCP node answers", () => {
    // "What would a compromised server put in reach" is exactly a forward walk along `serves`.
    const model = buildModel(NODES, EDGES);
    const { reach } = computeSets(model, { ...FILTERS, selectedId: "mcp:rugpull" });
    expect(reach.has("tool:read_file")).toBe(true);
  });

  it("does not change what an AGENT reaches", () => {
    // The edge runs server -> tool, so a forward walk from an agent never crosses it. Asserted
    // because a reversed edge would silently pull every MCP server into every agent's blast radius.
    const model = buildModel(NODES, EDGES);
    const { reach } = computeSets(model, { ...FILTERS, selectedId: "agentA" });
    expect(reach.has("tool:read_file")).toBe(true);
    expect(reach.has("mcp:rugpull")).toBe(false);
  });
});
