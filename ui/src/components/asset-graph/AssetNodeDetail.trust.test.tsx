// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { buildModel } from "./model";
import type { AssetNode } from "./types";

// The inspector re-derived a trust tier from >=0.75 / >=0.5 while the engine categorises at
// >=0.7 / >=0.4 (asset_graph._trust_category). The server already shipped trust_category and the model
// dropped it, so a 0.72 identity that the engine, the Agent Monitor and the alert bell all treat as
// HIGH rendered "Medium" in amber — and on a cluster with a raised threshold the error ran the other
// way, painting green "High" over an identity the engine had demoted and was escalating on.
describe("asset-graph trust tier", () => {
  const agent = (props: AssetNode["properties"]): AssetNode => ({
    id: "spiffe://norviq/ns/a/sa/b",
    type: "agent",
    name: "agent",
    properties: { namespace: "a", agent_class: "c", ...props },
  });

  it("carries the server's trust_category through the model", () => {
    const m = buildModel([agent({ trust_score: 0.72, trust_category: "high" })], []);
    expect(m.nodes[0].trustCategory).toBe("high");
  });

  it("keeps the score and the category independent, so the tier is not re-derived", () => {
    // 0.72 sits between the two ladders: engine says high, the old UI ladder said medium.
    const m = buildModel([agent({ trust_score: 0.72, trust_category: "high" })], []);
    expect(m.nodes[0].trust).toBe(0.72);
    expect(m.nodes[0].trustCategory).toBe("high");
  });

  it("leaves trustCategory undefined for nodes predating the field", () => {
    const m = buildModel([agent({ trust_score: 0.72 })], []);
    expect(m.nodes[0].trustCategory).toBeUndefined();
  });
});
