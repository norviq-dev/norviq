// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The AssetGraph canvas must survive render-timing edge cases without throwing:
//   • it mounts when the container has NO resolved size (jsdom reports clientWidth/Height = 0) — the d3
//     sizing is deferred, so no "SVGLength: Could not resolve relative length".
//   • imperative-handle methods (relayout / fitView / zoomBy) called before a size resolves do NOT throw
//     "Cannot read properties of null (reading 'clientWidth')" — dims() is null/zero-guarded.

import { createRef } from "react";
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AssetGraphCanvas, type CanvasHandle } from "./AssetGraphCanvas";
import { buildModel, type FilterState } from "./model";
import type { AssetEdge, AssetNode } from "./types";

const NODES: AssetNode[] = [
  { id: "agentA", type: "agent", name: "agentA", properties: { namespace: "payments", agent_class: "payments-bot", trust_score: 0.82 } },
  { id: "tool:execute_sql", type: "tool", name: "execute_sql", properties: { namespace: "payments", risk_level: "critical", call_count: 10 } as AssetNode["properties"] },
];
const EDGES: AssetEdge[] = [
  { source: "agentA", target: "tool:execute_sql", type: "calls", weight: 1, properties: { decision_history: { allow: 5, block: 7, escalate: 0 } } },
];
const FILTERS: FilterState = {
  search: "", types: { agent: true, tool: true, data: true },
  risks: { low: true, medium: true, high: true, critical: true },
  agentClass: "all", blockedOnly: false, focus: null, selectedId: null,
};

function renderCanvas() {
  const ref = createRef<CanvasHandle>();
  const errors: unknown[] = [];
  const onErr = (e: ErrorEvent) => errors.push(e.error);
  window.addEventListener("error", onErr);
  const utils = render(
    <AssetGraphCanvas
      ref={ref}
      model={buildModel(NODES, EDGES)}
      filters={FILTERS}
      nsColor={() => "#2ddab8"}
      onSelect={() => {}}
      onFocusAgent={() => {}}
      onSelectedSide={() => {}}
    />
  );
  window.removeEventListener("error", onErr);
  return { ref, errors, ...utils };
}

describe("AssetGraphCanvas — render-timing safety", () => {
  it("mounts at zero container size without throwing, and renders the svg", () => {
    const { errors, getByTestId } = renderCanvas();
    expect(getByTestId("asset-graph-canvas").tagName.toLowerCase()).toBe("svg");
    expect(errors).toEqual([]);
  });

  it("imperative methods called before a resolved size do not throw", () => {
    const { ref } = renderCanvas();
    // dims() is null/zero-guarded and the sim guards short-circuit — none of these should throw
    expect(() => {
      ref.current?.relayout();
      ref.current?.fitView();
      ref.current?.zoomBy(1.2);
    }).not.toThrow();
  });
});
