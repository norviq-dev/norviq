// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// TWO MAPS OF THE SAME ESTATE MUST NOT DISAGREE ABOUT WHETHER A NAME IS TRUSTWORTHY.
//
// Every node name on this canvas is OBSERVED traffic — a tool_name an agent registered, an agent
// identity, a data source. That is attacker-controlled text, and `exеcute_sql` (U+0435 CYRILLIC
// SMALL LETTER IE) renders pixel-identical to `execute_sql` in the console's font.
//
// The sibling kill-chain canvas already states this in its own header comment and captions such a
// node "⚠ lookalike · ex·cute_sql · U+0435" (components/attack-graph/AttackGraphCanvas.tsx's
// `lookalikeCaption`). The asset graph drew the same name in the same font with nothing at all — so
// an operator tracing "what can this agent reach" saw two nodes captioned `execute_sql` and read it
// as a rendering duplicate rather than an impostor tool the agent is quietly calling. The quiet
// surface is the one used to answer the reachability question.
//
// Same detector (`lookalikeOf`), same caption shape, same amber — not a second mechanism.
import { render } from "@testing-library/react";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { AssetGraphCanvas } from "./AssetGraphCanvas";
import { buildModel, type FilterState } from "./model";
import type { AssetEdge, AssetNode } from "./types";

/** Cyrillic е in third position. */
const TWIN = `exеcute_sql`;
const REAL = "execute_sql";

const NODES: AssetNode[] = [
  { id: "agentA", type: "agent", name: "support-bot", properties: { namespace: "payments", agent_class: "support", trust_score: 0.82 } },
  { id: `tool:${REAL}`, type: "tool", name: REAL, properties: { namespace: "payments", risk_level: "high" } },
  { id: `tool:${TWIN}`, type: "tool", name: TWIN, properties: { namespace: "payments", risk_level: "high" } }
];
const EDGES: AssetEdge[] = [
  { source: "agentA", target: `tool:${REAL}`, type: "calls", weight: 1, properties: { decision_history: { allow: 900, block: 0, escalate: 0 } } },
  { source: "agentA", target: `tool:${TWIN}`, type: "calls", weight: 1, properties: { decision_history: { allow: 12, block: 0, escalate: 0 } } }
];
const FILTERS: FilterState = {
  search: "", types: { agent: true, tool: true, data: true },
  risks: { low: true, medium: true, high: true, critical: true },
  agentClass: "all", blockedOnly: false, focus: null, selectedId: null
};

// jsdom reports clientWidth/Height = 0, which makes the canvas defer its d3 draw entirely. Give the
// container a real size so `draw()` actually runs and the labels reach the DOM.
const realW = Object.getOwnPropertyDescriptor(Element.prototype, "clientWidth");
const realH = Object.getOwnPropertyDescriptor(Element.prototype, "clientHeight");
beforeAll(() => {
  Object.defineProperty(Element.prototype, "clientWidth", { configurable: true, get: () => 1200 });
  Object.defineProperty(Element.prototype, "clientHeight", { configurable: true, get: () => 800 });
  // With a real size, fitView() now runs a d3-zoom transition, and d3-zoom's defaultExtent reads
  // `svg.width.baseVal.value` — an SVG DOM property jsdom does not implement, which surfaces as an
  // uncaught TypeError from the d3 timer AFTER the test body has finished. Purely a jsdom gap.
  Object.defineProperty(window.SVGSVGElement.prototype, "width", {
    configurable: true,
    get: () => ({ baseVal: { value: 1200 } })
  });
  Object.defineProperty(window.SVGSVGElement.prototype, "height", {
    configurable: true,
    get: () => ({ baseVal: { value: 800 } })
  });
});
afterAll(() => {
  if (realW) Object.defineProperty(Element.prototype, "clientWidth", realW);
  if (realH) Object.defineProperty(Element.prototype, "clientHeight", realH);
  // The SVG width/height shims are deliberately NOT torn down: d3's transition timer can still fire
  // after this hook, and removing them there is exactly when the uncaught TypeError reappears. Vitest
  // isolates the environment per test file, so they do not leak to any other suite.
});

function renderCanvas(filters: FilterState = FILTERS) {
  return render(
    <AssetGraphCanvas
      model={buildModel(NODES, EDGES)}
      filters={filters}
      nsColor={() => "#2ddab8"}
      onSelect={() => {}}
      onFocusAgent={() => {}}
      onSelectedSide={() => {}}
    />
  );
}

/** Every <text> the canvas emitted, in DOM order. */
function texts(container: HTMLElement): string[] {
  return [...container.querySelectorAll("text")].map((t) => t.textContent ?? "");
}

describe("an observed node name that is not what it looks like is captioned as such", () => {
  it("captions the homoglyph node the way the kill-chain canvas does", () => {
    const { container } = renderCanvas();
    const all = texts(container);

    // The name itself is still drawn — this is not censorship, it is annotation.
    expect(all).toContain(TWIN);
    // FAIL-ON-BUG: pre-fix the only labels were the bare names, so the two tool nodes were
    // indistinguishable. The caption carries the POSITION (ex·cute_sql), which a codepoint alone
    // cannot tell you, and the codepoint, which the mask alone cannot.
    const captions = all.filter((t) => /lookalike/i.test(t));
    expect(captions).toHaveLength(1);
    expect(captions[0]).toContain("ex·cute_sql");
    expect(captions[0]).toContain("U+0435");
  });

  it("says nothing at all about the plain-ASCII twin", () => {
    const { container } = renderCanvas();
    // Exactly one caption across the whole canvas — the ASCII `execute_sql`, `support-bot` and the
    // namespace hull must stay clean, or the marking stops meaning anything.
    expect(texts(container).filter((t) => /lookalike/i.test(t))).toHaveLength(1);
  });

  // The AGENT's own display name is observed identity text too, and it is not drawn on the node —
  // in cluster mode the node label is blanked and the name is carried by the hull label
  // (`ViewGroup.label` = the agent's name, model.ts:220). A homoglyph agent identity is the one an
  // operator reads as "support-bot's reachability" while looking at an impostor's, so the hull needs
  // the same marking. This half of the fix had no coverage: the suite only asserted the hull STAYS
  // clean for an ASCII name, which a hull that can never caption anything also satisfies.
  it("captions the hull label when the AGENT's own name is the impostor", () => {
    const CYR_AGENT = `suppоrt-bot`; // Cyrillic о (U+043E)
    const { container } = render(
      <AssetGraphCanvas
        model={buildModel(
          [
            { id: "agentB", type: "agent", name: CYR_AGENT, properties: { namespace: "payments", agent_class: "support", trust_score: 0.8 } },
            { id: `tool:${REAL}`, type: "tool", name: REAL, properties: { namespace: "payments", risk_level: "high" } }
          ],
          [{ source: "agentB", target: `tool:${REAL}`, type: "calls", weight: 1, properties: { decision_history: { allow: 9, block: 0, escalate: 0 } } }]
        )}
        filters={FILTERS}
        nsColor={() => "#2ddab8"}
        onSelect={() => {}}
        onFocusAgent={() => {}}
        onSelectedSide={() => {}}
      />
    );
    const captions = texts(container).filter((t) => /lookalike/i.test(t));
    expect(captions).toHaveLength(1);
    expect(captions[0]).toContain("supp·rt-bot");
    expect(captions[0]).toContain("U+043E");
  });

  it("keeps the caption in the amber the canvas already uses for 'review this'", () => {
    const { container } = renderCanvas();
    const el = [...container.querySelectorAll("text")].find((t) => /lookalike/i.test(t.textContent ?? ""));
    // Red on these canvases means an ENFORCED BLOCK; one signal must not carry two meanings.
    expect(el?.getAttribute("fill")).toBe("#ffcf82");
  });
});
