// SPDX-License-Identifier: Apache-2.0
//
// Tests for the kill-chain canvas. This component had NO tests at all, and three of the findings on
// this branch live inside it: a hardcoded time window on a range-scoped number, a redraw keyed on an
// id the server deliberately holds stable across content changes, and attacker-controlled names
// rendered as if the product authored them.
//
// The canvas is d3 painting into an <svg>, so the assertions read the emitted SVG: label text, line
// strokes, and the ScopeCard payload the click handler produces.
import { fireEvent, render } from "@testing-library/react";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { AttackGraphCanvas, type ScopeCard } from "./AttackGraphCanvas";
import type { ThreatPath } from "./types";

// jsdom implements neither getBBox nor a layout engine; fitView() reads getBBox on every draw.
beforeAll(() => {
  (window.SVGElement.prototype as unknown as { getBBox: () => DOMRect }).getBBox = () =>
    ({ x: 0, y: 0, width: 400, height: 500 }) as DOMRect;
});

/** The most recent ScopeCard the click handler produced. (`Array.prototype.at` is ES2022; this
 *  project's tsconfig targets ES2020 lib.) */
const lastScope = (fn: { mock: { calls: unknown[][] } }) => fn.mock.calls[fn.mock.calls.length - 1][0];
const texts = (c: HTMLElement) => Array.from(c.querySelectorAll("text")).map((t) => t.textContent ?? "");
const strokes = (c: HTMLElement) => Array.from(c.querySelectorAll("line.ed")).map((l) => l.getAttribute("stroke") ?? "");
/** The <g> for a chain node, located by the node-name label d3 wrote into it. */
function nodeG(c: HTMLElement, id: string): SVGGElement {
  const g = Array.from(c.querySelectorAll<SVGGElement>("g.ak-node")).find((el) =>
    Array.from(el.querySelectorAll("text")).some((t) => t.textContent === id)
  );
  if (!g) throw new Error(`no chain node labelled ${JSON.stringify(id)} — labels: ${JSON.stringify(texts(c))}`);
  return g;
}

const BASE: ThreatPath = {
  id: "p0123456789", sev: "critical", src: "report-gen", tgt: "postgresql/payments",
  ns: "payments", cls: "reporting", mitre: "T1190", hops: 2, trust: 0.5, blast: 3,
  status: "exploitable", tool: "execute_sql",
  reach: [{ n: "stripe-keys", s: 1 }],
  steps: [
    { from: "report-gen", to: "execute_sql", verb: "calls", dec: "allow", kind: "tool", deny: 0, allow: 9 },
    { from: "execute_sql", to: "postgresql/payments", verb: "reaches", dec: "allow", kind: "data", deny: 0, allow: 9 }
  ],
  verdict: "exploitable", fix: ""
};

function renderCanvas(props: Partial<React.ComponentProps<typeof AttackGraphCanvas>> = {}) {
  const onScope = vi.fn();
  const utils = render(
    <AttackGraphCanvas
      path={BASE}
      allPaths={[BASE]}
      whatIfIndex={-1}
      onToggleWhatIf={() => {}}
      onScope={onScope}
      {...props}
    />
  );
  return { ...utils, onScope };
}

// ── the scope card's denial window ────────────────────────────────────────────────────────────
//
// `deny` is aggregated server-side over RANGE_HOURS[range] (threats.py), i.e. over whatever the
// Range dropdown asked for. The card captioned that number "Denials · 24h" no matter what, so with
// Range on "Last 30d" a month of denials was presented as a day's — a ~30x overstatement of how hot
// the node is right now, on the card whose whole job is "what can this node touch".
describe("AttackGraphCanvas — the scope card states the window it actually measured", () => {
  const busy: ThreatPath = {
    ...BASE,
    steps: [
      { from: "report-gen", to: "execute_sql", verb: "calls", dec: "mixed", kind: "tool", deny: 512, allow: 40 },
      { ...BASE.steps[1] }
    ]
  };

  it("labels the denial row with the ACTIVE range, not a hardcoded 24h", () => {
    const { container, onScope } = renderCanvas({ path: busy, allPaths: [busy], range: "30d" });
    fireEvent.click(nodeG(container, "execute_sql"));
    const card = lastScope(onScope) as ScopeCard;
    const row = card.rows.find((r) => r.k.startsWith("Denials"))!;
    expect(row.v).toBe("512");
    expect(row.k).toBe("Denials · 30d");
    // the exact string the operator used to read over a thirty-day total
    expect(row.k).not.toBe("Denials · 24h");
  });

  it("says a bare 'Denials' rather than inventing a window when none was passed", () => {
    const { container, onScope } = renderCanvas({ path: busy, allPaths: [busy] });
    fireEvent.click(nodeG(container, "execute_sql"));
    const card = lastScope(onScope) as ScopeCard;
    expect(card.rows.find((r) => r.k.startsWith("Denials"))!.k).toBe("Denials");
  });
});

// ── redraw on new data under the same path id ─────────────────────────────────────────────────
//
// The server's path id is _short_id(ns, first_node, last_node, len(node_ids)) — independent of the
// range and of the decision history. Keying the redraw effect on `path.id` meant a Range switch, a
// Recompute, or a verb promotion (all of which refetch without clearing `paths`, so the canvas is
// never remounted) left the OLD picture on screen beside a freshly-updated inspector.
describe("AttackGraphCanvas — redraws when the same path id carries new data", () => {
  const AFTER: ThreatPath = {
    ...BASE, // SAME id on purpose — that is the whole point
    steps: [
      {
        from: "report-gen", to: "execute_sql", verb: "calls", dec: "block", kind: "tool",
        deny: 41, allow: 0, op: "delete", op_risk: "critical", op_src: "learned"
      },
      { from: "execute_sql", to: "postgresql/payments", verb: "reaches", dec: "block", kind: "data", deny: 41, allow: 0 }
    ]
  };

  it("repaints hop decisions and the tool's lifecycle caption on a same-id prop swap", () => {
    const { container, rerender } = renderCanvas();
    expect(texts(container)).toContain("9 allowed");
    expect(texts(container)).toContain("unclassified · observing");
    expect(new Set(strokes(container))).toEqual(new Set(["#00E5A0"]));

    rerender(
      <AttackGraphCanvas path={AFTER} allPaths={[AFTER]} whatIfIndex={-1} onToggleWhatIf={() => {}} onScope={() => {}} />
    );

    // pre-fix this block failed byte-for-byte: the canvas still read "9 allowed" in green.
    expect(texts(container)).toContain("⚠ 41 denied");
    expect(texts(container)).toContain("delete · learned");
    expect(texts(container)).not.toContain("9 allowed");
    expect(new Set(strokes(container))).toEqual(new Set(["#FF3B5C"]));
  });

  it("repaints the blast radius when reach[] changes under the same id", () => {
    const { container, rerender } = renderCanvas();
    expect(texts(container)).toContain("⬥ stripe-keys");
    const moved: ThreatPath = { ...BASE, reach: [{ n: "tax-records", s: 1 }] };
    rerender(
      <AttackGraphCanvas path={moved} allPaths={[moved]} whatIfIndex={-1} onToggleWhatIf={() => {}} onScope={() => {}} />
    );
    expect(texts(container)).toContain("⬥ tax-records");
    expect(texts(container)).not.toContain("⬥ stripe-keys");
  });

  it("does NOT redraw when the parent re-renders with equivalent data", () => {
    // The guard on the fix: a signature, not the raw object. Passing a fresh-but-identical path must
    // not tear down and rebuild the d3 world (that would redraw on every keystroke upstream).
    const { container, rerender } = renderCanvas();
    const before = container.querySelector("g.ak-node");
    rerender(
      <AttackGraphCanvas
        path={{ ...BASE, steps: BASE.steps.map((s) => ({ ...s })) }}
        allPaths={[BASE]}
        whatIfIndex={-1}
        onToggleWhatIf={() => {}}
        onScope={() => {}}
      />
    );
    expect(container.querySelector("g.ak-node")).toBe(before); // same DOM node = no re-draw
  });
});

// ── attacker-controlled names ─────────────────────────────────────────────────────────────────
//
// Node ids are OBSERVED names. `exеcute_sql` (Cyrillic е, U+0435) is pixel-identical to
// `execute_sql` in the console font, and the kill-chain drew the impostor exactly like the tool the
// operator trusts. The repo's own detector (lookalikeOf) already exists for this.
describe("AttackGraphCanvas — a lookalike name is marked, not drawn as the real one", () => {
  const TWIN = "exеcute_sql"; // Cyrillic е
  const spoofed: ThreatPath = {
    ...BASE, tool: TWIN,
    steps: [
      { from: "report-gen", to: TWIN, verb: "calls", dec: "allow", kind: "tool", deny: 0, allow: 3 },
      { from: TWIN, to: "postgresql/payments", verb: "reaches", dec: "allow", kind: "data", deny: 0, allow: 3 }
    ]
  };

  it("marks the node with the masked form and the codepoint", () => {
    const { container } = renderCanvas({ path: spoofed, allPaths: [spoofed] });
    const marks = texts(container).filter((t) => t.includes("lookalike"));
    expect(marks).toHaveLength(1);
    expect(marks[0]).toContain("ex·cute_sql"); // position of the invisible character
    expect(marks[0]).toContain("U+0435");
    // the name itself is still shown exactly as stored — never silently "cleaned up"
    expect(texts(container)).toContain(TWIN);
  });

  it("says nothing about plain-ASCII names", () => {
    const { container } = renderCanvas();
    expect(texts(container).filter((t) => t.includes("lookalike"))).toHaveLength(0);
  });

  it("marks a homoglyph in the BLAST RADIUS too, not only on the chain", () => {
    // `reach[]` names are observed asset names as well. Marking only the chain left the fan as an
    // unmarked hiding place for a twin of the crown jewel the operator is scanning for — and the fan
    // is exactly where they look to answer "what else does this reach".
    const TWIN_ASSET = "stripe-kеys"; // Cyrillic е in "keys"
    const { container } = renderCanvas({
      path: { ...BASE, reach: [{ n: TWIN_ASSET, s: 1 }] },
      allPaths: [BASE]
    });
    const marks = texts(container).filter((t) => t.includes("lookalike"));
    expect(marks).toHaveLength(1);
    expect(marks[0]).toContain("stripe-k·ys");
    expect(marks[0]).toContain("U+0435");
    expect(texts(container)).toContain(`⬥ ${TWIN_ASSET}`); // name still shown exactly as observed
  });

  it("repeats the warning on the scope card, where the operator acts on it", () => {
    const { container, onScope } = renderCanvas({ path: spoofed, allPaths: [spoofed] });
    fireEvent.click(nodeG(container, TWIN));
    const card = lastScope(onScope) as ScopeCard;
    const row = card.rows.find((r) => r.k === "Name");
    expect(row).toBeDefined();
    expect(row!.v).toContain("U+0435");
  });
});
