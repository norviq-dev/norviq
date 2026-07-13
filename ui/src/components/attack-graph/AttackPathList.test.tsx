import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AttackPathList } from "./AttackPathList";
import type { ThreatPath } from "./types";

const paths: ThreatPath[] = [
  {
    id: "p2", sev: "high", src: "billing-runner", tgt: "postgresql/ledger", ns: "payments", cls: "payments",
    mitre: "T1041 · Exfiltration", hops: 2, trust: 0.61, blast: 4, status: "exploitable", tool: "issue_refund",
    reach: [{ n: "tax-records", s: 1 }],
    steps: [{ from: "billing-runner", to: "issue_refund", verb: "calls", dec: "mixed", kind: "tool", deny: 6, allow: 68 }],
    verdict: "EXPLOITABLE", fix: "Scope issue_refund"
  }
];

describe("AttackPathList", () => {
  it("renders the ranked row (src→tgt + status) and selects on click", () => {
    const onSelect = vi.fn();
    render(<AttackPathList paths={paths} statusOf={(p) => p.status} onSelect={onSelect} />);
    expect(screen.getByText(/billing-runner/)).toBeInTheDocument();
    expect(screen.getByText(/EXPLOITABLE/)).toBeInTheDocument();
    fireEvent.click(screen.getByText(/billing-runner/));
    expect(onSelect).toHaveBeenCalledWith(paths[0]);
  });

  it("shows the chokepoint tool's classification-lifecycle stage as a chip on every card", () => {
    const mk = (id: string, tool: string, step: Partial<ThreatPath["steps"][0]>): ThreatPath => ({
      ...paths[0], id, tool,
      steps: [{ from: "a", to: tool, verb: "calls", dec: "allow", kind: "tool", deny: 0, allow: 1, ...step }]
    });
    const four = [
      mk("l1", "etl_load", { op: "delete", op_src: "learned", op_risk: "critical" }),
      mk("r1", "execute_sql", { op: "delete", op_src: "registry", op_risk: "critical" }),
      mk("o1", "warehouse_task", { op: null, inferred_verb: "delete", inferred_count: 10, observed_calls: 12 }),
      mk("u1", "frobnicate", { op: null })
    ];
    render(<AttackPathList paths={four} statusOf={(p) => p.status} onSelect={() => {}} />);
    const chips = screen.getAllByTestId("path-lifecycle-chip").map((c) => c.textContent);
    expect(chips).toEqual(["✓ delete · learned", "delete", "observing 10/12", "unclassified"]);
  });

  it("P2: the selected-row background is neutral grey, not blue/indigo", () => {
    const { getByRole } = render(
      <AttackPathList paths={paths} selectedId="p2" statusOf={(p) => p.status} onSelect={() => {}} />
    );
    // rgb(35,35,35) === #232323 — a neutral grey (r===g===b). The old #181026 was indigo (b > r).
    const row = getByRole("button", { pressed: true });
    const bg = row.style.background || row.style.backgroundColor;
    const m = bg.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/) || bg.match(/#([0-9a-f]{6})/i);
    if (m && m.length === 4) {
      const [r, g, b] = [Number(m[1]), Number(m[2]), Number(m[3])];
      expect(r).toBe(g);
      expect(g).toBe(b); // pure grey → no blue tint
    } else {
      expect(bg.toLowerCase()).toContain("#232323");
    }
    // The intentional purple selection accent (inset shadow) is preserved.
    expect(row.style.boxShadow).toContain("#c084fc");
  });
});
