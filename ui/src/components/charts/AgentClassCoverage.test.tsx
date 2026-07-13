import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AgentClassCoverage } from "./AgentClassCoverage";
import type { AgentClassPolicy } from "../../api/client";

const POLICY: AgentClassPolicy = {
  cls: "report-gen", kind: "intent", allow_tools: ["warehouse_task"], refinements: ["readonly"],
  learned_verbs: ["warehouse_task=delete"], priority: 100, enforcement_mode: "block",
  enforcing: false, observed: 14, blocked: 0, would_block: 10, effective: true,
};

describe("AgentClassCoverage", () => {
  it("renders a color-coded bar per governed class (state = colour, no text badge)", () => {
    render(<AgentClassCoverage policies={[POLICY]} namespaceMode="audit" />);
    expect(screen.getByText("report-gen")).toBeInTheDocument();
    const row = screen.getByTestId("agent-class-cov-row");
    // The bar's fill carries the state via colour + opacity — it's the only div with an inline opacity
    // (dimmed under Monitor since enforcing:false), coloured green (#00E5A0) because effective:true.
    const fill = [...row.querySelectorAll("div")].find((d) => d.style.opacity !== "") as HTMLElement;
    expect(fill).toBeTruthy();
    expect(Number(fill.style.opacity)).toBeLessThan(1);
    expect(fill.style.background).toBe("rgb(0, 229, 160)"); // #00E5A0 green tier (jsdom normalizes to rgb)
    // No verbose state text badge in the resting card — the detail is hover-only.
    expect(row.textContent).not.toMatch(/loaded · monitor/i);
  });

  it("hover reveals WHAT is enforced — allowlist, refinements, learned verbs, efficacy", () => {
    render(<AgentClassCoverage policies={[POLICY]} namespaceMode="audit" />);
    fireEvent.mouseEnter(screen.getByTestId("agent-class-cov-row"));
    const tip = screen.getByRole("tooltip");
    expect(tip).toHaveTextContent(/Positive-security/);
    expect(tip).toHaveTextContent(/warehouse_task/);
    expect(tip).toHaveTextContent(/Read-only/);
    expect(tip).toHaveTextContent(/warehouse_task=delete/);
    expect(tip).toHaveTextContent(/10.*would-block/i);
  });

  it("renders nothing when there are no agent-class policies", () => {
    const { container } = render(<AgentClassCoverage policies={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("caps a long list at 6 rows and folds the rest behind '+N more'", () => {
    const many = Array.from({ length: 10 }, (_, i) => ({ ...POLICY, cls: `class-${i}` }));
    render(<AgentClassCoverage policies={many} namespaceMode="block" />);
    // only the first 6 render at rest; a "+4 more" toggle folds the remainder
    expect(screen.getAllByTestId("agent-class-cov-row")).toHaveLength(6);
    const more = screen.getByRole("button", { name: /\+4 more classes/i });
    fireEvent.click(more);
    expect(screen.getAllByTestId("agent-class-cov-row")).toHaveLength(10);
    // and it collapses back
    fireEvent.click(screen.getByRole("button", { name: /show fewer/i }));
    expect(screen.getAllByTestId("agent-class-cov-row")).toHaveLength(6);
  });
});
