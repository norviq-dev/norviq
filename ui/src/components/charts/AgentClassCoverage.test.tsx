// Tests for the AgentClassCoverage chart — per-agent-class policy coverage bars shown on the Overview.
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

  // The Overview's default scope is "all" (AppContext.initialNamespace), and at that scope
  // coverage.py's `_agent_class_policies` runs with namespace=None and selects
  // `DISTINCT ON (namespace, agent_class)` — unique per PAIR, so one class name governed in two
  // namespaces arrives as two rows. `_parse_agent_policy` emits no `namespace` key and
  // `AgentClassPolicy` has no such field, so the discriminator is gone by the time it reaches here.
  const PAYMENTS: AgentClassPolicy = { ...POLICY, allow_tools: ["search_kb", "get_order"], refinements: ["readonly"] };
  const HR: AgentClassPolicy = { ...POLICY, allow_tools: ["execute_sql", "delete_record"], refinements: ["egress"] };

  it("shows the hovered row's own policy when one class name arrives twice", () => {
    // Keyed on `cls`, BOTH rows matched the hover and both portaled tooltips were painted at the
    // hovered row's rect — so the one on top (last in the DOM) was the OTHER row's allowlist. The
    // operator read one class's intended tools as another's.
    render(<AgentClassCoverage policies={[PAYMENTS, HR]} namespaceMode="block" />);
    const rows = screen.getAllByTestId("agent-class-cov-row");
    expect(rows).toHaveLength(2);
    fireEvent.mouseEnter(rows[0]);
    expect(screen.getAllByRole("tooltip")).toHaveLength(1);
    expect(screen.getByRole("tooltip")).toHaveTextContent("search_kb");
    expect(screen.getByRole("tooltip")).not.toHaveTextContent("execute_sql");
    fireEvent.mouseLeave(rows[0]);
    fireEvent.mouseEnter(rows[1]);
    expect(screen.getAllByRole("tooltip")).toHaveLength(1);
    expect(screen.getByRole("tooltip")).toHaveTextContent("execute_sql");
  });

  it("says two identically-labelled rows are two namespaces it cannot name", () => {
    // Two rows reading `report-gen`, byte-identical on screen, is a label that does not identify
    // what it labels. The payload carries no namespace, so the honest statement is that the console
    // cannot tell them apart — not silence.
    render(<AgentClassCoverage policies={[PAYMENTS, HR]} namespaceMode="block" />);
    const note = screen.getByTestId("agent-class-dup-note");
    expect(note).toHaveTextContent(/report-gen/);
    expect(note).toHaveTextContent(/more than one namespace/i);
  });

  it("stays quiet when every class name is distinct", () => {
    render(<AgentClassCoverage policies={[POLICY, { ...POLICY, cls: "support-agent" }]} namespaceMode="block" />);
    expect(screen.queryByTestId("agent-class-dup-note")).not.toBeInTheDocument();
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
