import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { SimulateAttackButton } from "./SimulateAttackButton";
import type { AttackPath } from "./types";

const path: AttackPath = {
  path_id: "p1",
  source_id: "spiffe://norviq/ns/default/sa/customer-support",
  target_id: "users-table",
  steps: [{ step_num: 1, node_id: "n", action: "execute_sql", policy_check: "would_block" }],
  risk_score: 0.9,
  severity: "critical",
  mitre_techniques: [],
  blocked_by_policy: true
};

describe("SimulateAttackButton (#6)", () => {
  it("calls onSimulate with the path and renders 'blocked' from a block decision", async () => {
    const onSimulate = vi.fn().mockResolvedValue({ blocked: true });
    render(<SimulateAttackButton path={path} onSimulate={onSimulate} />);
    fireEvent.click(screen.getByRole("button", { name: /simulate/i }));
    await waitFor(() => expect(onSimulate).toHaveBeenCalledWith(path));
    expect(await screen.findByText(/blocked by policy/i)).toBeInTheDocument();
  });

  it("renders 'policy gap' when the decision allows", async () => {
    const onSimulate = vi.fn().mockResolvedValue({ blocked: false });
    render(<SimulateAttackButton path={path} onSimulate={onSimulate} />);
    fireEvent.click(screen.getByRole("button", { name: /simulate/i }));
    expect(await screen.findByText(/policy gap/i)).toBeInTheDocument();
  });

  it("is disabled when no path is selected", () => {
    const onSimulate = vi.fn().mockResolvedValue({ blocked: false });
    render(<SimulateAttackButton path={undefined} onSimulate={onSimulate} />);
    expect(screen.getByRole("button", { name: /simulate/i })).toBeDisabled();
  });
});
