import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { SimulateAttackButton } from "./SimulateAttackButton";
import type { AttackPath } from "./types";

const path: AttackPath = {
  path_id: "p1",
  source_id: "a",
  target_id: "b",
  steps: [],
  risk_score: 0.8,
  severity: "high",
  mitre_techniques: [],
  blocked_by_policy: false
};

describe("SimulateAttackButton", () => {
  it("handles success path", async () => {
    const onSimulate = vi.fn().mockResolvedValue({ blocked: false });
    render(<SimulateAttackButton path={path} onSimulate={onSimulate} />);
    fireEvent.click(screen.getByText(/simulate attack/i));
    expect(await screen.findByText(/policy gap/i)).toBeInTheDocument();
  });
});
