import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AssetNodeDetail } from "./AssetNodeDetail";
import type { AssetNode } from "./types";

const mockNode: AssetNode = {
  id: "agent-1",
  type: "agent",
  name: "customer-support",
  properties: {
    namespace: "studioai",
    spiffe_id: "spiffe://norviq/ns/studioai/sa/customer-support",
    trust_score: 0.85,
    risk_level: "critical",
    tool_call_count: 47
  }
};

describe("AssetNodeDetail", () => {
  it("renders details and close callback", () => {
    const onClose = vi.fn();
    render(
      <MemoryRouter>
        <AssetNodeDetail node={mockNode} onClose={onClose} />
      </MemoryRouter>
    );
    expect(screen.getByText("AGENT")).toBeInTheDocument();
    expect(screen.getByText("customer-support")).toBeInTheDocument();
    fireEvent.click(screen.getByText("x"));
    expect(onClose).toHaveBeenCalled();
  });
});
