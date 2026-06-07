import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AttackPathDetail } from "./AttackPathDetail";

describe("AttackPathDetail", () => {
  it("shows placeholder when no path selected", () => {
    render(<AttackPathDetail />);
    expect(screen.getByText(/select a path/i)).toBeInTheDocument();
  });
});
