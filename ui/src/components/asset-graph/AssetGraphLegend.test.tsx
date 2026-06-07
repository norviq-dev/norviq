import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AssetGraphLegend } from "./AssetGraphLegend";

describe("AssetGraphLegend", () => {
  it("renders all node labels", () => {
    render(<AssetGraphLegend />);
    expect(screen.getByText("agent")).toBeInTheDocument();
    expect(screen.getByText("tool")).toBeInTheDocument();
    expect(screen.getByText("data")).toBeInTheDocument();
    expect(screen.getByText("namespace")).toBeInTheDocument();
  });
});
