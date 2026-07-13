// SPDX-License-Identifier: Apache-2.0
// Redesigned legend overlay: node types + edge decisions + risk rings.
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AssetGraphLegend } from "./AssetGraphLegend";

describe("AssetGraphLegend (redesign)", () => {
  it("renders node types, decisions, and risk rings", () => {
    render(<AssetGraphLegend />);
    expect(screen.getByText("Agent")).toBeInTheDocument();
    expect(screen.getByText("Tool")).toBeInTheDocument();
    expect(screen.getByText("Data")).toBeInTheDocument();
    expect(screen.getByText("Call")).toBeInTheDocument();
    expect(screen.getByText("Blocked")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });
});
