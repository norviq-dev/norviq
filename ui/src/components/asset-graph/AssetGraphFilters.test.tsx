import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AssetGraphFilters } from "./AssetGraphFilters";

const defaultFilters = {
  types: ["agent", "tool", "data", "namespace"] as const,
  riskLevels: ["low", "medium", "high", "critical"] as const,
  search: ""
};

describe("AssetGraphFilters", () => {
  it("renders type checkboxes checked by default", () => {
    render(<AssetGraphFilters filters={{ ...defaultFilters, types: [...defaultFilters.types], riskLevels: [...defaultFilters.riskLevels] }} onChange={vi.fn()} />);
    expect(screen.getByLabelText(/agent/i)).toBeChecked();
    expect(screen.getByLabelText(/tool/i)).toBeChecked();
  });

  it("removes type when checkbox unchecked", () => {
    const onChange = vi.fn();
    render(<AssetGraphFilters filters={{ ...defaultFilters, types: [...defaultFilters.types], riskLevels: [...defaultFilters.riskLevels] }} onChange={onChange} />);
    fireEvent.click(screen.getByLabelText(/tool/i));
    expect(onChange).toHaveBeenCalled();
  });
});
