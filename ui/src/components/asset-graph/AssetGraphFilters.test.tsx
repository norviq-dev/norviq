// SPDX-License-Identifier: Apache-2.0
// Redesigned filter bar: custom dark dropdown menus (single-select, ✓ on current), search, and
// Type / Risk chips. The Cluster dropdown is composed by the page ONLY when fleetEnabled — here we
// assert the bar renders exactly the dropdown specs it is given.
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { AssetGraphFilters, type DropdownSpec } from "./AssetGraphFilters";

function makeProps(overrides: Partial<Parameters<typeof AssetGraphFilters>[0]> = {}) {
  const onSelect = vi.fn();
  const dropdowns: DropdownSpec[] = [
    { key: "ns", title: "Namespace", value: "all", options: [{ value: "all", label: "All namespaces (2)" }, { value: "payments", label: "payments" }], onSelect },
    { key: "class", title: "Agent class", value: "all", options: [{ value: "all", label: "All classes" }], onSelect: vi.fn() }
  ];
  return {
    props: {
      dropdowns,
      openMenu: null as string | null,
      onToggleMenu: vi.fn(),
      search: "",
      onSearch: vi.fn(),
      types: { agent: true, tool: true, data: true },
      onToggleType: vi.fn(),
      risks: { low: true, medium: true, high: true, critical: true },
      onToggleRisk: vi.fn(),
      ...overrides
    },
    onSelect
  };
}

describe("AssetGraphFilters (redesign)", () => {
  it("renders custom dropdown buttons (not native selects)", () => {
    const { props } = makeProps();
    render(<AssetGraphFilters {...props} />);
    expect(screen.getByRole("button", { name: /namespace/i })).toHaveTextContent("All namespaces (2)");
    expect(document.querySelector("select")).toBeNull();
  });

  it("opens the menu via onToggleMenu and selects an option", () => {
    const { props, onSelect } = makeProps({ openMenu: "ns" });
    render(<AssetGraphFilters {...props} />);
    fireEvent.click(screen.getByRole("option", { name: /payments/i }));
    expect(onSelect).toHaveBeenCalledWith("payments");
  });

  it("omits the Cluster dropdown when the page did not compose one (single-cluster)", () => {
    const { props } = makeProps();
    render(<AssetGraphFilters {...props} />);
    expect(screen.queryByRole("button", { name: /^cluster$/i })).toBeNull();
  });

  it("renders the Cluster dropdown when the page composes it (multi-cluster/fleet)", () => {
    const { props } = makeProps();
    props.dropdowns = [
      ...props.dropdowns,
      { key: "cluster", title: "Cluster", value: "aks-dev", options: [{ value: "aks-dev", label: "aks-dev" }], onSelect: vi.fn() }
    ];
    render(<AssetGraphFilters {...props} />);
    expect(screen.getByRole("button", { name: /^cluster$/i })).toHaveTextContent("aks-dev");
  });

  it("toggles type and risk chips", () => {
    const { props } = makeProps();
    render(<AssetGraphFilters {...props} />);
    fireEvent.click(screen.getByRole("button", { name: /^tool$/i }));
    expect(props.onToggleType).toHaveBeenCalledWith("tool");
    fireEvent.click(screen.getByRole("button", { name: /^critical$/i }));
    expect(props.onToggleRisk).toHaveBeenCalledWith("critical");
  });

  it("fires search changes", () => {
    const { props } = makeProps();
    render(<AssetGraphFilters {...props} />);
    fireEvent.change(screen.getByLabelText(/search node name/i), { target: { value: "sql" } });
    expect(props.onSearch).toHaveBeenCalledWith("sql");
  });
});
