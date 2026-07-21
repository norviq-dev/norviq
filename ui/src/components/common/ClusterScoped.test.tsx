// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The per-cluster page gate renders the real page only when local; when a remote cluster is selected
// it renders the honest deep-link page instead (so the page never mounts → no local fetch, no controls).

import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

const mockUseApp = vi.fn();
vi.mock("../../store/AppContext", () => ({ useApp: () => mockUseApp() }));

import { ClusterScoped } from "./ClusterScoped";

describe("ClusterScoped", () => {
  it("renders children for a local selection", () => {
    mockUseApp.mockReturnValue({ isRemote: false, scopeCluster: "fleet-a", selectedClusterConsoleUrl: "" });
    render(
      <ClusterScoped page="Policy Catalog">
        <div>REAL PAGE</div>
      </ClusterScoped>
    );
    expect(screen.getByText("REAL PAGE")).toBeInTheDocument();
  });

  it("renders the deep-link page (NOT the children) for a remote selection", () => {
    mockUseApp.mockReturnValue({
      isRemote: true,
      scopeCluster: "fleet-b",
      selectedClusterConsoleUrl: "http://127.0.0.1:18081"
    });
    render(
      <ClusterScoped page="Policy Catalog">
        <div>REAL PAGE</div>
      </ClusterScoped>
    );
    expect(screen.queryByText("REAL PAGE")).not.toBeInTheDocument();
    const link = screen.getByRole("link", { name: /open fleet-b/i });
    expect(link).toHaveAttribute("href", "http://127.0.0.1:18081");
  });

  it("falls back to guidance (no dead link) when the console URL is unknown", () => {
    mockUseApp.mockReturnValue({ isRemote: true, scopeCluster: "fleet-c", selectedClusterConsoleUrl: "" });
    render(
      <ClusterScoped page="Audit Log">
        <div>REAL PAGE</div>
      </ClusterScoped>
    );
    expect(screen.queryByText("REAL PAGE")).not.toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText(/own console to view this/i)).toBeInTheDocument();
  });
});
