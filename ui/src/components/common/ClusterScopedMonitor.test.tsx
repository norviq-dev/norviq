// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// fleet-mgmt Stage 3 — the monitor wrapper renders local pages unchanged, renders hub data when a remote spoke is
// FRESH, and falls back to the deep-link when the spoke is stale/unreachable. freshnessLabel bounds "fresh".

import { render, screen, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

const mockUseApp = vi.fn();
const fetchFleetClusters = vi.fn();
vi.mock("../../store/AppContext", () => ({ useApp: () => mockUseApp() }));
vi.mock("../../api/fleet", () => ({ fetchFleetClusters: () => fetchFleetClusters() }));

import { ClusterScopedMonitor, freshnessLabel } from "./ClusterScopedMonitor";

const nowISO = () => new Date(Date.now() - 5000).toISOString();
const oldISO = () => new Date(Date.now() - 10 * 60 * 1000).toISOString();

describe("freshnessLabel", () => {
  it("fresh within the window, stale beyond it, none without a heartbeat", () => {
    expect(freshnessLabel(nowISO()).fresh).toBe(true);
    expect(freshnessLabel(oldISO()).fresh).toBe(false);
    expect(freshnessLabel(null).fresh).toBe(false);
  });
});

describe("ClusterScopedMonitor", () => {
  it("renders the local page unchanged when not remote", () => {
    mockUseApp.mockReturnValue({ isRemote: false, scopeCluster: "fleet-a", selectedCluster: "fleet-a", selectedClusterConsoleUrl: "" });
    render(<ClusterScopedMonitor page="Agents" hubView={() => <div>HUB</div>}><div>LOCAL</div></ClusterScopedMonitor>);
    expect(screen.getByText("LOCAL")).toBeInTheDocument();
  });

  it("renders the hub view when the remote spoke is fresh", async () => {
    mockUseApp.mockReturnValue({ isRemote: true, scopeCluster: "fleet-b", selectedCluster: "fleet-b", selectedClusterConsoleUrl: "" });
    fetchFleetClusters.mockResolvedValue([{ id: "fleet-b", status: "healthy", last_heartbeat: nowISO() }]);
    render(<ClusterScopedMonitor page="Agents" hubView={() => <div>HUB VIEW</div>}><div>LOCAL</div></ClusterScopedMonitor>);
    await waitFor(() => expect(screen.getByText("HUB VIEW")).toBeInTheDocument());
    expect(screen.queryByText("LOCAL")).not.toBeInTheDocument();
  });

  it("falls back to the deep-link when the remote spoke is stale", async () => {
    mockUseApp.mockReturnValue({ isRemote: true, scopeCluster: "fleet-c", selectedCluster: "fleet-c", selectedClusterConsoleUrl: "http://c" });
    fetchFleetClusters.mockResolvedValue([{ id: "fleet-c", status: "stale", last_heartbeat: oldISO() }]);
    render(<ClusterScopedMonitor page="Agents" hubView={() => <div>HUB VIEW</div>}><div>LOCAL</div></ClusterScopedMonitor>);
    await waitFor(() => expect(screen.getByRole("link", { name: /open fleet-c/i })).toBeInTheDocument());
    expect(screen.queryByText("HUB VIEW")).not.toBeInTheDocument();
  });
});
