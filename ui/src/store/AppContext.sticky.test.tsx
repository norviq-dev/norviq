// SPDX-License-Identifier: Apache-2.0
// The selected namespace is STICKY — persisted to localStorage so it survives navigation / remount instead
// of resetting to the aggregate "All namespaces".
import { render, screen, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppProvider, useApp } from "./AppContext";

// No token → the cluster/namespace load() + posture effects no-op, so we isolate the sticky state machine.
vi.mock("../auth/session", () => ({ getToken: () => null, tokenSubject: () => null }));
vi.mock("../auth/oidc", () => ({ oidcEnabled: false, login: () => Promise.resolve() }));
vi.mock("../api/client", () => ({
  fetchClusterInfo: () => Promise.reject(new Error("no net")),
  fetchSettings: () => Promise.reject(new Error("no net"))
}));
vi.mock("../api/fleet", () => ({ fleetEnabled: false, fetchFleetClusters: () => Promise.resolve([]) }));
vi.mock("../api/clusterGuard", () => ({ setRemoteClusterContext: () => {}, setSelectedClusterId: () => {} }));

function Probe() {
  const { namespace, setNamespace } = useApp();
  return (
    <div>
      <span data-testid="ns">{namespace}</span>
      <button onClick={() => setNamespace("payments")}>pick</button>
    </div>
  );
}

// AppProvider now syncs ?ns= with the router, so it needs a Router in tests too.
function mount() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <Probe />
      </AppProvider>
    </MemoryRouter>
  );
}

beforeEach(() => localStorage.clear());
afterEach(() => localStorage.clear());

describe("AppContext sticky namespace", () => {
  it("defaults to the aggregate 'all' when nothing is stored (no silent auto-default)", () => {
    mount();
    expect(screen.getByTestId("ns")).toHaveTextContent("all");
  });

  it("setNamespace persists to localStorage and a fresh mount restores it (survives navigation)", () => {
    const first = mount();
    act(() => { screen.getByText("pick").click(); });
    expect(screen.getByTestId("ns")).toHaveTextContent("payments");
    expect(localStorage.getItem("nrvq_namespace")).toBe("payments");
    first.unmount();
    // a subsequent navigation mounts a fresh provider — the concrete namespace STICKS (not reset to "all")
    mount();
    expect(screen.getByTestId("ns")).toHaveTextContent("payments");
  });
});
