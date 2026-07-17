// SPDX-License-Identifier: Apache-2.0
// P1 (context architecture): URL ?ns= is the shareable source of scope, the stored selection is
// identity-scoped, and the governance posture of the selected scope is loaded into context.
import { render, screen, act, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppProvider, useApp } from "./AppContext";
import { clearApiCache } from "../hooks/useApi";

const mocks = vi.hoisted(() => ({
  getToken: vi.fn<() => string | null>(() => null),
  tokenSubject: vi.fn<() => string | null>(() => null),
  fetchSettings: vi.fn<(ns?: string) => Promise<unknown>>(() => Promise.reject(new Error("no net")))
}));

vi.mock("../auth/session", () => ({ getToken: mocks.getToken, tokenSubject: mocks.tokenSubject }));
vi.mock("../auth/oidc", () => ({ oidcEnabled: false, login: () => Promise.resolve() }));
vi.mock("../api/client", () => ({
  fetchClusterInfo: () => Promise.reject(new Error("no net")),
  fetchSettings: mocks.fetchSettings
}));
vi.mock("../api/fleet", () => ({ fleetEnabled: false, fetchFleetClusters: () => Promise.resolve([]) }));
vi.mock("../api/clusterGuard", () => ({ setRemoteClusterContext: () => {}, setSelectedClusterId: () => {} }));

function Probe() {
  const { namespace, setNamespace, posture } = useApp();
  const location = useLocation();
  return (
    <div>
      <span data-testid="ns">{namespace}</span>
      <span data-testid="url">{`${location.pathname}${location.search}`}</span>
      <span data-testid="posture">{posture.mode ?? "unknown"}</span>
      <button onClick={() => setNamespace("payments")}>pick</button>
      <button onClick={() => setNamespace("all")}>pick-all</button>
    </div>
  );
}

function mount(initialEntry = "/audit") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <AppProvider>
        <Probe />
      </AppProvider>
    </MemoryRouter>
  );
}

beforeEach(() => {
  localStorage.clear();
  clearApiCache(); // SLIM-SETTINGS: posture now read/write-throughs the shared cache — isolate per test
  mocks.getToken.mockReturnValue(null);
  mocks.tokenSubject.mockReturnValue(null);
  mocks.fetchSettings.mockImplementation(() => Promise.reject(new Error("no net")));
});
afterEach(() => localStorage.clear());

describe("P1-2: namespace ↔ URL", () => {
  it("adopts ?ns= from the URL over the stored selection (shareable links win)", () => {
    localStorage.setItem("nrvq_namespace", "team-a");
    mount("/audit?ns=analytics");
    expect(screen.getByTestId("ns")).toHaveTextContent("analytics");
  });

  it("writes the selection to ?ns= (replace) and drops the param for the 'all' default", async () => {
    mount("/audit");
    act(() => { screen.getByText("pick").click(); });
    await waitFor(() => expect(screen.getByTestId("url")).toHaveTextContent("/audit?ns=payments"));
    act(() => { screen.getByText("pick-all").click(); });
    await waitFor(() => expect(screen.getByTestId("url")).toHaveTextContent(/^\/audit$/));
  });

  it("preserves unrelated query params (audit deep-link filters) when adding ns", async () => {
    mount("/audit?decision=block");
    act(() => { screen.getByText("pick").click(); });
    await waitFor(() => {
      const url = screen.getByTestId("url").textContent ?? "";
      expect(url).toContain("decision=block");
      expect(url).toContain("ns=payments");
    });
  });
});

describe("P1-2: identity-scoped persistence", () => {
  it("a different identity does NOT inherit the previous identity's namespace", () => {
    // admin picked "payments"…
    mocks.tokenSubject.mockReturnValue("admin");
    const first = mount();
    act(() => { screen.getByText("pick").click(); });
    expect(localStorage.getItem("nrvq_namespace_sub")).toBe("admin");
    first.unmount();
    // …then a scoped viewer signs in: the stored ns must not leak to them.
    mocks.tokenSubject.mockReturnValue("viewer-team-a");
    mount();
    expect(screen.getByTestId("ns")).toHaveTextContent("all");
  });

  it("the same identity keeps its selection across mounts", () => {
    mocks.tokenSubject.mockReturnValue("admin");
    const first = mount();
    act(() => { screen.getByText("pick").click(); });
    first.unmount();
    mount();
    expect(screen.getByTestId("ns")).toHaveTextContent("payments");
  });
});

describe("P1-1: governance posture in context", () => {
  it("loads the selected scope's enforcement mode and exposes it (monitor = 'audit')", async () => {
    mocks.getToken.mockReturnValue("t.t.t");
    mocks.fetchSettings.mockImplementation(() =>
      Promise.resolve({
        namespace: "analytics",
        enforcement_mode: "audit",
        trust_threshold: 0.7,
        rate_limit: 60,
        apply_mode: "enforce"
      })
    );
    mount("/audit?ns=analytics");
    await waitFor(() => expect(screen.getByTestId("posture")).toHaveTextContent("audit"));
    expect(mocks.fetchSettings).toHaveBeenCalledWith("analytics");
  });

  it("an unreachable settings API leaves the posture UNKNOWN (never assumed 'block')", async () => {
    mocks.getToken.mockReturnValue("t.t.t");
    mount("/audit?ns=analytics");
    await waitFor(() => expect(screen.getByTestId("posture")).toHaveTextContent("unknown"));
  });
});
