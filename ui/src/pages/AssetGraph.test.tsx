// SPDX-License-Identifier: Apache-2.0
// Asset Graph page (redesign): defaults to All namespaces (namespace=all against the real endpoint),
// renders the stat strip + custom dropdowns, shows the awaiting banner, and gates the Cluster
// dropdown on the EXISTING fleetEnabled signal (absent single-cluster, present multi-cluster).
import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

let fleetEnabledValue = false;
vi.mock("../api/fleet", () => ({
  get fleetEnabled() {
    return fleetEnabledValue;
  }
}));
// P2-3: the graph's namespace scope IS the global selector, so each test controls useApp() directly.
// The spy mutates the context the way the real AppContext does (setNamespace updates the shared value and
// consumers re-render), so a dropdown pick still drives a scoped re-fetch — now via the GLOBAL selector.
const setNamespaceSpy = vi.fn((ns: string) => {
  mockApp = { ...mockApp, selectedNamespace: ns, namespace: ns };
});
const APP_DEFAULTS = {
  timeRange: "24h",
  clusters: ["aks-dev", "fleet-b"],
  selectedCluster: "",
  servedCluster: "aks-dev",
  setCluster: vi.fn(),
  selectedNamespace: "all",
  namespace: "all",
  namespaces: ["payments", "support"],
  setNamespace: setNamespaceSpy
};
let mockApp = { ...APP_DEFAULTS };
vi.mock("../store/AppContext", () => ({ useApp: () => mockApp }));
// d3 runs a real force simulation; the canvas internals are exercised in the browser, not here.
vi.mock("../components/asset-graph/AssetGraphCanvas", () => ({
  AssetGraphCanvas: () => <div data-testid="canvas" />
}));

import AssetGraph from "./AssetGraph";

const GRAPH = {
  nodes: [
    {
      id: "payments::spiffe://p/pay", type: "agent", name: "payments-bot",
      properties: { namespace: "payments", agent_class: "payments-bot", trust_score: 0.9 }
    },
    {
      id: "payments::tool:execute_sql", type: "tool", name: "execute_sql",
      properties: { namespace: "payments", risk_level: "critical", call_count: 12 }
    },
    {
      id: "hr::awaiting:hr-bot", type: "agent", name: "hr-bot",
      properties: { namespace: "hr", agent_class: "hr-bot", awaiting: true }
    }
  ],
  edges: [
    {
      source: "payments::spiffe://p/pay", target: "payments::tool:execute_sql", type: "calls", weight: 2,
      properties: { decision_history: { allow: 3, block: 5, escalate: 0 } }
    }
  ],
  namespaces: ["hr", "payments"]
};

function mockFetch(body: unknown = GRAPH) {
  const f = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } })
  );
  vi.stubGlobal("fetch", f);
  return f;
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AssetGraph />
    </MemoryRouter>
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  localStorage.clear();
  fleetEnabledValue = false;
  mockApp = { ...APP_DEFAULTS };
  setNamespaceSpy.mockClear();
});

describe("AssetGraph page (redesign)", () => {
  it("defaults to All namespaces and fetches namespace=all with the range param", async () => {
    const f = mockFetch();
    renderPage();
    await screen.findByRole("button", { name: /namespace/i });
    expect(String(f.mock.calls[0][0])).toContain("namespace=all");
    expect(String(f.mock.calls[0][0])).toContain("range=24h");
    // observed excludes the awaiting agent; awaiting is surfaced separately so the counts reconcile
    expect(screen.getByText(/All namespaces · 1 agents observed · 1 awaiting/)).toBeInTheDocument();
  });

  it("renders the clickable stat strip with real counts", async () => {
    mockFetch();
    renderPage();
    const strip = await screen.findByTestId("stat-strip");
    expect(strip.textContent).toMatch(/Namespaces/i);
    expect(strip.textContent).toMatch(/High risk/i);
    expect(strip.textContent).toMatch(/Blocked/i);
    // one blocked edge (block>0, allow>0 -> mixed is NOT blocked; 3 allow + 5 block => mixed) so Blocked shows 0
    expect(screen.getByText(/paths/)).toBeInTheDocument();
  });

  it("A2: awaiting agents are hidden by default behind an 'Awaiting (N) — Show' chip (in document flow)", async () => {
    // The real default response hides awaiting agents server-side (include_awaiting=false) and reports the count.
    mockFetch({ nodes: [GRAPH.nodes[0], GRAPH.nodes[1]], edges: GRAPH.edges, namespaces: ["hr", "payments"], awaiting_hidden: 1 });
    renderPage();
    const chip = await screen.findByRole("status");
    expect(chip.textContent).toMatch(/Awaiting \(1\)/);
    expect(chip.textContent).toMatch(/Show/);
    // in-flow: not absolutely positioned so it structurally can't overlap the canvas
    expect(chip.style.position).not.toBe("absolute");
  });

  it("High-risk tile narrows the Risk chips to high+critical, and restores on second click", async () => {
    const { fireEvent } = await import("@testing-library/react");
    mockFetch();
    renderPage();
    const lowChip = await screen.findByRole("button", { name: /^low$/i });
    expect(lowChip).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(screen.getByText(/High risk/i).closest("[role='button']")!);
    expect(screen.getByRole("button", { name: /^low$/i })).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByRole("button", { name: /^high$/i })).toHaveAttribute("aria-pressed", "true");
    fireEvent.click(screen.getByText(/High risk/i).closest("[role='button']")!);
    expect(screen.getByRole("button", { name: /^low$/i })).toHaveAttribute("aria-pressed", "true");
  });

  it("Blocked tile enters a blocked-only view (fewer visible nodes)", async () => {
    const { fireEvent, within } = await import("@testing-library/react");
    // fixture with a genuinely blocked edge (allow 0, block 5)
    mockFetch({
      nodes: [
        { id: "a::agent", type: "agent", name: "a", properties: { namespace: "a", agent_class: "a", trust_score: 0.9 } },
        { id: "a::tool:x", type: "tool", name: "x", properties: { namespace: "a", risk_level: "high" } },
        { id: "b::agent", type: "agent", name: "b", properties: { namespace: "b", agent_class: "b", trust_score: 0.9 } },
        { id: "b::tool:y", type: "tool", name: "y", properties: { namespace: "b", risk_level: "low" } }
      ],
      edges: [
        { source: "a::agent", target: "a::tool:x", type: "calls", weight: 1, properties: { decision_history: { allow: 0, block: 5, escalate: 0 } } },
        { source: "b::agent", target: "b::tool:y", type: "calls", weight: 1, properties: { decision_history: { allow: 4, block: 0, escalate: 0 } } }
      ],
      namespaces: ["a", "b"]
    });
    renderPage();
    const strip = await screen.findByTestId("stat-strip");
    expect(strip.textContent).toMatch(/4\s*assets/); // all 4 nodes visible
    fireEvent.click(within(strip).getByText(/^Blocked$/).closest("[role='button']")!);
    // only the a-side blocked path remains (2 nodes)
    await waitFor(() => expect(screen.getByTestId("stat-strip").textContent).toMatch(/2\s*assets/));
  });

  it("hides the Cluster dropdown in a single-cluster install", async () => {
    mockFetch();
    renderPage();
    await screen.findByRole("button", { name: /namespace/i });
    expect(screen.queryByRole("button", { name: /^cluster$/i })).toBeNull();
  });

  it("shows the Cluster dropdown when the install is multi-cluster (fleetEnabled)", async () => {
    fleetEnabledValue = true;
    mockFetch();
    renderPage();
    await waitFor(() => expect(screen.getByRole("button", { name: /^cluster$/i })).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /^cluster$/i })).toHaveTextContent("aks-dev");
  });

  it("renders the padded panel header + its zoom/re-layout controls (moved out of Panel props)", async () => {
    mockFetch();
    renderPage();
    expect(await screen.findByText("Asset Relationships")).toBeInTheDocument();
    expect(screen.getByText(/drag to rearrange/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /zoom in/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /re-layout/i })).toBeInTheDocument();
  });

  it("dropdown SELECTION works: pick a namespace → refetches that namespace", async () => {
    const { fireEvent } = await import("@testing-library/react");
    const f = mockFetch();
    renderPage();
    // open Namespace, pick "payments"
    fireEvent.click(await screen.findByRole("button", { name: /^namespace$/i }));
    fireEvent.click(await screen.findByRole("option", { name: /^payments$/i }));
    await waitFor(() => expect(String(f.mock.calls[f.mock.calls.length - 1][0])).toContain("namespace=payments"));
    // the button reflects the selection
    expect(screen.getByRole("button", { name: /^namespace$/i })).toHaveTextContent("payments");
  });

  it("keeps the FULL namespace list after drilling into one (no 'All namespaces (1)' collapse)", async () => {
    const { fireEvent } = await import("@testing-library/react");
    const f = vi.fn(async (input: RequestInfo | URL) => {
      // "all" returns 2 namespaces; a scoped request returns only that one
      const scoped = String(input).match(/namespace=(?!all)([^&]+)/);
      const body = scoped
        ? { nodes: [{ id: "payments::a", type: "agent", name: "a", properties: { namespace: "payments", agent_class: "a" } }], edges: [], namespaces: ["payments"] }
        : GRAPH;
      return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
    });
    vi.stubGlobal("fetch", f);
    renderPage();
    // drill into payments
    fireEvent.click(await screen.findByRole("button", { name: /^namespace$/i }));
    fireEvent.click(await screen.findByRole("option", { name: /^payments$/i }));
    await waitFor(() => expect(String(f.mock.calls[f.mock.calls.length - 1][0])).toContain("namespace=payments"));
    // re-open: the dropdown STILL lists every namespace + the correct "(2)" count, not "(1)".
    // P2-3: the universe is now the GLOBAL one (useApp().namespaces, i.e. /cluster-info — what the header
    // lists), not whatever the scoped graph response happened to return. That is what keeps the in-panel
    // dropdown a faithful view of the global selector.
    fireEvent.click(screen.getByRole("button", { name: /^namespace$/i }));
    expect(screen.getByRole("option", { name: /All namespaces \(2\)/ })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: /^payments/ })).toBeInTheDocument(); // "payments ✓" (now selected)
    expect(screen.getByRole("option", { name: /^support$/i })).toBeInTheDocument();
  });

  it("dropdown SELECTION works: pick a Range → refetches that range", async () => {
    const { fireEvent } = await import("@testing-library/react");
    const f = mockFetch();
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /^range$/i }));
    fireEvent.click(await screen.findByRole("option", { name: /last 7d/i }));
    await waitFor(() => expect(String(f.mock.calls[f.mock.calls.length - 1][0])).toContain("range=7d"));
  });

  it("keeps a graceful empty state", async () => {
    mockFetch({ nodes: [], edges: [], namespaces: [] });
    renderPage();
    await screen.findByText(/no assets observed for this scope/i);
  });
});

// ── P2-3 GRAPH-GLOBAL-NS-SYNC: the graph follows the GLOBAL namespace selector ──────────────────
// Pre-fix the page held its own `nsScope` state initialised to "all" and never read useApp(), so the
// global selector was ignored: the fetch always carried namespace=all and the header always read
// "All namespaces", no matter what the console was scoped to.
describe("P2-3: Asset Graph namespace follows the global selector", () => {
  it("fetches the GLOBAL namespace, not 'all', when the console is scoped", async () => {
    mockApp = { ...APP_DEFAULTS, selectedNamespace: "payments", namespace: "payments" };
    const f = mockFetch();
    renderPage();
    await screen.findByRole("button", { name: /namespace/i });
    expect(String(f.mock.calls[0][0])).toContain("namespace=payments"); // pre-fix: namespace=all
    expect(String(f.mock.calls[0][0])).not.toContain("namespace=all");
  });

  it("renders the scoped namespace in the header, not 'All namespaces'", async () => {
    mockApp = { ...APP_DEFAULTS, selectedNamespace: "payments", namespace: "payments" };
    mockFetch();
    renderPage();
    expect(await screen.findByText(/payments namespace/)).toBeInTheDocument();
    expect(screen.queryByText(/All namespaces ·/)).not.toBeInTheDocument();
  });

  it("still shows every namespace when the global selector is on 'all'", async () => {
    const f = mockFetch();
    renderPage();
    await screen.findByRole("button", { name: /namespace/i });
    expect(String(f.mock.calls[0][0])).toContain("namespace=all");
    expect(screen.getByText(/All namespaces · 1 agents observed/)).toBeInTheDocument();
  });

  it("the in-panel dropdown DRIVES the global selector (no divergent page-local state)", async () => {
    const { fireEvent } = await import("@testing-library/react");
    mockFetch();
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /namespace/i }));
    const listbox = await screen.findByRole("listbox", { name: /namespace/i });
    fireEvent.click(within(listbox).getByRole("option", { name: "payments" }));
    expect(setNamespaceSpy).toHaveBeenCalledWith("payments"); // pre-fix: only local setNsScope
  });

  it("the dropdown lists the full namespace universe even when already scoped (no collapse)", async () => {
    // Landing scoped never fetches namespace=all, so the page must take the universe from useApp().
    mockApp = { ...APP_DEFAULTS, selectedNamespace: "payments", namespace: "payments" };
    const { fireEvent } = await import("@testing-library/react");
    mockFetch({ nodes: [GRAPH.nodes[0], GRAPH.nodes[1]], edges: GRAPH.edges, namespaces: ["payments"] });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /namespace/i }));
    const listbox = await screen.findByRole("listbox", { name: /namespace/i });
    // the selected option's accessible name carries a trailing "✓", so match on the prefix
    expect(within(listbox).getByRole("option", { name: /^payments/ })).toBeInTheDocument();
    expect(within(listbox).getByRole("option", { name: /^support/ })).toBeInTheDocument(); // pre-fix: absent
  });
});
