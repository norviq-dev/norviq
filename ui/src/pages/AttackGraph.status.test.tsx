// What the Attack Graph's status tiles and Simulate say about the traffic behind a path.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import AttackGraph from "./AttackGraph";
import { AppProvider } from "../store/AppContext";
import type { ThreatPath } from "../components/attack-graph/types";

beforeAll(() => {
  (window.SVGElement.prototype as unknown as { getBBox: () => DOMRect }).getBBox = () =>
    ({ x: 0, y: 0, width: 400, height: 500 }) as DOMRect;
  (window as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
});

const server = setupServer();
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

// analytics is in Monitor: execute_sql matched a policy five times and every call ran (`audit`). The
// tool -> data hop carries the same calls, marked `via`.
const MONITOR: ThreatPath = {
  id: "pm", sev: "high", src: "data-analyst", tgt: "postgresql/users", ns: "analytics", cls: "data-analyst",
  mitre: "T1213", hops: 2, trust: 0.6, blast: 2, status: "would_block", tool: "execute_sql",
  reach: [],
  steps: [
    { from: "data-analyst", to: "execute_sql", verb: "calls", dec: "would_block", kind: "tool", deny: 0, allow: 0, would_block: 5 },
    { from: "execute_sql", to: "postgresql/users", verb: "reaches", dec: "would_block", kind: "data", deny: 0, allow: 0, would_block: 5, via: "execute_sql" }
  ],
  verdict: "Monitor mode: a policy would block 'execute_sql', but this namespace logs instead of enforcing, so these calls ran.",
  fix: "Scope execute_sql."
};

// Real traffic has not walked this chain yet.
const UNWALKED: ThreatPath = {
  ...MONITOR, id: "pu", status: "unsimulated",
  steps: [
    { from: "data-analyst", to: "execute_sql", verb: "calls", dec: "allow", kind: "tool", deny: 0, allow: 0 },
    { from: "execute_sql", to: "postgresql/users", verb: "reaches", dec: "allow", kind: "data", deny: 0, allow: 0, via: "execute_sql" }
  ],
  verdict: "No end-to-end traffic yet — simulate to confirm reachability."
};

function handlers(paths: ThreatPath[], decision: string) {
  return [
    http.get("/api/v1/cluster-info", () =>
      HttpResponse.json({ cluster_id: "local", cluster_name: "local", namespaces: ["analytics", "payments"] })),
    http.get("/api/v1/threats/attack-paths", () => HttpResponse.json({ paths, namespaces: ["analytics", "payments"] })),
    http.post("/api/v1/evaluate", () =>
      HttpResponse.json({ decision, rule_id: decision === "allow" ? "default_allow" : "r1" }))
  ];
}

function renderPage(url = "/") {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <AppProvider>
        <AttackGraph />
      </AppProvider>
    </MemoryRouter>
  );
}

const tile = (id: string) => screen.getByTestId(id);
const tileValue = (id: string) => (tile(id).querySelector("span") as HTMLElement).textContent;

describe("a Monitor would-block is not a block", () => {
  it("is counted on its own tile, never under Blocked, and its chip says WOULD BLOCK", async () => {
    server.use(...handlers([MONITOR], "audit"));
    renderPage();
    await screen.findByRole("complementary", { name: /attack path inspector/i });
    expect(tileValue("stat-blocked")).toBe("0");
    expect(tileValue("stat-exploitable")).toBe("0");
    expect(tileValue("stat-would-block")).toBe("1");
    expect(screen.getByRole("button", { name: /WOULD BLOCK data-analyst/i })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^BLOCKED data-analyst/i })).toBeNull();
  });

  it("a Simulate that comes back `audit` reads would-block, not blocked", async () => {
    server.use(...handlers([UNWALKED], "audit"));
    renderPage();
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    fireEvent.click(within(inspector).getByRole("button", { name: /simulate \(preview\)/i }));
    await within(inspector).findByText(/Monitor mode, so the call would run/i);
    expect(tileValue("stat-blocked")).toBe("0");
    expect(tileValue("stat-would-block")).toBe("1");
  });
});

// Path ids changed in 0.2.8, so a `?path=` link saved before then names an id that no longer exists.
// The page used to fall back to the first path silently: a different path shown under the link.
describe("a ?path= link that does not resolve", () => {
  it("says the path no longer exists or was renamed instead of showing another path", async () => {
    server.use(...handlers([UNWALKED, MONITOR], "allow"));
    renderPage("/attack-graph?path=pdeadbeef00");
    const notice = await screen.findByTestId("stale-path");
    expect(notice).toHaveTextContent(/This path no longer exists or was renamed/);
    expect(notice).toHaveTextContent(/pdeadbeef00/);
    // No other path is presented as the linked one.
    expect(screen.queryByRole("complementary", { name: /attack path inspector/i })).toBeNull();
    // The list is still there to pick from, and picking one clears the notice.
    fireEvent.click(within(notice).getByRole("button", { name: /show the worst path instead/i }));
    await screen.findByRole("complementary", { name: /attack path inspector/i });
    expect(screen.queryByTestId("stale-path")).toBeNull();
  });

  // Both ids, so the test cannot pass by the page opening its default path.
  it.each([
    ["pu", /No end-to-end traffic yet/],
    ["pm", /Monitor mode: a policy would block/]
  ])("a link that does resolve opens that path with no notice (%s)", async (id, verdict) => {
    server.use(...handlers([UNWALKED, MONITOR], "allow"));
    renderPage(`/attack-graph?path=${id}`);
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    expect(within(inspector).getAllByText(verdict).length).toBeGreaterThan(0);
    expect(screen.queryByTestId("stale-path")).toBeNull();
  });
});
