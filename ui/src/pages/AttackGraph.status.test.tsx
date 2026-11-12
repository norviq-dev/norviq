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

const AGENT = "spiffe://norviq/ns/analytics/sa/analytics-runner";

// analytics is in Monitor: execute_sql matched a policy five times and every call ran (`audit`). The
// tool -> data hop carries the same calls, marked `via`.
const MONITOR: ThreatPath = {
  id: "pm", sev: "high", src: "data-analyst", tgt: "postgresql/users", ns: "analytics", cls: "data-analyst",
  spiffe_id: AGENT, mitre: "T1213", hops: 2, trust: 0.6, blast: 2, status: "would_block", tool: "execute_sql",
  reach: [],
  steps: [
    { from: "data-analyst", to: "execute_sql", verb: "calls", dec: "would_block", kind: "tool", deny: 0, allow: 0, would_block: 5 },
    { from: "execute_sql", to: "postgresql/users", verb: "reaches", dec: "would_block", kind: "data", deny: 0, allow: 0, would_block: 5, via: "execute_sql" }
  ],
  verdict: "Monitor mode: a policy would block 'execute_sql', but this namespace logs instead of enforcing, so these calls ran.",
  fix: "Scope execute_sql."
};

// run_shell was blocked three times in real traffic by a rule that checks its arguments.
const ARG_GATED: ThreatPath = {
  id: "pb", sev: "high", src: "invoice-agent", tgt: "compute/destructive", ns: "payments", cls: "invoice-agent",
  spiffe_id: "spiffe://norviq/ns/payments/sa/invoice-runner", mitre: "T1059", hops: 2, trust: 0.7, blast: 1,
  status: "blocked", tool: "run_shell", reach: [],
  steps: [
    { from: "invoice-agent", to: "run_shell", verb: "calls", dec: "block", kind: "tool", deny: 3, allow: 0 },
    { from: "run_shell", to: "compute/destructive", verb: "reaches", dec: "block", kind: "data", deny: 3, allow: 0, via: "run_shell" }
  ],
  verdict: "Policy blocks the chokepoint 'run_shell' — path neutralized.",
  fix: ""
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

function handlers(paths: ThreatPath[], decision: string, seen: unknown[] = []) {
  return [
    http.get("/api/v1/cluster-info", () =>
      HttpResponse.json({ cluster_id: "local", cluster_name: "local", namespaces: ["analytics", "payments"] })),
    http.get("/api/v1/threats/attack-paths", () => HttpResponse.json({ paths, namespaces: ["analytics", "payments"] })),
    http.post("/api/v1/evaluate", async ({ request }) => {
      seen.push(await request.json());
      return HttpResponse.json({ decision, rule_id: decision === "allow" ? "default_allow" : "r1" });
    })
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

describe("Simulate", () => {
  it("evaluates as the path's own workload identity, not a made-up sa/<class>", async () => {
    const seen: Array<{ agent_identity: { spiffe_id: string; agent_class: string } }> = [];
    server.use(...handlers([UNWALKED], "allow", seen));
    renderPage();
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    fireEvent.click(within(inspector).getByRole("button", { name: /simulate \(preview\)/i }));
    await waitFor(() => expect(seen.length).toBeGreaterThan(0));
    expect(seen[0].agent_identity.spiffe_id).toBe(AGENT);
    expect(seen[0].agent_identity.agent_class).toBe("data-analyst");
    // The tag is unchanged: whatever classifies Simulate traffic keys on it.
    expect((seen[0] as unknown as { framework: string }).framework).toBe("attack-graph");
  });

  it("says when it had to use a stand-in identity", async () => {
    const seen: Array<{ agent_identity: { spiffe_id: string } }> = [];
    server.use(...handlers([{ ...UNWALKED, spiffe_id: null }], "allow", seen));
    renderPage();
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    fireEvent.click(within(inspector).getByRole("button", { name: /simulate \(preview\)/i }));
    await within(inspector).findByText(/stand-in identity \(sa\/data-analyst\)/i);
    expect(seen[0].agent_identity.spiffe_id).toBe("spiffe://norviq/ns/analytics/sa/data-analyst");
  });

  // Rewritten: it used to assert the banner said "not a gap". That was an inference from real stops plus
  // one empty-argument allow, stated as fact. The banner now says only what is known.
  it("an empty-argument allow on a path real traffic was blocked on says what it cannot tell", async () => {
    server.use(...handlers([ARG_GATED], "allow"));
    renderPage();
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    expect(tileValue("stat-blocked")).toBe("1");
    fireEvent.click(within(inspector).getByRole("button", { name: /simulate \(preview\)/i }));
    // Three real stops, not six: the data hop repeats the tool hop's counts.
    const banner = await within(inspector).findByText(/real calls on this path were stopped 3 times/i);
    expect(banner).toHaveTextContent(/Simulate sent no arguments, so it cannot tell whether that rule covers this path/i);
    expect(banner).not.toHaveTextContent(/not a gap/i);
    expect(banner).not.toHaveTextContent(/depends on argument values/i);
    expect(within(inspector).queryByText(/policy gap/i)).toBeNull();
    // The preview does not overturn what real traffic established.
    expect(tileValue("stat-blocked")).toBe("1");
    expect(tileValue("stat-exploitable")).toBe("0");
  });

  // A Monitor would-block RAN. Counting it as a stop made the banner say "stopped 5 times" for a path on
  // which nothing was ever stopped.
  it("an empty-argument allow on a Monitor path does not call its would-blocks stops", async () => {
    server.use(...handlers([MONITOR], "allow"));
    renderPage();
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    fireEvent.click(within(inspector).getByRole("button", { name: /simulate \(preview\)/i }));
    const banner = await within(inspector).findByText(/logged as would-block 5 times \(Monitor, they ran\)/i);
    expect(banner).not.toHaveTextContent(/stopped/i);
    expect(banner).toHaveTextContent(/cannot tell whether that rule covers this path/i);
    // The preview does not overturn what real traffic established.
    expect(tileValue("stat-would-block")).toBe("1");
    expect(tileValue("stat-exploitable")).toBe("0");
  });

  it("an empty-argument allow with no real stops says what it did not test", async () => {
    const open: ThreatPath = {
      ...ARG_GATED, id: "po", status: "unsimulated",
      steps: [
        { from: "invoice-agent", to: "run_shell", verb: "calls", dec: "allow", kind: "tool", deny: 0, allow: 0 },
        { from: "run_shell", to: "compute/destructive", verb: "reaches", dec: "allow", kind: "data", deny: 0, allow: 0, via: "run_shell" }
      ]
    };
    server.use(...handlers([open], "allow"));
    renderPage();
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    fireEvent.click(within(inspector).getByRole("button", { name: /simulate \(preview\)/i }));
    await within(inspector).findByText(/Rules that check argument values were not exercised/i);
    expect(within(inspector).queryByText(/policy gap/i)).toBeNull();
    await waitFor(() => expect(tileValue("stat-exploitable")).toBe("1"));
  });
});

// Path ids changed in 0.2.8, so a `?path=` link saved before then names an id that no longer exists.
// The page used to fall back to the first path silently: a different path shown under the link.
describe("a ?path= link that does not resolve", () => {
  it("says the path no longer exists or was renamed instead of showing another path", async () => {
    server.use(...handlers([ARG_GATED, MONITOR], "allow"));
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

  it("a link that does resolve opens that path with no notice", async () => {
    server.use(...handlers([ARG_GATED, MONITOR], "allow"));
    renderPage("/attack-graph?path=pb");
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    expect(within(inspector).getAllByText(/invoice-agent/).length).toBeGreaterThan(0);
    expect(screen.queryByTestId("stale-path")).toBeNull();
  });
});
