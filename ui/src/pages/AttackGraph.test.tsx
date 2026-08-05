// Tests for the AttackGraph page — headline stats, what-if isolation, and page-local namespace/reset behavior.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import AttackGraph from "./AttackGraph";
import { AppProvider } from "../store/AppContext";
import type { ThreatPath } from "../components/attack-graph/types";

// jsdom has no getBBox / ResizeObserver — the d3 canvas fitView reads getBBox; stub both so the SVG
// draw path runs without throwing (the canvas is not the subject of these tests, the page state is).
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

const CLUSTER_INFO = { cluster_id: "local", cluster_name: "local", namespaces: ["payments", "default"] };

const P2: ThreatPath = {
  id: "p2", sev: "high", src: "billing-runner", tgt: "postgresql/ledger", ns: "payments", cls: "payments",
  mitre: "T1041 · Exfiltration", hops: 2, trust: 0.61, blast: 4, status: "exploitable", tool: "issue_refund",
  reach: [{ n: "tax-records", s: 1 }, { n: "invoices", s: 0 }],
  steps: [
    { from: "billing-runner", to: "issue_refund", verb: "calls", dec: "mixed", kind: "tool", deny: 6, allow: 68 },
    { from: "issue_refund", to: "postgresql/ledger", verb: "reaches", dec: "allow", kind: "data", deny: 0, allow: 512 }
  ],
  verdict: "No step fully blocked — path is EXPLOITABLE.",
  fix: "Scope issue_refund: cap refund amount and restrict to ns payments."
};
const P1: ThreatPath = {
  id: "p1", sev: "critical", src: "customer-support", tgt: "postgresql/payments", ns: "default", cls: "customer-support",
  mitre: "T1190 · Initial Access", hops: 2, trust: 0.62, blast: 5, status: "blocked", tool: "execute_sql",
  reach: [{ n: "stripe-keys", s: 1 }],
  steps: [
    { from: "customer-support", to: "execute_sql", verb: "calls", dec: "block", kind: "tool", deny: 237, allow: 0 },
    { from: "execute_sql", to: "postgresql/payments", verb: "reaches", dec: "allow", kind: "data", deny: 0, allow: 1420 }
  ],
  verdict: "Blocked at step 1.", fix: ""
};

function baseHandlers(paths: ThreatPath[]) {
  return [
    http.get("/api/v1/cluster-info", () => HttpResponse.json(CLUSTER_INFO)),
    http.get("/api/v1/threats/attack-paths", () => HttpResponse.json({ paths, namespaces: ["payments", "default"] }))
  ];
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <AttackGraph />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("AttackGraph page", () => {
  it("renders paths from fetchThreatPaths (ranked list, worst-first)", async () => {
    server.use(...baseHandlers([P1, P2]));
    renderPage();
    // ranked list buttons appear (server pre-sorts; the page keeps the order stable)
    await waitFor(() => expect(screen.getByRole("button", { name: /EXPLOITABLE billing-runner/i })).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /BLOCKED customer-support/i })).toBeInTheDocument();
    expect(screen.getByText(/Threat Relationships/)).toBeInTheDocument();
  });

  it("stat strip counts critical / exploitable / blocked across visible paths", async () => {
    server.use(...baseHandlers([P1, P2]));
    renderPage();
    await waitFor(() => expect(screen.getByRole("button", { name: /EXPLOITABLE billing-runner/i })).toBeInTheDocument());
    // Critical paths = 1 (P1), Exploitable = 1 (P2), Blocked = 1 (P1)
    const crit = screen.getByText("Critical paths").parentElement as HTMLElement;
    expect(within(crit).getByText("1")).toBeInTheDocument();
    const expl = screen.getByText("Exploitable").parentElement as HTMLElement;
    expect(within(expl).getByText("1")).toBeInTheDocument();
  });

  // ONE definition of "chokepoint", shared with the inspector chip and the backend's own tag.
  // The strip used to define it locally as "a tool appearing on 2+ paths", so with paths through
  // distinct tools — including the ordinary single-path case — it read "CHOKEPOINTS 0 tools" while
  // the inspector two panels over was naming one. Same shape as the 3-paths-vs-2-rules bug already
  // found on this screen: two numbers for one word, on panels an operator reads together.
  it("the Chokepoints stat counts the same thing the inspector chip names", async () => {
    server.use(...baseHandlers([P1, P2])); // chokepoints: execute_sql, issue_refund — one path each
    renderPage();
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    const cell = screen.getByTestId("stat-chokepoints");
    // pre-fix this cell read "0" while the chip below named a tool
    expect(within(cell).getByText("2")).toBeInTheDocument();
    // the chip the number has to agree with
    const chip = within(inspector).getByText(/^chokepoint$/i).parentElement as HTMLElement;
    expect(chip).toHaveTextContent(/execute_sql|issue_refund/);
  });

  it("a single path with a chokepoint never reports zero chokepoints", async () => {
    server.use(...baseHandlers([P2]));
    renderPage();
    await screen.findByRole("complementary", { name: /attack path inspector/i });
    expect(within(screen.getByTestId("stat-chokepoints")).getByText("1")).toBeInTheDocument();
  });

  it("counts a shared chokepoint once, not once per path", async () => {
    const A: ThreatPath = { ...P2, id: "a" };
    const B: ThreatPath = { ...P2, id: "b", src: "other-runner" }; // same tool: issue_refund
    server.use(...baseHandlers([A, B]));
    renderPage();
    await screen.findByRole("complementary", { name: /attack path inspector/i });
    expect(within(screen.getByTestId("stat-chokepoints")).getByText("1")).toBeInTheDocument();
  });

  it("selecting a path shows the inspector with its fix + verdict", async () => {
    server.use(...baseHandlers([P2, P1]));
    renderPage();
    // the first (auto-selected) path's inspector is present
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    expect(within(inspector).getByText(/RECOMMENDED FIX/)).toBeInTheDocument();
    expect(within(inspector).getByText(/MITRE T1041/)).toBeInTheDocument();
  });

  it("opening the intent modal loads the tool surface + calls fetchIntentCoverage", async () => {
    let coverageCalled = 0;
    server.use(
      ...baseHandlers([P2]),
      http.get("/api/v1/threats/intent-suggest", () =>
        HttpResponse.json({
          ns: "payments", cls: "payments",
          tools: [
            { name: "read_ledger", allow: 90, block: 0, tag: "normal", target: null, in_attack_path: false },
            { name: "issue_refund", allow: 68, block: 6, tag: "chokepoint", target: "postgresql/ledger", in_attack_path: true }
          ]
        })
      ),
      http.post("/api/v1/threats/intent-coverage", () => {
        coverageCalled += 1;
        return HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 });
      })
    );
    renderPage();
    // The button renders IMMEDIATELY but starts `disabled={!visible.length}` — there is nothing to
    // define intent over until the paths fetch resolves. findByRole matches disabled elements, so
    // clicking as soon as it is findable clicks a dead control: no modal, and the failure surfaces
    // later as "unable to find role=dialog", pointing at the modal rather than at the click. Wait
    // for ENABLED, which is also the only thing a real user can do.
    const openBtn = await screen.findByRole("button", { name: /define intended behaviour/i });
    await waitFor(() => expect(openBtn).toBeEnabled());
    fireEvent.click(openBtn);
    const dialog = await screen.findByRole("dialog", { name: /define intended behaviour/i });
    // the observed tools render as a checklist
    expect(await within(dialog).findByLabelText(/Intended: read_ledger/i)).toBeInTheDocument();
    // coverage is fetched once the checklist has seeded (debounced) — wait for it
    await waitFor(() => expect(coverageCalled).toBeGreaterThan(0));
  });

  // The denial total on the scope card is aggregated server-side over RANGE_HOURS[range], i.e. over
  // whatever this dropdown asked for — but the card captioned it "Denials · 24h" unconditionally, so
  // a thirty-day total was labelled a day's. This asserts the page actually hands the canvas the
  // window it queried; the label itself is covered in AttackGraphCanvas.test.tsx.
  it("the scope card's denial window follows the Range dropdown", async () => {
    server.use(...baseHandlers([P2]));
    const { container } = renderPage();
    await screen.findByRole("complementary", { name: /attack path inspector/i });

    // switch Range to Last 30d
    fireEvent.click(screen.getByRole("button", { name: /^range$/i }));
    fireEvent.click(within(screen.getByRole("listbox", { name: /range/i })).getByText("Last 30d"));

    // click the chokepoint tool node on the kill-chain → the scope card opens
    const toolNode = Array.from(container.querySelectorAll<SVGGElement>("g.ak-node")).find((g) =>
      Array.from(g.querySelectorAll("text")).some((t) => t.textContent === "issue_refund")
    )!;
    expect(toolNode).toBeDefined();
    fireEvent.click(toolNode);

    const denials = await screen.findByText(/^Denials · /);
    expect(denials).toHaveTextContent("Denials · 30d");
    expect(denials.textContent).not.toContain("24h");
  });

  /** Open the kill-chain scope card for the chokepoint tool node. */
  function openScopeCard(container: HTMLElement) {
    const toolNode = Array.from(container.querySelectorAll<SVGGElement>("g.ak-node")).find((g) =>
      Array.from(g.querySelectorAll("text")).some((t) => t.textContent === "issue_refund")
    )!;
    expect(toolNode).toBeDefined();
    fireEvent.click(toolNode);
  }

  // An ALREADY OPEN card is the case the click-order test above cannot reach: the operator opens it,
  // then widens the window. The card's denial total is range-scoped, so leaving it alone would keep a
  // day's number under a month's label — the same defect as the old hardcoded caption, one step later.
  it("relabels an already-open scope card when the window is re-measured", async () => {
    server.use(...baseHandlers([P2]));
    const { container } = renderPage();
    await screen.findByRole("complementary", { name: /attack path inspector/i });
    openScopeCard(container);
    expect(await screen.findByText("Denials · 24h")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /^range$/i }));
    fireEvent.click(within(screen.getByRole("listbox", { name: /range/i })).getByText("Last 30d"));

    await waitFor(() => expect(screen.getByText("Denials · 30d")).toBeInTheDocument());
    expect(screen.queryByText("Denials · 24h")).not.toBeInTheDocument();
  });

  // …and the other direction, which is the one that matters. `range` is what was ASKED for;
  // it moves the instant the dropdown does and STAYS moved when the fetch behind it fails — the catch
  // keeps the previous `paths` and raises the degraded banner. Captioning the number with `range`
  // therefore prints a 24-hour total as a 30-day one: "we could not measure this" rendered as a
  // measurement. Only a window the numbers were actually fetched with may label them.
  it("does not relabel the card with a window whose refetch FAILED", async () => {
    let calls = 0;
    server.use(
      http.get("/api/v1/cluster-info", () => HttpResponse.json(CLUSTER_INFO)),
      http.get("/api/v1/threats/attack-paths", () => {
        calls += 1;
        return calls === 1
          ? HttpResponse.json({ paths: [P2], namespaces: ["payments", "default"] })
          : new HttpResponse(null, { status: 503 });
      })
    );
    const { container } = renderPage();
    await screen.findByRole("complementary", { name: /attack path inspector/i });
    openScopeCard(container);
    const before = await screen.findByText("Denials · 24h");
    const denials = before.parentElement!.textContent;

    fireEvent.click(screen.getByRole("button", { name: /^range$/i }));
    fireEvent.click(within(screen.getByRole("listbox", { name: /range/i })).getByText("Last 30d"));

    // the 30d read failed — the page says so
    await screen.findByText(/API unavailable/i);
    // …and the card still reports the window its numbers came from, unchanged
    expect(screen.getByText("Denials · 24h")).toBeInTheDocument();
    expect(screen.queryByText("Denials · 30d")).not.toBeInTheDocument();
    expect(screen.getByText("Denials · 24h").parentElement!.textContent).toBe(denials);
  });

  it("empty result shows the no-paths reset/recompute state", async () => {
    server.use(...baseHandlers([]));
    renderPage();
    expect(await screen.findByRole("button", { name: /recompute attack paths/i })).toBeInTheDocument();
  });

  // A hypothetical "Block this step (what-if)" must NOT inflate the real BLOCKED headline stat
  // (a screenshot of this page is read as deployed posture) — it is annotated separately.
  it("what-if block does not increment the real BLOCKED stat; it is annotated as what-if", async () => {
    // Two exploitable paths, zero real blocks → Blocked stat starts at 0.
    const A: ThreatPath = { ...P2, id: "a", status: "exploitable" };
    const B: ThreatPath = { ...P2, id: "b", src: "other-runner", status: "exploitable" };
    server.use(...baseHandlers([A, B]));
    renderPage();
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    const blockedTile = screen.getByTestId("stat-blocked");
    expect(within(blockedTile).getByText("0")).toBeInTheDocument();

    // Apply a what-if block on the selected path's first step.
    fireEvent.click(within(inspector).getAllByRole("button", { name: /block this step \(what-if\)/i })[0]);

    // The real BLOCKED count STAYS 0; the what-if is surfaced as a separate "+1 what-if" annotation.
    expect(within(blockedTile).getByText("0")).toBeInTheDocument();
    await waitFor(() => expect(within(blockedTile).getByText(/\+1 what-if/i)).toBeInTheDocument());
    // …and the path row carries the distinct what-if chip, not the solid BLOCKED chip.
    expect(screen.getAllByTestId("path-whatif-chip").length).toBeGreaterThan(0);
  });

  // The what-if "Draft blocking policy" now PERSISTS a real dry-run draft (POST /threats/intent-draft)
  // and the confirmation deep-links to it — it was a fabricated local-only "✓ Draft created" with no POST.
  it("drafting a blocking policy POSTs a real dry-run draft and deep-links to it (no fabrication)", async () => {
    let draftBody: any = null;
    server.use(
      ...baseHandlers([P2]),
      http.post("/api/v1/threats/intent-draft", async ({ request }) => {
        draftBody = await request.json();
        return HttpResponse.json({ draft_id: "draft-xyz", ns: "payments", cls: "payments",
          deeplink: "/policies/catalog?intent_draft=draft-xyz", enforcement: "draft", valid: true });
      })
    );
    renderPage();
    const inspector = await screen.findByRole("complementary", { name: /attack path inspector/i });
    // Toggle a what-if block on a step → the "Draft blocking policy" button appears.
    fireEvent.click(within(inspector).getAllByRole("button", { name: /block this step \(what-if\)/i })[0]);
    fireEvent.click(await within(inspector).findByTestId("ag-draft-button"));
    // A real POST fired for the path's class (pre-fix: no POST at all).
    await waitFor(() => expect(draftBody).toMatchObject({ ns: "payments", cls: "payments", path_ids: ["p2"] }));
    expect(draftBody.intent).toMatchObject({ readonly: true });
    // The confirmation becomes a live deep-link (open in Policies), not a static label.
    await waitFor(() => expect(within(inspector).getByTestId("ag-draft-button")).toHaveTextContent(/open dry-run in Policies/i));
  });
});

// ── GRAPH-GLOBAL-NS-SYNC ────────────────────────────────────────────────────────────────────
// The Attack Graph already scoped itself from the global selector — but its page-local "Reset" button
// called setNamespace("all"), silently rescoping the WHOLE console (Audit Log, Policies, …) back to
// All namespaces. A page-local filter reset must not mutate the global scope.
describe("page-local Reset must not clobber the GLOBAL namespace", () => {
  it("keeps the global namespace scoped after clicking Reset", async () => {
    const seen: string[] = [];
    server.use(
      http.get("/api/v1/cluster-info", () => HttpResponse.json(CLUSTER_INFO)),
      // no paths -> the empty state renders, which is where the "Reset" control lives
      http.get("/api/v1/threats/attack-paths", ({ request }) => {
        seen.push(new URL(request.url).searchParams.get("ns") ?? "");
        return HttpResponse.json({ paths: [], namespaces: ["payments", "default"] });
      })
    );
    localStorage.setItem("nrvq_namespace", "payments"); // the console is scoped to `payments`
    renderPage();
    await waitFor(() => expect(seen[seen.length - 1]).toBe("payments"));

    fireEvent.click(await screen.findByRole("button", { name: /^reset$/i }));

    // the global scope survives a page-local filter reset (pre-fix: setNamespace("all") -> ns=all)
    await waitFor(() => expect(screen.getByText(/Showing:\s*payments/)).toBeInTheDocument());
    expect(seen).not.toContain("all");
    expect(localStorage.getItem("nrvq_namespace")).toBe("payments");
  });
});
