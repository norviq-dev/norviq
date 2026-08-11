// Attack Graph — Recompute must actually recompute at the DEFAULT "All namespaces" scope.
//
// "all" is the console's aggregate sentinel, not a namespace. POST /api/v1/attack-paths/compute
// branches on `if namespace:` and takes its SINGLE-namespace path for any truthy value, then
// exact-matches `asset_graph.namespace = :ns` — a row that never exists for "all"
// (policies.py's `_VIEW_SENTINEL_NAMESPACES` rejects the same string at the write boundary because
// no agent ever reports it). Sending it recomputed nothing, answered 200 {"computed": 0}, and the
// page — which read only `res.ok` — cleared its failure latch and re-rendered the identical stale
// kill-chains, or the identical empty state, as if freshly computed. The aggregate branch
// (`compute_all_namespaces`) is reachable ONLY when the parameter is ABSENT.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import AttackGraph from "./AttackGraph";
import { AppProvider } from "../store/AppContext";

// jsdom has no getBBox / ResizeObserver — the d3 canvas draw path reads both.
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

function renderPage(initial = "/threats/attack-graph") {
  return render(
    <MemoryRouter initialEntries={[initial]}>
      <AppProvider>
        <AttackGraph />
      </AppProvider>
    </MemoryRouter>
  );
}

/** Records every compute POST's query string; answers with the route's real body shapes. */
function useHandlers(queries: string[]) {
  server.use(
    http.get("/api/v1/cluster-info", () => HttpResponse.json(CLUSTER_INFO)),
    http.get("/api/v1/threats/attack-paths", () => HttpResponse.json({ paths: [], namespaces: ["payments", "default"] })),
    http.post("/api/v1/attack-paths/compute", ({ request }) => {
      const u = new URL(request.url);
      queries.push(u.search);
      const ns = u.searchParams.get("namespace");
      // Mirrors attack_graph_compute.py exactly: a present `namespace` -> single-namespace shape,
      // an ABSENT one -> the aggregate shape from compute_all_namespaces().
      return ns === null
        ? HttpResponse.json({ computed_by_namespace: { payments: 3, default: 1 }, total: 4 })
        : HttpResponse.json({ namespace: ns, computed: 0 });
    })
  );
}

describe("Recompute at the aggregate scope hits the aggregate branch", () => {
  it("sends NO namespace parameter when the scope is 'All namespaces'", async () => {
    const queries: string[] = [];
    useHandlers(queries);
    renderPage();

    const btn = await screen.findByRole("button", { name: /recompute attack paths/i });
    fireEvent.click(btn);
    await waitFor(() => expect(queries.length).toBeGreaterThanOrEqual(1));

    // FAIL-ON-BUG: pre-fix this is "?namespace=all" — the literal sentinel, which the route treats
    // as a real namespace and finds no asset graph for.
    expect(queries[0]).not.toContain("namespace=all");
    expect(new URLSearchParams(queries[0]).get("namespace")).toBeNull();
  });

  it("still scopes the POST when a real namespace is selected", async () => {
    const queries: string[] = [];
    useHandlers(queries);
    renderPage("/threats/attack-graph?ns=payments");

    const btn = await screen.findByRole("button", { name: /recompute attack paths/i });
    fireEvent.click(btn);
    await waitFor(() => expect(queries.length).toBeGreaterThanOrEqual(1));

    expect(new URLSearchParams(queries[0]).get("namespace")).toBe("payments");
  });

  it("reports what the run computed instead of falling silent on a 200", async () => {
    const queries: string[] = [];
    useHandlers(queries);
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: /recompute attack paths/i }));
    await waitFor(() => expect(queries.length).toBeGreaterThanOrEqual(1));

    // FAIL-ON-BUG: pre-fix the body was never read, so nothing on the page distinguished
    // "recomputed 4 paths" from "recomputed nothing".
    expect(await screen.findByTestId("recompute-note")).toHaveTextContent(
      /Recomputed 4 attack paths across 2 namespaces\./i
    );
  });

  it("says a zero result is zero, in the operator's words", async () => {
    server.use(
      http.get("/api/v1/cluster-info", () => HttpResponse.json(CLUSTER_INFO)),
      http.get("/api/v1/threats/attack-paths", () => HttpResponse.json({ paths: [], namespaces: [] })),
      http.post("/api/v1/attack-paths/compute", () =>
        HttpResponse.json({ computed_by_namespace: {}, total: 0 })
      )
    );
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: /recompute attack paths/i }));
    expect(await screen.findByTestId("recompute-note")).toHaveTextContent(
      /no namespace has a stored asset graph/i
    );
  });

  // "WE COULD NOT MEASURE THIS" MUST NOT RENDER LIKE "WE MEASURED, AND IT IS FINE".
  //
  // `describeRecompute` reads the route's body, and a body it cannot parse is the one case where the
  // page has a 200 and no idea what happened. Falling back to a count (or to silence, which on this
  // screen reads as a completed refresh) would be the same defect as the one this file exists for,
  // just arriving through the error path. Untested until now — the branch nothing else exercises.
  it("reports an unreadable body as UNREAD, never as a count and never as silence", async () => {
    server.use(
      http.get("/api/v1/cluster-info", () => HttpResponse.json(CLUSTER_INFO)),
      http.get("/api/v1/threats/attack-paths", () => HttpResponse.json({ paths: [], namespaces: [] })),
      // 200 with a body that is not JSON — a proxy's HTML error page is the everyday shape of this.
      http.post("/api/v1/attack-paths/compute", () => new HttpResponse("<html>gateway</html>", { status: 200 }))
    );
    renderPage();

    fireEvent.click(await screen.findByRole("button", { name: /recompute attack paths/i }));
    const note = await screen.findByTestId("recompute-note");
    expect(note).toHaveTextContent(/did not report what it computed/i);
    expect(note).toHaveTextContent(/unverified/i);
    // And it must not have invented a number to stand in for the one it could not read.
    expect(note).not.toHaveTextContent(/Recomputed \d/);
  });

  it("does not call the aggregate empty state 'this namespace'", async () => {
    const queries: string[] = [];
    useHandlers(queries);
    renderPage();

    // FAIL-ON-BUG: pre-fix the copy read "No attack paths stored for this namespace." while the
    // header said "Showing: All namespaces" — one namespace's all-clear, standing in for the estate's.
    expect(await screen.findByText("No attack paths stored in any namespace.")).toBeInTheDocument();
    expect(screen.queryByText(/stored for this namespace/i)).not.toBeInTheDocument();
  });
});
