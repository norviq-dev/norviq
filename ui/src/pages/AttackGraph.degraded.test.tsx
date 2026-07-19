import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import AttackGraph from "./AttackGraph";
import { AppProvider } from "../store/AppContext";
import type { ThreatPath } from "../components/attack-graph/types";

// jsdom has no getBBox / ResizeObserver — the d3 canvas fitView reads getBBox; stub both so the SVG
// draw path runs without throwing (the canvas is not the subject of this test, the degraded flag is).
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

const PATH: ThreatPath = {
  id: "p2", sev: "high", src: "billing-runner", tgt: "postgresql/ledger", ns: "payments", cls: "payments",
  mitre: "T1041 · Exfiltration", hops: 2, trust: 0.61, blast: 4, status: "exploitable", tool: "issue_refund",
  reach: [{ n: "tax-records", s: 1 }],
  steps: [
    { from: "billing-runner", to: "issue_refund", verb: "calls", dec: "mixed", kind: "tool", deny: 6, allow: 68 },
    { from: "issue_refund", to: "postgresql/ledger", verb: "reaches", dec: "allow", kind: "data", deny: 0, allow: 512 }
  ],
  verdict: "No step fully blocked — path is EXPLOITABLE.",
  fix: "Scope issue_refund: cap refund amount and restrict to ns payments."
};

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <AttackGraph />
      </AppProvider>
    </MemoryRouter>
  );
}

// ── ──────────────────────────────────────────────────────────────────────────────────────
// A failed recompute POST (500/403) raises the degraded banner, but recompute()'s finally flips
// `recomputing` which re-triggers the display-fetch effect; the follow-on READ GET succeeds and the
// pre-fix code unconditionally called setDegraded(false) — clobbering the banner the instant the STALE
// precompute re-rendered as if fresh. The fix latches the recompute failure across that refetch so the
// banner survives a successful GET of the stale paths (only a compute POST that returns ok clears it).
describe("a failed recompute keeps the degraded banner up across the follow-on refetch", () => {
  it("keeps 'API unavailable. Showing partial data.' visible after a 500 compute + 200 read settle", async () => {
    let getCount = 0;
    let computeCount = 0;
    server.use(
      http.get("/api/v1/cluster-info", () => HttpResponse.json(CLUSTER_INFO)),
      // The READ endpoint always succeeds and returns the (now stale) precomputed paths.
      http.get("/api/v1/threats/attack-paths", () => {
        getCount += 1;
        return HttpResponse.json({ paths: [PATH], namespaces: ["payments", "default"] });
      }),
      // The COMPUTE endpoint fails — a non-2xx that fetch does NOT reject on.
      http.post("/api/v1/attack-paths/compute", () => {
        computeCount += 1;
        return HttpResponse.json({ error: "compute failed" }, { status: 500 });
      })
    );

    renderPage();

    // Initial load settles cleanly: paths render, spinner gone, and NO degraded banner yet.
    await screen.findByRole("button", { name: "Recompute" });
    await waitFor(() => expect(screen.queryByText(/Recomputing attack paths/i)).not.toBeInTheDocument());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    const getBase = getCount;
    fireEvent.click(screen.getByRole("button", { name: "Recompute" }));

    // The compute POST fired and failed…
    await waitFor(() => expect(computeCount).toBeGreaterThanOrEqual(1));
    // …and the recompute cycle re-triggered the display-fetch effect at least twice (recomputing
    // true→GET, then false→GET) — i.e. the successful READ that pre-fix cleared the banner has happened.
    await waitFor(() => expect(getCount).toBeGreaterThanOrEqual(getBase + 2));
    // Let all follow-on refetch state updates flush (the recompute overlay clears once settled).
    await waitFor(() => expect(screen.queryByText(/Recomputing attack paths/i)).not.toBeInTheDocument());

    // FAIL-ON-BUG: pre-fix the successful READ GET called setDegraded(false), so the banner is gone here;
    // post-fix the recompute-failure is latched and the banner survives the stale-path refetch.
    expect(screen.getByRole("alert")).toHaveTextContent(/API unavailable\. Showing partial data\./i);
  });
});
