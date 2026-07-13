// SPDX-License-Identifier: Apache-2.0
// C2-2/C2-3/C2-4b: Target Settings is now namespace-GOVERNANCE only — the "effective policy" resolved-stack view
// was folded into the Catalog hierarchy (covered by PolicyHierarchy.test). Here we pin: no effective-policy table;
// the "See how this resolves →" link; packs-applied APPLIED/NONE; the subtitle bound to the working scope.
import type { ReactNode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { TargetSettings } from "./TargetSettings";
import { clearApiCache } from "../hooks/useApi";

const mockApp = { namespace: "default", selectedCluster: "local", isRemote: false, servedCluster: "local", scopeCluster: "local" };
vi.mock("../store/AppContext", () => ({ useApp: () => mockApp, AppProvider: ({ children }: { children: ReactNode }) => <>{children}</> }));

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
beforeEach(() => { mockApp.namespace = "default"; });
afterEach(() => { server.resetHandlers(); clearApiCache(); });
afterAll(() => server.close());

function handlers(enabledPacks: { id: string; title: string; enabled: boolean }[] = []) {
  server.use(
    http.get("/api/v1/me", () => HttpResponse.json({ role: "admin", namespace: null })),
    http.get("/api/v1/settings", () => HttpResponse.json({ apply_mode: "enforce", enforcement_mode: "block" })),
    http.get("/api/v1/policy-packs", () => HttpResponse.json(enabledPacks.map((p) => ({ ...p, sector: "X", enforces: "", rule_ids: [], composes: [], categories: [], compliance: [], tunables: [], namespace: "default" }))))
  );
}
function renderPage() {
  return render(<MemoryRouter><TargetSettings /></MemoryRouter>);
}

describe("TargetSettings — governance only (C2-2/C2-3/C2-4b)", () => {
  it("does NOT render the effective-policy resolved-stack table (folded into Catalog)", async () => {
    handlers();
    renderPage();
    await screen.findByText("Governance");
    // the resolved-stack table + its "Scope"/"Layer" headers are gone from this page
    expect(screen.queryByText(/no policy layers in force/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "Scope" })).not.toBeInTheDocument();
    // and the link to the hierarchy is present with the namespace-preserving route
    const link = screen.getByTestId("see-how-resolves");
    expect(link).toHaveAttribute("href", "/policies/catalog?tab=catalog");
  });

  it("C2-4b: the subtitle binds to the working scope (concrete ns, not 'all')", async () => {
    handlers();
    renderPage();
    expect(await screen.findByText("Namespace: default")).toBeInTheDocument();
    expect(screen.queryByText(/Namespace: all/i)).not.toBeInTheDocument();
  });

  it("C2-4b: an aggregate scope shows 'All namespaces', never 'Namespace: all'", async () => {
    mockApp.namespace = "all";
    handlers();
    renderPage();
    expect(await screen.findByText("All namespaces")).toBeInTheDocument();
    expect(screen.queryByText("Namespace: all")).not.toBeInTheDocument();
  });

  it("C2-3: packs-applied shows the APPLIED set for the concrete namespace", async () => {
    handlers([{ id: "ecommerce", title: "E-commerce", enabled: true }, { id: "pci", title: "PCI", enabled: true }, { id: "off", title: "Off", enabled: false }]);
    renderPage();
    await waitFor(() => expect(screen.getByTestId("packs-applied-state")).toHaveAttribute("data-count", "2"));
    expect(screen.getByTestId("packs-applied-state")).toHaveTextContent(/2 packs applied/i);
    expect(screen.getByText("E-commerce")).toBeInTheDocument();
    expect(screen.getByText("PCI")).toBeInTheDocument();
  });

  it("C2-3: packs-applied shows NONE when no packs are enabled", async () => {
    handlers([{ id: "off", title: "Off", enabled: false }]);
    renderPage();
    await waitFor(() => expect(screen.getByTestId("packs-applied-state")).toHaveAttribute("data-count", "0"));
    expect(screen.getByTestId("packs-applied-state")).toHaveTextContent(/No packs applied/i);
  });

  // TGT-POSTURE-01: the enforcement axis is now an editable Block ⇄ Monitor toggle (was a read-only label).
  it("renders the Block/Monitor enforcement toggle (not a read-only label)", async () => {
    handlers();
    renderPage();
    expect(await screen.findByTestId("enforcement-mode-block")).toHaveTextContent("Block");
    // wire value stays `audit`; DISPLAYED as "Monitor"
    expect(screen.getByTestId("enforcement-mode-audit")).toHaveTextContent("Monitor");
    expect(screen.getByTestId("enforcement-mode-audit")).not.toHaveTextContent(/audit/i);
  });

  it("flipping to Monitor PUTs enforcement_mode:'audit' for the concrete namespace, not 'all'", async () => {
    let putBody: any = null;
    let putUrl = "";
    handlers();
    server.use(http.put("/api/v1/settings", async ({ request }) => {
      putUrl = request.url; putBody = await request.json();
      return HttpResponse.json({ apply_mode: "enforce", enforcement_mode: "audit" });
    }));
    const { fireEvent } = await import("@testing-library/react");
    renderPage();
    fireEvent.click(await screen.findByTestId("enforcement-mode-audit"));
    await waitFor(() => expect(putBody).toEqual({ enforcement_mode: "audit" }));  // pre-fix: no such toggle
    expect(putUrl).toContain("namespace=default");                                // concrete ns, never all
  });

  it("relabels apply_mode as Live / Frozen (not Enforce / Dry-run only)", async () => {
    handlers();
    renderPage();
    expect(await screen.findByTestId("apply-mode-enforce")).toHaveTextContent("Live");
    expect(screen.getByTestId("apply-mode-dry_run_only")).toHaveTextContent("Frozen");
    expect(screen.queryByText(/Dry-run only/i)).not.toBeInTheDocument();
  });

  it("disables the enforcement toggle under the aggregate 'all' scope (no aggregate write)", async () => {
    mockApp.namespace = "all";
    handlers();
    renderPage();
    expect(await screen.findByTestId("enforcement-mode-audit")).toBeDisabled();
  });
});
