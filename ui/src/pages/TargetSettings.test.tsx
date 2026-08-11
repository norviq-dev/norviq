// SPDX-License-Identifier: Apache-2.0
// Target Settings is now namespace-GOVERNANCE only — the "effective policy" resolved-stack view
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

describe("TargetSettings — governance only", () => {
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

  it("the subtitle binds to the working scope (concrete ns, not 'all')", async () => {
    handlers();
    renderPage();
    expect(await screen.findByText("Namespace: default")).toBeInTheDocument();
    expect(screen.queryByText(/Namespace: all/i)).not.toBeInTheDocument();
  });

  it("an aggregate scope shows 'All namespaces', never 'Namespace: all'", async () => {
    mockApp.namespace = "all";
    handlers();
    renderPage();
    expect(await screen.findByText("All namespaces")).toBeInTheDocument();
    expect(screen.queryByText("Namespace: all")).not.toBeInTheDocument();
  });

  it("packs-applied shows the APPLIED set for the concrete namespace", async () => {
    handlers([{ id: "ecommerce", title: "E-commerce", enabled: true }, { id: "pci", title: "PCI", enabled: true }, { id: "off", title: "Off", enabled: false }]);
    renderPage();
    await waitFor(() => expect(screen.getByTestId("packs-applied-state")).toHaveAttribute("data-count", "2"));
    expect(screen.getByTestId("packs-applied-state")).toHaveTextContent(/2 packs applied/i);
    expect(screen.getByText("E-commerce")).toBeInTheDocument();
    expect(screen.getByText("PCI")).toBeInTheDocument();
  });

  it("packs-applied shows NONE when no packs are enabled", async () => {
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

// TGT-POSTURE-01 — WHAT THE MODE MEANS IS STATE, NOT PERMISSION.
// Both consequence sentences were gated on `isAdmin`, so a read-only auditor opening a Monitor + Frozen
// namespace saw two live-looking segmented controls, the words "Monitor"/"Frozen", and "Admin only" — and
// nothing at all about the fact that live traffic is not being stopped. This page is the ONLY place in the
// console where those consequences exist as readable text (the header chip's visible text is the two words
// "Monitor mode"; its consequence lives in a `title` tooltip), so gating it on the write permission hid the
// posture from exactly the reader auditing it.
describe("Namespace Governance states the CONSEQUENCE of the mode to every reader", () => {
  function monitorFrozen(role: "admin" | "viewer") {
    server.use(
      http.get("/api/v1/me", () => HttpResponse.json({ role, namespace: null })),
      http.get("/api/v1/settings", () => HttpResponse.json({ apply_mode: "dry_run_only", enforcement_mode: "audit" })),
      http.get("/api/v1/policy-packs", () => HttpResponse.json([]))
    );
  }

  it("a VIEWER sees the Monitor and Frozen consequence sentences, not just 'Admin only'", async () => {
    mockApp.namespace = "payments";
    monitorFrozen("viewer");
    renderPage();

    // FAIL-ON-BUG: pre-fix both notes were `isAdmin &&` gated, so both queries returned null for a viewer.
    const monitorNote = await screen.findByTestId("enforcement-monitor-note");
    expect(monitorNote).toHaveTextContent(/logs a would-block instead of stopping the call/i);
    expect(screen.getByTestId("apply-mode-dryrun-note")).toHaveTextContent(/policy edits are frozen \(live policy still enforces\)/i);
    // Permission is still stated — as a fact about the CONTROL, next to it.
    expect(screen.getAllByText(/Admin only/i)).toHaveLength(2); // one per control
    // And the read-only segmented control is visibly read-only (`.tab-kit` has no `:disabled` styling of its
    // own, so an undimmed disabled tab was indistinguishable from a live one).
    expect(screen.getByTestId("enforcement-mode-audit")).toHaveStyle({ opacity: "0.55" });
  });

  it("an ADMIN still gets both sentences (the ungating did not move them off the admin path)", async () => {
    mockApp.namespace = "payments";
    monitorFrozen("admin");
    renderPage();
    expect(await screen.findByTestId("enforcement-monitor-note")).toBeInTheDocument();
    expect(screen.getByTestId("apply-mode-dryrun-note")).toBeInTheDocument();
    expect(screen.queryAllByText(/Admin only/i)).toHaveLength(0);
  });

  // /settings' enforcement_mode merges the CLUSTER-WIDE default (settings_router `_effective`), while the
  // engine softens ONLY on an explicit per-namespace override (`_resolve_posture`: "a null/global mode does
  // NO softening"), so under the aggregate scope the flat namespace consequence ("nothing is stopped here")
  // must NOT be asserted over every namespace.
  //
  // REWRITTEN (was: asserted the note says "the cluster-wide default is Monitor"). That sentence was itself
  // untrue of the code under it, so the assertion is re-pointed at the corrected behaviour rather than kept:
  // `fetchSettings("all")` DROPS the namespace param, and `GET /api/v1/settings` declares
  // `namespace: str = Query("default")`. An unscoped read is therefore the namespace literally named
  // `default`, merged with the global — not a cluster-wide value. The request assertion below pins the fact
  // the copy now depends on, so a future change to either end breaks this test rather than the sentence.
  it("under the aggregate scope the Monitor note names the UNSCOPED reading, and does not claim a cluster-wide default", async () => {
    mockApp.namespace = "all";
    const settingsUrls: string[] = [];
    server.use(
      http.get("/api/v1/me", () => HttpResponse.json({ role: "admin", namespace: null })),
      http.get("/api/v1/settings", ({ request }) => {
        const url = new URL(request.url);
        settingsUrls.push(url.pathname + url.search);
        // What the server really answers an unscoped read with: the `default` NAMESPACE's row.
        return HttpResponse.json({ namespace: "default", apply_mode: "dry_run_only", enforcement_mode: "audit" });
      }),
      http.get("/api/v1/policy-packs", () => HttpResponse.json([]))
    );
    renderPage();
    const note = await screen.findByTestId("enforcement-monitor-note-aggregate");

    // The read carried NO namespace, so the answer cannot be attributed to the cluster as a whole.
    expect(settingsUrls).toEqual(["/api/v1/settings"]);
    // FAIL-ON-BUG: this used to read "The cluster-wide default is Monitor."
    expect(note).not.toHaveTextContent(/cluster-wide default is Monitor/i);
    expect(note).toHaveTextContent(/unscoped Settings read/i);
    expect(note).toHaveTextContent(/default/);
    // The true half is kept: a namespace that does not set Monitor itself is not softened.
    expect(note).toHaveTextContent(/only where a namespace sets Monitor itself/i);
    expect(screen.queryByTestId("enforcement-monitor-note")).not.toBeInTheDocument();
  });

  // A POSTURE WE DID NOT READ IS NOT A POSTURE. Both knobs resolved an absent payload to their reassuring
  // value — `settings.data?.enforcement_mode === "audit" ? "audit" : "block"` and the same shape for
  // apply_mode — so a 5xx left this page highlighting "Block" and "Live" in exactly the pixels it uses for a
  // measured answer. On the page whose whole job is to say how a namespace is governed, that is the
  // "we could not measure it" → "we measured, and it is fine" inversion in its most direct form.
  it("a FAILED /settings read shows no posture at all — not a highlighted 'Block' + 'Live'", async () => {
    mockApp.namespace = "payments";
    server.use(
      http.get("/api/v1/me", () => HttpResponse.json({ role: "admin", namespace: null })),
      http.get("/api/v1/settings", () => new HttpResponse("boom", { status: 500 })),
      http.get("/api/v1/policy-packs", () => HttpResponse.json([]))
    );
    renderPage();

    // FAIL-ON-BUG: pre-fix `enforcement-mode-block` and `apply-mode-enforce` both carried `active`.
    const unreadable = await screen.findByTestId("enforcement-mode-unreadable");
    expect(unreadable).toHaveTextContent(/unknown, not Block/i);
    expect(screen.getByTestId("apply-mode-unreadable")).toHaveTextContent(/unknown, not Live/i);
    for (const id of ["enforcement-mode-block", "enforcement-mode-audit", "apply-mode-enforce", "apply-mode-dry_run_only"]) {
      expect(screen.getByTestId(id).className).not.toMatch(/\bactive\b/);
    }
    // The controls themselves stay on the page — an admin can still SET a posture we could not read.
    expect(screen.getByTestId("enforcement-mode-audit")).toBeEnabled();
    // And no consequence sentence is asserted off a posture that was never read.
    expect(screen.queryByTestId("enforcement-monitor-note")).toBeNull();
    expect(screen.queryByTestId("apply-mode-dryrun-note")).toBeNull();
  });

  // "Admin only" is a fact about the CONTROL. "read-only for your ROLE" is a claim about the READER, and
  // `isAdmin` is false for three different reasons — including "/me failed", where an admin was told, as
  // fact, that their role is read-only.
  it("does not assert the reader's role when /me could not be read", async () => {
    mockApp.namespace = "payments";
    server.use(
      http.get("/api/v1/me", () => new HttpResponse("boom", { status: 500 })),
      http.get("/api/v1/settings", () => HttpResponse.json({ apply_mode: "enforce", enforcement_mode: "block" })),
      http.get("/api/v1/policy-packs", () => HttpResponse.json([]))
    );
    renderPage();

    // FAIL-ON-BUG: pre-fix both notes read "Admin only — read-only for your role."
    await waitFor(() => expect(screen.getAllByText(/your role could not be read/i)).toHaveLength(2));
    expect(screen.queryByText(/read-only for your role/i)).toBeNull();
    // Still says what IS true of the control.
    expect(screen.getAllByText(/Admin only/i)).toHaveLength(2);
  });
});
