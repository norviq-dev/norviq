// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import PolicyPacks from "./PolicyPacks";
import { clearApiCache } from "../hooks/useApi";

// The mutation guard reads the selected scope from useApp() — mock it so each test controls the namespace
// (the real AppProvider defaults to the aggregate "all", under which every mutation is correctly disabled).
const mockApp = { namespace: "default", selectedCluster: "local", isRemote: false, namespaces: ["default", "payments"] };
vi.mock("../store/AppContext", () => ({
  useApp: () => mockApp,
  AppProvider: ({ children }: { children: ReactNode }) => <>{children}</>
}));

const server = setupServer();
beforeAll(() => server.listen());
beforeEach(() => {
  mockApp.namespace = "default";
  mockApp.selectedCluster = "local";
  mockApp.isRemote = false;
});
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

function pack(id: string, sector: string, title: string, enabled: boolean) {
  return {
    id,
    sector,
    title,
    enforces: `${title} enforcement`,
    rule_ids: ["rule_a", "rule_b"],
    composes: sector === "Finance" ? ["pci_card_numbers"] : [],
    categories: [`${sector} Cat`],
    compliance: ["REG-1"],
    tunables: ["verbs"],
    enabled,
    namespace: "default"
  };
}

function handlers(role: string, enabled: Set<string>, opts: { applyMode?: string; onEnable?: (ns: string) => void } = {}) {
  return [
    http.get("/api/v1/me", () => HttpResponse.json({ sub: "u", role, namespace: "default" })),
    http.get("/api/v1/settings", () => HttpResponse.json({ namespace: "default", sector: "Energy", apply_mode: opts.applyMode ?? "enforce" })),
    http.get("/api/v1/policy-packs/override", () => HttpResponse.json({ namespace: "default", rego_source: "", active: false, mode: "tighten-only" })),
    http.get("/api/v1/policy-packs", () =>
      HttpResponse.json([
        pack("energy-ot", "Energy", "Energy OT/IT Segmentation", enabled.has("energy-ot")),
        pack("finance-money-movement", "Finance", "Finance Money-Movement", enabled.has("finance-money-movement"))
      ])
    ),
    http.post("/api/v1/policy-packs/:id/enable", async ({ params, request }) => {
      const body = (await request.json().catch(() => ({}))) as { namespace?: string };
      opts.onEnable?.(String(body?.namespace ?? ""));
      enabled.add(String(params.id));
      return HttpResponse.json({ namespace: body?.namespace ?? "default", pack_id: params.id, enabled: true, enabled_packs: [...enabled] });
    }),
    http.post("/api/v1/policy-packs/:id/disable", ({ params }) => {
      enabled.delete(String(params.id));
      return HttpResponse.json({ namespace: "default", pack_id: params.id, enabled: false, enabled_packs: [...enabled] });
    })
  ];
}

function renderPage() {
  return render(
    <MemoryRouter>
      <PolicyPacks />
    </MemoryRouter>
  );
}

describe("PolicyPacks page", () => {
  it("renders packs grouped by sector with enabled state and suggested-sector highlight", async () => {
    server.use(...handlers("admin", new Set(["finance-money-movement"])));
    renderPage();
    expect(await screen.findByText("Energy OT/IT Segmentation")).toBeInTheDocument();
    expect(screen.getByText("Finance Money-Movement")).toBeInTheDocument();
    expect(screen.getByText("Suggested")).toBeInTheDocument();
    expect(screen.getByText("Energy")).toBeInTheDocument();
    expect(screen.getByText("Off")).toBeInTheDocument();
    expect(screen.getByText("Enabled")).toBeInTheDocument();
  });

  it("admin can enable a pack under a concrete namespace — POSTs {namespace:default} and flips to Enabled", async () => {
    const sentNs: string[] = [];
    server.use(...handlers("admin", new Set(), { onEnable: (ns) => sentNs.push(ns) }));
    renderPage();
    const enableBtn = await screen.findAllByRole("button", { name: "Enable" });
    expect(enableBtn.length).toBe(2);
    fireEvent.click(enableBtn[0]);
    // PACK-CONFIRM: enabling now confirms first (names the namespace); the POST only fires on confirm.
    const confirm = await screen.findByTestId("pack-confirm-apply");
    fireEvent.click(confirm);
    await waitFor(() => expect(screen.getByText("Enabled")).toBeInTheDocument());
    // The write targeted the concrete namespace, never the phantom "all".
    expect(sentNs).toContain("default");
    expect(sentNs).not.toContain("all");
  });

  it("the apply-result badge never shows APPLIED while its own outcome text still says Verifying, " +
    "and converges to a matching APPLIED + 'Confirmed via a live read' once the toggle's poll resolves", async () => {
    server.use(...handlers("admin", new Set()));
    renderPage();
    const enableBtn = await screen.findAllByRole("button", { name: "Enable" });
    fireEvent.click(enableBtn[0]);
    const confirm = await screen.findByTestId("pack-confirm-apply");
    fireEvent.click(confirm);
    // Eventually the toggle's own poll converges (msw's enable handler adds the id synchronously, so the
    // first poll try already matches) and the panel shows a badge consistent with its own outcome text —
    // never an APPLIED badge sitting above lingering "Verifying…" body text.
    await waitFor(() => expect(screen.getByText(/Confirmed via a live read/i)).toBeInTheDocument());
    expect(screen.getByText("APPLIED")).toBeInTheDocument();
  });

  it("PACK-CONFIRM: cancelling the confirm dialog fires no network POST", async () => {
    const sentNs: string[] = [];
    server.use(...handlers("admin", new Set(), { onEnable: (ns) => sentNs.push(ns) }));
    renderPage();
    const enableBtn = await screen.findAllByRole("button", { name: "Enable" });
    fireEvent.click(enableBtn[0]);
    fireEvent.click(await screen.findByRole("button", { name: /cancel/i }));
    // no confirm → no write, pack stays Off.
    expect(sentNs).toHaveLength(0);
  });

  it("under All-namespaces (aggregate) every pack mutation is DISABLED and prompts for a concrete namespace", async () => {
    mockApp.namespace = "all";
    server.use(...handlers("admin", new Set()));
    renderPage();
    await screen.findByText("Energy OT/IT Segmentation");
    expect(screen.getByTestId("pack-scope-prompt")).toHaveTextContent(/Select a namespace/i);
    // both toggle buttons are disabled — no write can target "all"
    expect(screen.getByTestId("pack-toggle-energy-ot")).toBeDisabled();
    expect(screen.getByTestId("pack-toggle-finance-money-movement")).toBeDisabled();
    // override actions are disabled too
    expect(screen.getByTestId("override-apply")).toBeDisabled();
    expect(screen.getByTestId("override-dryrun")).toBeDisabled();
  });

  it("a disabled aggregate mutation never fires a network POST", async () => {
    mockApp.namespace = "all";
    const sentNs: string[] = [];
    server.use(...handlers("admin", new Set(), { onEnable: (ns) => sentNs.push(ns) }));
    renderPage();
    const btn = await screen.findByTestId("pack-toggle-energy-ot");
    fireEvent.click(btn); // disabled → no-op
    await new Promise((r) => setTimeout(r, 200));
    expect(sentNs).toEqual([]); // nothing sent; certainly no ?namespace=all write
  });

  it("a dry-run-only namespace shows the reason and disables pack enable up-front", async () => {
    server.use(...handlers("admin", new Set(), { applyMode: "dry_run_only" }));
    renderPage();
    await screen.findByText("Energy OT/IT Segmentation");
    expect(screen.getByTestId("pack-dryrun-banner")).toHaveTextContent(/dry-run-only/i);
    expect(screen.getByTestId("pack-toggle-energy-ot")).toBeDisabled();
  });

  it("viewer sees read-only catalog (no enable/disable buttons)", async () => {
    server.use(...handlers("viewer", new Set()));
    renderPage();
    expect(await screen.findByText("Energy OT/IT Segmentation")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Enable" })).not.toBeInTheDocument();
    expect(screen.getAllByText("Admin only").length).toBeGreaterThan(0);
  });

  it("ALL packs lay out in ONE flat side-by-side grid (not one stack per sector)", async () => {
    server.use(...handlers("admin", new Set(["finance-money-movement"])));
    renderPage();
    await screen.findByText("Energy OT/IT Segmentation");
    const rails = screen.getAllByTestId("pack-rail");
    expect(rails.length).toBe(1);
    const rail = rails[0];
    expect(rail).toHaveClass("pack-rail");
    expect(rail.querySelectorAll(".panel").length).toBe(2);
  });
});
