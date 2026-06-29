// SPDX-License-Identifier: Apache-2.0
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import PolicyPacks from "./PolicyPacks";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";

const server = setupServer();
beforeAll(() => server.listen());
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

function handlers(role: string, enabled: Set<string>) {
  return [
    http.get("/api/v1/me", () => HttpResponse.json({ sub: "u", role, namespace: "default" })),
    http.get("/api/v1/settings", () => HttpResponse.json({ namespace: "default", sector: "Energy" })),
    http.get("/api/v1/policy-packs", () =>
      HttpResponse.json([
        pack("energy-ot", "Energy", "Energy OT/IT Segmentation", enabled.has("energy-ot")),
        pack("finance-money-movement", "Finance", "Finance Money-Movement", enabled.has("finance-money-movement"))
      ])
    ),
    http.post("/api/v1/policy-packs/:id/enable", ({ params }) => {
      enabled.add(String(params.id));
      return HttpResponse.json({ namespace: "default", pack_id: params.id, enabled: true, enabled_packs: [...enabled] });
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
      <AppProvider>
        <PolicyPacks />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("PolicyPacks page (F047)", () => {
  it("renders packs grouped by sector with enabled state and suggested-sector highlight", async () => {
    server.use(...handlers("admin", new Set(["finance-money-movement"])));
    renderPage();
    expect(await screen.findByText("Energy OT/IT Segmentation")).toBeInTheDocument();
    expect(screen.getByText("Finance Money-Movement")).toBeInTheDocument();
    // sector headers + the suggestion chip (settings.sector = Energy)
    expect(screen.getByText("Suggested for your sector")).toBeInTheDocument();
    // enabled state reflected
    expect(screen.getByText("Off")).toBeInTheDocument();
    expect(screen.getByText("Enabled")).toBeInTheDocument();
  });

  it("admin can enable a pack — POSTs and reflects the new state", async () => {
    server.use(...handlers("admin", new Set()));
    renderPage();
    const enableBtn = await screen.findAllByRole("button", { name: "Enable" });
    expect(enableBtn.length).toBe(2);
    fireEvent.click(enableBtn[0]);
    // after the POST + refetch, one pack flips to Enabled
    await waitFor(() => expect(screen.getByText("Enabled")).toBeInTheDocument());
  });

  it("viewer sees read-only catalog (no enable/disable buttons)", async () => {
    server.use(...handlers("viewer", new Set()));
    renderPage();
    expect(await screen.findByText("Energy OT/IT Segmentation")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Enable" })).not.toBeInTheDocument();
    expect(screen.getAllByText("Admin only").length).toBeGreaterThan(0);
  });
});
