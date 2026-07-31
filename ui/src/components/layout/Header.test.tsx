// SPDX-License-Identifier: Apache-2.0
// The header time-range selector renders ONLY on time-scoped routes, and the selected chip
// carries a visible ACTIVE state (teal --accent + aria-pressed + `active` class), distinct from the
// muted inactive chips. Header's mount fetches are left unhandled (bypassed) — they fail gracefully;
// the chips render synchronously from the route, which is what we assert.
import { render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { Header } from "./Header";
import { AppProvider } from "../../store/AppContext";
import { clearApiCache } from "../../hooks/useApi";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => { server.resetHandlers(); clearApiCache(); });
afterAll(() => server.close());

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AppProvider>
        <Header isTablet={false} onMenuToggle={() => {}} tabletMenuOpen={false} />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("Header time-range selector — scope + active state", () => {
  it("renders the range selector on time-scoped routes (/audit, /compliance)", () => {
    renderAt("/audit");
    expect(screen.getByTestId("time-range")).toBeInTheDocument();
    expect(screen.getByTestId("range-chip-24h")).toBeInTheDocument();
  });

  it("renders the range selector on Compliance (it IS range-scoped)", () => {
    renderAt("/compliance");
    expect(screen.getByTestId("time-range")).toBeInTheDocument();
  });

  it("does NOT render the range selector on Policy Catalog (current-state, not time-scoped)", () => {
    renderAt("/policies/catalog");
    expect(screen.queryByTestId("time-range")).not.toBeInTheDocument();
    expect(screen.queryByTestId("range-chip-24h")).not.toBeInTheDocument();
  });

  it("hidden on Policy Packs, Target Settings, and pages with their own range picker (Attack/Asset Graph)", () => {
    for (const p of ["/policies/packs", "/policies/targets", "/threats/graph", "/asset-graph"]) {
      const { unmount } = renderAt(p);
      expect(screen.queryByTestId("time-range")).not.toBeInTheDocument();
      unmount();
    }
  });

  it("the selected chip (default 24h) is ACTIVE (aria-pressed + `active` class + --accent fill); others are not", () => {
    renderAt("/audit");
    const active = screen.getByTestId("range-chip-24h");
    expect(active).toHaveAttribute("aria-pressed", "true");
    expect(active.className).toContain("active");
    // teal --accent fill (jsdom resolves the inline var literally to the CSS custom property).
    expect(active).toHaveStyle({ background: "var(--accent)" });

    for (const r of ["1h", "6h", "7d", "30d"]) {
      const chip = screen.getByTestId(`range-chip-${r}`);
      expect(chip).toHaveAttribute("aria-pressed", "false");
      expect(chip.className).not.toContain("active");
    }
  });
});

describe("Inbox alert copy agrees with its own count", () => {
  // A single blocked call read as "1 tool calls blocked". An alert that contradicts the number
  // sitting next to it undercuts the one thing the alert exists to state.
  async function openInboxWith(blocked: number) {
    server.use(
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 100, blocked, allowed: 100 - blocked })),
      http.get("*/api/v1/agents", () => HttpResponse.json([]))
    );
    renderAt("/audit");
    screen.getByRole("button", { name: /Inbox/i }).click();
  }

  it("says 'call' for exactly one blocked call", async () => {
    await openInboxWith(1);
    await waitFor(() => expect(screen.getByText(/1 tool call blocked in last 24h/)).toBeInTheDocument());
    expect(screen.queryByText(/1 tool calls blocked/)).not.toBeInTheDocument();
  });

  it("keeps the plural for more than one", async () => {
    await openInboxWith(4);
    await waitFor(() => expect(screen.getByText(/4 tool calls blocked in last 24h/)).toBeInTheDocument());
  });
});
