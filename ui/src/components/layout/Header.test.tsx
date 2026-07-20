// SPDX-License-Identifier: Apache-2.0
// The header time-range selector renders ONLY on time-scoped routes, and the selected chip
// carries a visible ACTIVE state (teal --accent + aria-pressed + `active` class), distinct from the
// muted inactive chips. Header's mount fetches are left unhandled (bypassed) — they fail gracefully;
// the chips render synchronously from the route, which is what we assert.
import { render, screen } from "@testing-library/react";
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
