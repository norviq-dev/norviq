// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { useEffect } from "react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { AppProvider, useApp } from "../../store/AppContext";
import * as client from "../../api/client";

// ExpandedPanel calls fetchVersion() on every mount and nothing in this suite mocks the network.
// One unmocked call was survivable; the route sweep below mounts the panel once per nav link, and a
// batch of late-rejecting promises resolving after their test has unmounted surfaced as a failure in
// whichever unrelated test happened to be running. Stub it: this file is about which link is lit.
vi.spyOn(client, "fetchVersion").mockResolvedValue({ version: "0.0.0-test" } as never);
import ExpandedPanel from "./ExpandedPanel";

function ForceSecurity({ children }: { children: React.ReactNode }) {
  const { setActiveSection } = useApp();
  useEffect(() => setActiveSection("security"), [setActiveSection]);
  return <>{children}</>;
}

describe("ExpandedPanel navigation", () => {
  it("shows Policy Tester and the Red Team view (it ships) under TESTING", () => {
    render(
      <MemoryRouter>
        <AppProvider>
          <ForceSecurity>
            <ExpandedPanel />
          </ForceSecurity>
        </AppProvider>
      </MemoryRouter>
    );
    expect(screen.getByText("Policy Tester")).toBeInTheDocument();
    const redTeam = screen.getByText("Red Team");
    expect(redTeam).toBeInTheDocument();
    expect(redTeam.closest("a")).toHaveAttribute("href", "/redteam");
  });
});

function renderAt(route: string) {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <AppProvider>
        <ForceSecurity>
          <ExpandedPanel />
        </ForceSecurity>
      </AppProvider>
    </MemoryRouter>
  );
}

const activeHrefs = (c: HTMLElement) =>
  [...c.querySelectorAll(".sb-nav .sb-link.active")].map((a) => a.getAttribute("href"));

describe("exactly one nav item is highlighted", () => {
  it("does not light the parent when standing on a nested item", () => {
    // Reported from the live console: on Policy Compliance, BOTH Compliance and Policy Compliance were
    // highlighted. NavLink matches by prefix unless `end` is set, and `end` was set only for "/", so
    // `/compliance` matched `/compliance/policies` too.
    const { container } = renderAt("/compliance/policies");
    expect(activeHrefs(container)).toEqual(["/compliance/policies"]);
  });

  it("still lights the parent on the parent's own route", () => {
    // The obvious over-fix is `end` on everything, which would also be wrong here in the other
    // direction — so pin both ends of the behaviour, not just the bug.
    const { container } = renderAt("/compliance");
    expect(activeHrefs(container)).toEqual(["/compliance"]);
  });

  it("keeps prefix matching for a DETAIL route under a leaf item", () => {
    // This is why `end` is derived rather than applied to every item: nothing in the nav sits under
    // /tools, so a tool detail page must keep Tools lit. Blanket `end` would leave the sidebar with
    // nothing highlighted at all.
    const { container } = renderAt("/tools/get_order");
    expect(activeHrefs(container)).toEqual(["/tools"]);
  });

  it("never highlights two items, on any route the nav can reach", () => {
    // The general property, checked against the nav's own link list so a future nested item is
    // covered without anyone remembering to extend this test.
    const { container, unmount } = renderAt("/");
    const routes = [...container.querySelectorAll(".sb-nav .sb-link")].map((a) => a.getAttribute("href")!);
    unmount();
    expect(routes.length).toBeGreaterThan(5);
    for (const r of routes) {
      const view = renderAt(r);
      expect(activeHrefs(view.container), `route ${r}`).toEqual([r]);
      view.unmount();
    }
  });
});
