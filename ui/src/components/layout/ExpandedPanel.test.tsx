// SPDX-License-Identifier: Apache-2.0
import { render, screen } from "@testing-library/react";
import { useEffect } from "react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { AppProvider, useApp } from "../../store/AppContext";
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
