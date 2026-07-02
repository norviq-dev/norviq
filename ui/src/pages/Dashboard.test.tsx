// SPDX-License-Identifier: Apache-2.0
// UI-1 smoke test: the Dashboard (default landing route) must mount without throwing React #130.
// echarts core is stubbed so the chart components render without a canvas; the interop-shape guard
// lives in components/common/EChart.test.tsx.
import { render, screen, waitFor } from "@testing-library/react";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("echarts-for-react/lib/core", () => ({
  default: () => null
}));

import { Dashboard } from "./Dashboard";
import { AppProvider } from "../store/AppContext";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("UI-1: Dashboard mounts", () => {
  it("renders the Overview page without a React #130 crash", async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((m) => errors.push(String(m)));
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("Overview")).toBeInTheDocument());
    expect(errors.join("\n")).not.toMatch(/#130|element type is invalid/i);
    spy.mockRestore();
  });
});
