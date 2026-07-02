// SPDX-License-Identifier: Apache-2.0
// UI-1 smoke test: Agents page mounts without React #130 (renders DonutChart/VolumeChart/CategoryBars).
import { render, screen, waitFor } from "@testing-library/react";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("echarts-for-react/lib/core", () => ({ default: () => null }));

import { AgentMonitor } from "./AgentMonitor";
import { AppProvider } from "../store/AppContext";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("UI-1: AgentMonitor mounts", () => {
  it("renders the Agent Monitor page without a React #130 crash", async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((m) => errors.push(String(m)));
    render(
      <MemoryRouter>
        <AppProvider>
          <AgentMonitor />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("Agent Monitor")).toBeInTheDocument());
    expect(errors.join("\n")).not.toMatch(/#130|element type is invalid/i);
    spy.mockRestore();
  });
});
