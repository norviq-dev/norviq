// SPDX-License-Identifier: Apache-2.0
// Smoke test: Fleet page mounts without React #130 (crashed identically pre-fix).
import { render, waitFor } from "@testing-library/react";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("echarts-for-react/lib/core", () => ({ default: () => null }));

import Fleet from "./Fleet";
import { AppProvider } from "../store/AppContext";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("Fleet mounts", () => {
  it("mounts without a React #130 crash", async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((m) => errors.push(String(m)));
    const { container } = render(
      <MemoryRouter>
        <AppProvider>
          <Fleet />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(container.firstChild).not.toBeNull());
    expect(errors.join("\n")).not.toMatch(/#130|element type is invalid/i);
    spy.mockRestore();
  });
});
