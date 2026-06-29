// SPDX-License-Identifier: Apache-2.0
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Settings } from "./Settings";
import { AppProvider } from "../store/AppContext";

const server = setupServer();
let putBody: Record<string, unknown> | null = null;

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
beforeEach(() => {
  putBody = null;
  server.use(
    http.get("/api/v1/settings", () =>
      HttpResponse.json({
        namespace: "default",
        enforcement_mode: "block",
        trust_threshold: 0.7,
        violation_penalty: 0.05,
        rate_limit: 60
      })
    ),
    http.put("/api/v1/settings", async ({ request }) => {
      putBody = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({
        namespace: "default",
        enforcement_mode: "block",
        trust_threshold: 0.55,
        violation_penalty: 0.05,
        rate_limit: 60
      });
    })
  );
});
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <Settings />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("Settings (#8) — server-backed", () => {
  it("loads the effective settings from the API", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByDisplayValue("0.7")).toBeInTheDocument());
    expect(screen.getByDisplayValue("60")).toBeInTheDocument();
  });

  it("saves via PUT /settings and shows a confirmation", async () => {
    renderPage();
    const trust = await screen.findByDisplayValue("0.7");
    fireEvent.change(trust, { target: { value: "0.55" } });
    fireEvent.click(screen.getByRole("button", { name: /save changes/i }));

    await waitFor(() => expect(screen.getByText(/settings saved/i)).toBeInTheDocument());
    expect(putBody).toMatchObject({ enforcement_mode: "block", trust_threshold: 0.55 });
  });

  it("notes that settings are persisted server-side", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText(/persisted server-side/i)).toBeInTheDocument());
  });
});
