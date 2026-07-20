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
        rate_limit: 60
      })
    ),
    http.put("/api/v1/settings", async ({ request }) => {
      putBody = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({
        namespace: "default",
        enforcement_mode: "block",
        trust_threshold: 0.55,
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
    // Governance (enforcement_mode/apply_mode) moved to Target Settings — Settings now only
    // persists the tuning defaults, so the PUT body must NOT carry enforcement_mode.
    expect(putBody).toMatchObject({ trust_threshold: 0.55 });
    expect(putBody).not.toHaveProperty("enforcement_mode");
    expect(putBody).not.toHaveProperty("apply_mode");
    // violation_penalty was a dead control (never reached the engine) — it must no longer be sent.
    expect(putBody).not.toHaveProperty("violation_penalty");
  });

  it("governance is not duplicated here — it links to Target Settings instead", async () => {
    renderPage();
    await screen.findByDisplayValue("0.7");
    // The duplicate Block/Monitor + Live/Frozen toggles are gone; a pointer to Target Settings remains.
    expect(screen.queryByText("Enforcement Mode")).not.toBeInTheDocument();
    expect(screen.getByText(/managed in Target Settings/i)).toBeInTheDocument();
  });

  it("notes that settings are persisted server-side", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText(/persisted server-side/i)).toBeInTheDocument());
  });
});
