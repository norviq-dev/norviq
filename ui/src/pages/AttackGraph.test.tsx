import { render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import AttackGraph from "./AttackGraph";
import { AppProvider } from "../store/AppContext";

const server = setupServer();
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <AttackGraph />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("AttackGraph page", () => {
  it("shows data when API returns paths", async () => {
    server.use(
      http.get("/api/v1/attack-paths", () =>
        HttpResponse.json({
          paths: [
            {
              path_id: "p1",
              source_id: "a",
              target_id: "b",
              steps: [],
              risk_score: 0.9,
              severity: "critical",
              mitre_techniques: [],
              blocked_by_policy: false
            }
          ],
          nodes: []
        })
      )
    );
    renderPage();
    await waitFor(() => expect(screen.getByText(/total: 1/i)).toBeInTheDocument());
  });
});
