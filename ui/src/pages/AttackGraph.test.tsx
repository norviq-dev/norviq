import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

const PATH = {
  path_id: "p1",
  source_id: "spiffe://norviq/ns/default/sa/customer-support",
  target_id: "users",
  steps: [{ step_num: 1, node_id: "n", action: "execute_sql", policy_check: "would_block" }],
  risk_score: 0.9,
  severity: "critical",
  mitre_techniques: [],
  blocked_by_policy: false
};

describe("AttackGraph page", () => {
  it("shows data when API returns paths", async () => {
    server.use(http.get("/api/v1/attack-paths", () => HttpResponse.json({ paths: [PATH], nodes: [] })));
    renderPage();
    await waitFor(() => expect(screen.getByText(/total: 1/i)).toBeInTheDocument());
  });

  it("Simulate runs a REAL evaluation (calls /api/v1/evaluate) and renders the decision (#6)", async () => {
    let evaluateCalled = 0;
    server.use(
      http.get("/api/v1/attack-paths", () => HttpResponse.json({ paths: [PATH], nodes: [] })),
      http.post("/api/v1/evaluate", () => {
        evaluateCalled += 1;
        return HttpResponse.json({ decision: "block", rule_id: "deny_sql_injection", trust_score: 0.5 });
      })
    );
    renderPage();
    // highest-risk path auto-selects → Simulate is enabled without manual selection.
    const button = await screen.findByRole("button", { name: /simulate attack/i });
    await waitFor(() => expect(button).not.toBeDisabled());
    fireEvent.click(button);
    await waitFor(() => expect(evaluateCalled).toBeGreaterThan(0));
    expect(await screen.findByText(/simulation blocked by policy/i)).toBeInTheDocument();
  });
});
