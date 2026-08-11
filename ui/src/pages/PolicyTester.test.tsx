// SPDX-License-Identifier: Apache-2.0
// The Result panel must show ONLY telemetry the engine actually returned. When /evaluate
// omits trust_signals it previously substituted all-1.0 defaults that rendered as real "1.00 OK" bars
// — indistinguishable from genuine per-call signal data. Now it says so honestly.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { PolicyTester } from "./PolicyTester";
import { AppProvider } from "../store/AppContext";

const server = setupServer(
  http.get("/api/v1/cluster-info", () => HttpResponse.json({ cluster_id: "local", cluster_name: "local", namespaces: ["default"] })),
  http.get("/api/v1/settings", () => HttpResponse.json({ namespace: "default", enforcement_mode: "block", trust_threshold: 0.7, rate_limit: 60, apply_mode: "enforce" }))
);
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <PolicyTester />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("PolicyTester signals honesty", () => {
  it("shows an explicit 'no signals' note when the engine returns none (no fabricated 1.00 OK bars)", async () => {
    server.use(
      http.post("/api/v1/evaluate", () =>
        // decision only — NO trust_signals in the response.
        HttpResponse.json({ decision: "block", rule_id: "deny_sql_injection", trust_score: 0.5 })
      )
    );
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /^evaluate$/i }));
    await waitFor(() => expect(screen.getByTestId("signals-unavailable")).toBeInTheDocument());
    // Crucially: no fabricated "1.00" signal value is rendered.
    expect(screen.queryByText("1.00")).not.toBeInTheDocument();
  });

  // NOTE ON THIS FIXTURE: /api/v1/evaluate does NOT return `trust_signals` today — evaluate.py's
  // `EvaluateResponse` has exactly three fields (decision / rule_id / trust_score), so the body below
  // is one this API cannot currently produce and the branch it covers is unreachable in production.
  // The test is kept (and renamed) as a CONDITIONAL contract — "if a response ever carries signals,
  // render the real values, never fabricated ones" — not as evidence that the endpoint carries them.
  // The reachable branch, and the copy the operator actually reads, is covered above and in
  // PolicyTester.provenance.test.tsx.
  it("renders real signal bars IF a response ever carries them (branch is unreachable via /evaluate today)", async () => {
    server.use(
      http.post("/api/v1/evaluate", () =>
        HttpResponse.json({
          decision: "allow",
          rule_id: "default_allow",
          trust_score: 0.9,
          trust_signals: { violation_rate: 0.2, tool_novelty: 0.8 }
        })
      )
    );
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /^evaluate$/i }));
    await waitFor(() => expect(screen.getByText("violation_rate")).toBeInTheDocument());
    expect(screen.queryByTestId("signals-unavailable")).not.toBeInTheDocument();
    expect(screen.getByText("0.20")).toBeInTheDocument();
  });
});
