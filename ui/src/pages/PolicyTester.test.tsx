// SPDX-License-Identifier: Apache-2.0
// MUT-SIGNALS: the Result panel must show ONLY telemetry the engine actually returned. When /evaluate
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

describe("PolicyTester signals honesty (MUT-SIGNALS)", () => {
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

  it("renders real signal bars when the engine DOES return them", async () => {
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
