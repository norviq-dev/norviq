// SPDX-License-Identifier: Apache-2.0
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { PolicyCatalog } from "./PolicyCatalog";
import { AppProvider } from "../store/AppContext";

// Monaco can't mount in jsdom — stub it so we can assert the editor surfaced.
vi.mock("@monaco-editor/react", () => ({
  default: ({ value }: { value?: string }) => <div data-testid="monaco-editor">{value}</div>
}));

const server = setupServer();
let deploymentsCalls = 0;
let deployments404 = false;

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => {
  server.resetHandlers();
  deploymentsCalls = 0;
  deployments404 = false;
});
afterAll(() => server.close());

function seedHandlers(policyTargetType: string | undefined) {
  const policy: Record<string, unknown> = {
    namespace: "default",
    agent_class: "customer-support",
    current_version: 1,
    rego_length: 120,
    priority: 700
  };
  if (policyTargetType !== undefined) policy.target_type = policyTargetType;
  server.use(
    http.get("/api/v1/policies", () => HttpResponse.json([policy])),
    http.get("/api/v1/deployments", () => {
      deploymentsCalls += 1;
      return HttpResponse.json([{ name: "customer-support", namespace: "default", agent_class: "customer-support" }]);
    }),
    http.get("/api/v1/policies/default/customer-support", () =>
      HttpResponse.json({ namespace: "default", agent_class: "customer-support", rego_source: "package norviq.strict\n", version: 1 })
    ),
    http.get("/api/v1/policies/default/customer-support/versions", () => HttpResponse.json([]))
  );
}

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <PolicyCatalog />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("PolicyCatalog (#3 / #4)", () => {
  it("opens the class policy in the editor (Monaco mounts) and groups it under Agent-Class", async () => {
    seedHandlers("class");
    renderPage();

    // Editor is the landing tab: the class policy file is listed and Monaco mounts.
    expect(await screen.findByText("customer-support.rego")).toBeInTheDocument();
    expect(screen.getByTestId("monaco-editor")).toBeInTheDocument();

    // It lands in the Agent-Class tier of the catalog (not "No class policies configured").
    fireEvent.click(screen.getByRole("button", { name: /^catalog$/i }));
    expect(await screen.findByText(/agent-class policies/i)).toBeInTheDocument();
    expect(screen.getAllByText("customer-support").length).toBeGreaterThan(0);
    expect(screen.queryByText(/no class policies configured/i)).not.toBeInTheDocument();
  });

  it("defaults a target_type-less policy to class (UI defense-in-depth)", async () => {
    seedHandlers(undefined); // API omitted target_type
    renderPage();
    // Still opens in the editor — withTargetType() defaults agent_class policies to "class".
    expect(await screen.findByText("customer-support.rego")).toBeInTheDocument();
    expect(screen.getByTestId("monaco-editor")).toBeInTheDocument();
  });

  it("fetches /api/v1/deployments without a 404 (#4)", async () => {
    seedHandlers("class");
    server.use(
      http.get("/api/v1/deployments", ({ request }) => {
        deploymentsCalls += 1;
        if (new URL(request.url).pathname !== "/api/v1/deployments") deployments404 = true;
        return HttpResponse.json([]);
      })
    );
    renderPage();
    await waitFor(() => expect(deploymentsCalls).toBeGreaterThan(0));
    expect(deployments404).toBe(false);
  });
});
