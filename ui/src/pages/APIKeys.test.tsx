// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { APIKeys } from "./APIKeys";
import { clearApiCache } from "../hooks/useApi";

// The create guard reads the selected scope from useApp() — mock it so each test controls the namespace.
const mockApp = { namespace: "default" };
vi.mock("../store/AppContext", () => ({
  useApp: () => mockApp,
  AppProvider: ({ children }: { children: ReactNode }) => <>{children}</>
}));

let created: Array<{ name?: string; namespace?: string }> = [];
const server = setupServer(
  http.get("/api/v1/keys", () => HttpResponse.json([])),
  http.post("/api/v1/keys", async ({ request }) => {
    const body = (await request.json().catch(() => ({}))) as { name?: string; namespace?: string };
    created.push(body);
    return HttpResponse.json({ id: "k1", prefix: "nrvq_ab", key: "nrvq_ab.secret", name: body.name, namespace: body.namespace, role: "viewer" });
  })
);
beforeAll(() => server.listen());
beforeEach(() => {
  mockApp.namespace = "default";
  created = [];
});
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter>
      <APIKeys />
    </MemoryRouter>
  );
}

describe("APIKeys — all-namespace scope guard", () => {
  // FAIL-ON-BUG: on the pre-fix code the button stays enabled and clicking POSTs {namespace:"all"} —
  // binding the key to a phantom tenant. The guard must block the create and prompt for a concrete ns.
  it("under All-namespaces (aggregate) the create is disabled, prompts for a concrete ns, and never POSTs namespace:all", async () => {
    mockApp.namespace = "all";
    renderPage();

    fireEvent.change(screen.getByPlaceholderText("key name"), { target: { value: "ci-runner" } });

    const btn = screen.getByRole("button", { name: /Create key/i });
    expect(btn).toBeDisabled();
    expect(screen.getByTestId("apikey-scope-prompt")).toBeInTheDocument();

    // Even if the click somehow fires, no key may be issued under the aggregate scope.
    fireEvent.click(btn);
    await new Promise((r) => setTimeout(r, 0));
    expect(created).toHaveLength(0);
  });

  it("under a concrete namespace the create is enabled and POSTs that namespace", async () => {
    mockApp.namespace = "payments";
    renderPage();

    fireEvent.change(screen.getByPlaceholderText("key name"), { target: { value: "ci-runner" } });
    const btn = screen.getByRole("button", { name: /Create key/i });
    expect(btn).not.toBeDisabled();
    expect(screen.queryByTestId("apikey-scope-prompt")).not.toBeInTheDocument();

    fireEvent.click(btn);
    await waitFor(() => expect(created).toHaveLength(1));
    expect(created[0].namespace).toBe("payments");
  });
});
