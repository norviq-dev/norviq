// SPDX-License-Identifier: Apache-2.0
// A dry-run that fails to evaluate MUST surface a degraded/error state — NEVER a fabricated
// all-zero "safe" preview. The pre-fix catch swallowed the failure and set a zeroed DryRunResult
// ({ total_records_checked: 0, would_block: 0, would_allow: 0, ... }), which the renderer painted as a
// GREEN "0 currently-allowed calls would be newly blocked · would block 0, allow 0" — indistinguishable
// from a genuinely validated zero-impact result. This test drives the error path and asserts the operator
// sees an explicit error, not a fake zero-impact preview.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { PolicyCatalog } from "./PolicyCatalog";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";

// A functional Monaco stub: a textarea that forwards edits so the editor's regoDraft is a real,
// non-empty buffer (the repro requires a non-empty regoDraft with dryRunRego still null).
vi.mock("@monaco-editor/react", () => ({
  default: ({ value, onChange }: { value?: string; onChange?: (v: string) => void }) => (
    <textarea data-testid="monaco-editor" value={value} onChange={(e) => onChange?.(e.target.value)} />
  )
}));

const LOADED_REGO = "package norviq.strict\ndefault decision = \"allow\"\n";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

function seedLoadedPolicy() {
  server.use(
    http.get("/api/v1/policies", () =>
      HttpResponse.json([{ namespace: "default", agent_class: "customer-support", target_type: "class", current_version: 1, rego_length: LOADED_REGO.length, priority: 700 }])
    ),
    http.get("/api/v1/deployments", () => HttpResponse.json([])),
    http.get("/api/v1/threats/intent-drafts", () => HttpResponse.json({ drafts: [], total: 0, returned: 0, offset: 0, limit: 15 })),
    http.get("/api/v1/policies/default/customer-support", () =>
      HttpResponse.json({ namespace: "default", agent_class: "customer-support", rego_source: LOADED_REGO, version: 1 })
    ),
    http.get("/api/v1/policies/default/customer-support/versions", () => HttpResponse.json([]))
  );
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <AppProvider>
        <PolicyCatalog />
      </AppProvider>
    </MemoryRouter>
  );
}

async function loadEditorAndDryRun() {
  renderPage();
  // Wait for the editor to seed the loaded policy source (non-empty regoDraft, dryRunRego still null).
  await waitFor(() =>
    expect((screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value).toContain("norviq.strict")
  );
  fireEvent.click(screen.getByRole("button", { name: /^dry-run$/i }));
}

describe("PolicyCatalog dry-run failure", () => {
  it("renders an explicit error — NOT a green all-zero 'safe' preview — when the dry-run API fails", async () => {
    seedLoadedPolicy();
    // The dry-run engine call fails (e.g. 503 / engine unreachable).
    server.use(http.post("/api/v1/policies/dry-run", () => new HttpResponse("engine unavailable", { status: 503 })));

    await loadEditorAndDryRun();

    // The degraded/error banner appears. (Pre-fix: this testid never existed — the catch fabricated a
    // zeroed DryRunResult instead, so this findBy would time out and the test would FAIL.)
    const errorBanner = await screen.findByTestId("dryrun-error");
    expect(errorBanner).toHaveTextContent(/could not evaluate/i);
    // And it is styled as an error, not the green allow/success color.
    expect(errorBanner.style.color).toContain("--block");

    // The fabricated zero-impact preview must NOT be shown: no "Dry-Run Results" panel, no green
    // "newly blocked" flip line, no "would block 0, allow 0", no fake recommendation.
    expect(screen.queryByText(/dry-run results/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/would be.*newly blocked/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/would block 0, allow 0/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/unable to evaluate right now/i)).not.toBeInTheDocument();
  });

  it("a SUCCESSFUL dry-run with genuinely zero impact still shows the zero-impact preview (error path is distinct)", async () => {
    // The distinction the fix protects: a REAL zero-impact result is a valid, honest preview and must
    // still render — only a swallowed FAILURE is suppressed. This guards against over-correcting.
    seedLoadedPolicy();
    server.use(
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({ total_records_checked: 42, would_block: 0, would_allow: 42, newly_blocked: 0, newly_allowed: 0, block_rate_pct: 0, recommendation: "No decision flips — safe to apply." })
      )
    );

    await loadEditorAndDryRun();

    // The genuine result renders; no error banner.
    expect(await screen.findByText(/dry-run results/i)).toBeInTheDocument();
    expect(screen.getByText(/No decision flips — safe to apply\./i)).toBeInTheDocument();
    expect(screen.queryByTestId("dryrun-error")).not.toBeInTheDocument();
  });
});
