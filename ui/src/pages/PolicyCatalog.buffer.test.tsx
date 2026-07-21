// SPDX-License-Identifier: Apache-2.0
// The editor buffer must reset to the LOADED policy's source on every file switch — even when
// two policies have byte-identical rego (all seeded classes share one canonical policy). The old reset
// effect keyed on `editorPolicy?.id` (always undefined — the list API returns no id) plus the raw rego
// string, so switching between identical-source policies never re-fired: policy A's unsaved edits
// silently became policy B's buffer, one Save from overwriting a live enforcing policy.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { PolicyCatalog } from "./PolicyCatalog";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";

// A functional Monaco stub: a textarea that forwards edits through onChange, so we can drive the
// editor's DIRTY state exactly as a user typing would.
vi.mock("@monaco-editor/react", () => ({
  default: ({ value, onChange }: { value?: string; onChange?: (v: string) => void }) => (
    <textarea data-testid="monaco-editor" value={value} onChange={(e) => onChange?.(e.target.value)} />
  )
}));

const IDENTICAL_REGO = "package norviq.strict\n# canonical\ndefault decision = \"allow\"\n";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

function seedTwoIdenticalPolicies() {
  const mk = (cls: string) => ({
    namespace: "default",
    agent_class: cls,
    target: cls,
    target_type: "class",
    current_version: 1,
    rego_length: IDENTICAL_REGO.length,
    priority: 700
  });
  server.use(
    http.get("/api/v1/policies", () => HttpResponse.json([mk("alpha-bot"), mk("beta-bot")])),
    http.get("/api/v1/deployments", () => HttpResponse.json([])),
    http.get("/api/v1/threats/intent-drafts", () => HttpResponse.json({ drafts: [], total: 0, returned: 0, offset: 0, limit: 15 })),
    // BOTH policies return the SAME rego_source — the key of the original bug.
    http.get("/api/v1/policies/default/:cls", ({ params }) =>
      HttpResponse.json({ namespace: "default", agent_class: params.cls, rego_source: IDENTICAL_REGO, version: 1 })
    ),
    http.get("/api/v1/policies/default/:cls/versions", () => HttpResponse.json([]))
  );
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={["/policies/catalog"]}>
      <AppProvider>
        <PolicyCatalog />
      </AppProvider>
    </MemoryRouter>
  );
}

function betaRowEl(): HTMLElement {
  const el = screen.getAllByText("beta-bot.rego").find((e) => e.closest("[role=row]"));
  return el!.closest("[role=row]") as HTMLElement;
}

describe("PolicyCatalog editor buffer isolation", () => {
  it("switching to an identical-source policy discards the prior edit (buffer is not contaminated)", async () => {
    seedTwoIdenticalPolicies();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    renderPage();

    await screen.findAllByText("alpha-bot.rego");
    // Wait for the detail fetch to seed the buffer (else the reset effect fires AFTER our edit and
    // clears the dirty flag — a test race, not a product bug).
    await waitFor(() =>
      expect((screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value).toContain("canonical")
    );
    const editor = screen.getByTestId("monaco-editor") as HTMLTextAreaElement;

    // Author edits alpha-bot — buffer is now DIRTY and contains a marker string.
    fireEvent.change(editor, { target: { value: IDENTICAL_REGO + "# EDIT-ALPHA-ONLY\n" } });
    expect((screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value).toContain("EDIT-ALPHA-ONLY");

    // Switch to beta-bot (identical canonical source). Pre-fix: the reset never re-fired (undefined id +
    // identical rego string) so alpha's edit bled into beta. Post-fix: beta loads its own clean source.
    fireEvent.click(betaRowEl());
    await waitFor(() => {
      const val = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(val).not.toContain("EDIT-ALPHA-ONLY");
      expect(val).toContain("canonical");
    });
    // The editor header now names beta-bot (matches the highlighted sidebar row).
    expect(screen.getAllByText("beta-bot.rego").length).toBeGreaterThanOrEqual(2);
    confirmSpy.mockRestore();
  });

  it("prompts before discarding unsaved edits, and staying (cancel) keeps the edit + the same policy", async () => {
    seedTwoIdenticalPolicies();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false); // user chooses to STAY
    renderPage();
    await screen.findAllByText("alpha-bot.rego");
    await waitFor(() =>
      expect((screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value).toContain("canonical")
    );
    const editor = screen.getByTestId("monaco-editor") as HTMLTextAreaElement;
    fireEvent.change(editor, { target: { value: IDENTICAL_REGO + "# UNSAVED\n" } });

    // Attempt to switch away with a dirty buffer → the guard prompts, user cancels → no switch.
    fireEvent.click(betaRowEl());
    expect(confirmSpy).toHaveBeenCalledTimes(1);
    // Still on alpha with the edit intact (switch was aborted).
    expect((screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value).toContain("UNSAVED");
    confirmSpy.mockRestore();
  });

  it("does NOT prompt when the buffer is clean (no false 'discard changes' dialog)", async () => {
    seedTwoIdenticalPolicies();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    renderPage();
    await screen.findAllByText("alpha-bot.rego");
    fireEvent.click(betaRowEl());
    expect(confirmSpy).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });
});
