// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// BuilderSheet — render, add a rule, watch the live compiled-rego preview update, and the two safety
// gates: Run dry-run is disabled while the graph has compile errors, and Save & enforce is disabled
// until a VALID dry-run of the CURRENT graph state has completed (recompile invalidates it — see
// builderCompile.ts / BuilderSheet.tsx's `dryRunStale` doctrine, same pattern as PolicyCatalog's raw
// editor). Follows PolicyCatalog.dryrun.test.tsx's msw + monaco-stub convention.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { BuilderSheet } from "./BuilderSheet";

// A minimal Monaco stub: a read-only textarea that mirrors `value`, so the compiled rego preview is
// inspectable without pulling in the real editor.
vi.mock("@monaco-editor/react", () => ({
  default: ({ value }: { value?: string }) => <textarea data-testid="monaco-editor" readOnly value={value} />
}));

const server = setupServer(http.get("/api/v1/agents", () => HttpResponse.json([])));
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderSheet() {
  return render(<BuilderSheet namespace="default" onClose={() => {}} />);
}

/** Scope + one rule with a reason (auto-fills rule_id) + one detector condition — a fully valid graph. */
function buildValidRule() {
  fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });
  fireEvent.click(screen.getByTestId("builder-add-rule"));
  fireEvent.change(screen.getByTestId("builder-rule-reason-0"), { target: { value: "SQL injection blocked" } });
  fireEvent.click(screen.getByTestId("builder-add-condition-0-0")); // default condition = detector/sql_injection, already valid
}

describe("BuilderSheet", () => {
  it("renders the scope field and an empty rule rail", () => {
    renderSheet();
    expect(screen.getByTestId("builder-sheet")).toBeInTheDocument();
    expect(screen.getByTestId("builder-agent-class")).toBeInTheDocument();
    expect(screen.getByText(/no rules yet/i)).toBeInTheDocument();
    // Dry-run/Save start disabled — no scope, no rules.
    expect(screen.getByTestId("builder-dryrun-btn")).toBeDisabled();
    expect(screen.getByTestId("builder-save-btn")).toBeDisabled();
  });

  it("adding a rule renders a rule card, and filling it out updates the LIVE compiled rego preview", async () => {
    renderSheet();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });
    fireEvent.click(screen.getByTestId("builder-add-rule"));
    expect(screen.getByTestId("builder-rule-0")).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("builder-rule-reason-0"), { target: { value: "SQL injection blocked" } });
    fireEvent.click(screen.getByTestId("builder-add-condition-0-0"));

    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain("package norviq.custom.builder_spike");
      // rule_id auto-slugged from the reason text (untouched rule_id field).
      expect(rego).toContain('blocks["sql_injection_blocked"]');
      expect(rego).toContain('"sql_injection_blocked": "SQL injection blocked"');
    });
    // A fully-formed rule has no compile errors.
    expect(screen.queryByTestId("builder-errors")).not.toBeInTheDocument();
  });

  it("disables Run dry-run while the graph has compile errors (an incomplete rule)", () => {
    renderSheet();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });
    fireEvent.click(screen.getByTestId("builder-add-rule")); // empty rule_id/reason/conditions -> compile errors
    expect(screen.getByTestId("builder-errors")).toBeInTheDocument();
    expect(screen.getByTestId("builder-dryrun-btn")).toBeDisabled();
    expect(screen.getByTestId("builder-save-btn")).toBeDisabled();
  });

  it("disables Save & enforce until a VALID dry-run of the current graph has completed", async () => {
    server.use(
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({
          valid: true,
          errors: [],
          total_records_checked: 5,
          would_block: 1,
          would_allow: 4,
          would_escalate: 0,
          newly_blocked: 1,
          newly_allowed: 0,
          newly_blocked_samples: [{ tool_name: "execute_sql", was: "allow", now: "block", rule_id: "sql_injection_blocked" }],
          recommendation: "Would NEWLY block 1 of 5 recent calls (20.0%) — review the flips before deploying."
        })
      )
    );

    renderSheet();
    buildValidRule();

    await waitFor(() => expect(screen.getByTestId("builder-dryrun-btn")).not.toBeDisabled());
    // No dry-run has run yet against this graph -> Save stays gated.
    expect(screen.getByTestId("builder-save-btn")).toBeDisabled();

    fireEvent.click(screen.getByTestId("builder-dryrun-btn"));

    await waitFor(() => expect(screen.getByTestId("builder-dryrun-result")).toBeInTheDocument());
    expect(screen.getByText(/would newly block 1 of 5/i)).toBeInTheDocument();
    // A VALID dry-run of the exact current graph -> Save unlocks.
    await waitFor(() => expect(screen.getByTestId("builder-save-btn")).not.toBeDisabled());
  });

  it("re-locks Save after the graph changes post-dry-run (staleness), even though the earlier dry-run was valid", async () => {
    server.use(
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({ valid: true, errors: [], total_records_checked: 0, newly_blocked: 0, recommendation: "n/a" })
      )
    );
    renderSheet();
    buildValidRule();
    await waitFor(() => expect(screen.getByTestId("builder-dryrun-btn")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("builder-dryrun-btn"));
    await waitFor(() => expect(screen.getByTestId("builder-save-btn")).not.toBeDisabled());

    // Edit the reason (and thus the compiled rego) after the dry-run — Save must re-lock.
    fireEvent.change(screen.getByTestId("builder-rule-reason-0"), { target: { value: "SQL injection blocked v2" } });
    expect(screen.getByTestId("builder-save-btn")).toBeDisabled();
  });
});

// --- unsaved-changes guard (round B fix 3): overlay click, Cancel, and the X button all funnel
// through the same `requestClose` gate — a dirty graph (some class typed or a rule added) requires an
// explicit window.confirm before the sheet actually closes; a pristine sheet or one just saved does not. ---
describe("BuilderSheet — unsaved-changes guard on close", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("guards the X button with window.confirm when dirty, and only closes once confirmed", () => {
    const confirmSpy = vi.spyOn(window, "confirm");
    const onClose = vi.fn();
    render(<BuilderSheet namespace="default" onClose={onClose} />);
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });

    confirmSpy.mockReturnValueOnce(false);
    fireEvent.click(screen.getByTestId("builder-close"));
    expect(confirmSpy).toHaveBeenLastCalledWith("Discard this unsaved policy?");
    expect(onClose).not.toHaveBeenCalled();

    confirmSpy.mockReturnValueOnce(true);
    fireEvent.click(screen.getByTestId("builder-close"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("guards the Cancel button with window.confirm when dirty (via a rule, not a class), and only closes once confirmed", () => {
    const confirmSpy = vi.spyOn(window, "confirm");
    const onClose = vi.fn();
    render(<BuilderSheet namespace="default" onClose={onClose} />);
    fireEvent.click(screen.getByTestId("builder-add-rule")); // dirty via a rule, not a class this time

    confirmSpy.mockReturnValueOnce(false);
    fireEvent.click(screen.getByText("Cancel"));
    expect(onClose).not.toHaveBeenCalled();

    confirmSpy.mockReturnValueOnce(true);
    fireEvent.click(screen.getByText("Cancel"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("guards the overlay click with window.confirm when dirty, and only closes once confirmed", () => {
    const confirmSpy = vi.spyOn(window, "confirm");
    const onClose = vi.fn();
    const { container } = render(<BuilderSheet namespace="default" onClose={onClose} />);
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });
    const overlay = container.querySelector(".sheet-overlay") as HTMLElement;

    confirmSpy.mockReturnValueOnce(false);
    fireEvent.click(overlay);
    expect(onClose).not.toHaveBeenCalled();

    confirmSpy.mockReturnValueOnce(true);
    fireEvent.click(overlay);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does NOT call window.confirm when closing a pristine sheet (no class, no rules)", () => {
    const confirmSpy = vi.spyOn(window, "confirm");
    const onClose = vi.fn();
    render(<BuilderSheet namespace="default" onClose={onClose} />);

    fireEvent.click(screen.getByTestId("builder-close"));
    expect(confirmSpy).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("does NOT prompt after a successful Save & enforce, even though the sheet still has a class + a rule", async () => {
    server.use(
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({ valid: true, errors: [], total_records_checked: 0, newly_blocked: 0, recommendation: "n/a" })
      ),
      http.post("/api/v1/policies", () => HttpResponse.json({ version: 1 })),
      // verifyPolicyApplied's convergence poll — resolve on the very first tick so no timers linger.
      http.get("/api/v1/policies", () =>
        HttpResponse.json([{ namespace: "default", agent_class: "builder-spike", current_version: 1, enforcement_mode: "block" }])
      )
    );
    const confirmSpy = vi.spyOn(window, "confirm");
    const onClose = vi.fn();
    render(<BuilderSheet namespace="default" onClose={onClose} />);
    buildValidRule();

    await waitFor(() => expect(screen.getByTestId("builder-dryrun-btn")).not.toBeDisabled());
    fireEvent.click(screen.getByTestId("builder-dryrun-btn"));
    await waitFor(() => expect(screen.getByTestId("builder-save-btn")).not.toBeDisabled());

    fireEvent.click(screen.getByTestId("builder-save-btn"));
    // The save round-trip completed once the button stops reading "Saving...".
    await waitFor(() => expect(screen.getByTestId("builder-save-btn")).toHaveTextContent("Save & enforce"));

    // Sheet still has a class + a rule (nothing was cleared) — pre-fix-3 this would still prompt.
    expect(screen.getByTestId("builder-agent-class")).toHaveValue("builder-spike");
    fireEvent.click(screen.getByTestId("builder-close"));
    expect(confirmSpy).not.toHaveBeenCalled();
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

// --- editor expand/collapse (round B fix 4) ---
describe("BuilderSheet — compiled-rego editor expand/collapse", () => {
  it("toggles the editor between the compact and expanded height, and reflects state on the toggle + container", () => {
    renderSheet();
    const toggle = screen.getByTestId("builder-editor-expand-toggle");
    const editorContainer = screen.getByTestId("builder-editor-container");

    expect(toggle).toHaveAttribute("data-expanded", "false");
    expect(editorContainer).toHaveAttribute("data-expanded", "false");
    expect(editorContainer.style.height).toBe("260px");

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("data-expanded", "true");
    expect(editorContainer).toHaveAttribute("data-expanded", "true");
    expect(editorContainer.style.height).toBe("560px");

    // The stats row below the editor is unaffected by the toggle (still present, unchanged testid).
    expect(screen.getByTestId("builder-stats")).toBeInTheDocument();

    fireEvent.click(toggle);
    expect(toggle).toHaveAttribute("data-expanded", "false");
    expect(editorContainer.style.height).toBe("260px");
  });
});

// --- Phase 2b: sourceVerb / paramRegex / NOT condition types -------------------------------------
describe("BuilderSheet — Phase 2b condition types (sourceVerb / paramRegex / NOT)", () => {
  it("configures a sourceVerb condition (source then verb dropdowns) and reflects it live in the compiled rego", async () => {
    renderSheet();
    buildValidRule(); // scope + rule 0 + reason + condition 0 (default: detector/sql_injection)

    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-type"), { target: { value: "sourceVerb" } });

    await waitFor(() => {
      expect(screen.getByTestId("builder-cond-0-0-0-source")).toBeInTheDocument();
      expect(screen.getByTestId("builder-cond-0-0-0-verb")).toBeInTheDocument();
    });

    // Default (source,verb) picked by defaultConditionFor is the first entry of the capability mirror
    // (elasticsearch/read) — it shows up in the live compiled preview immediately, no extra input needed.
    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain("bld_srcverb_elasticsearch_read");
    });
    expect(screen.queryByTestId("builder-errors")).not.toBeInTheDocument();

    // Switching source to postgresql and verb to delete updates the compiled predicate reference.
    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-source"), { target: { value: "postgresql" } });
    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-verb"), { target: { value: "delete" } });

    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain("bld_srcverb_postgresql_delete");
      expect(rego).not.toContain("bld_srcverb_elasticsearch_read");
    });
  });

  it("filters the verb dropdown to what the chosen source supports (egress sources expose only 'send')", async () => {
    renderSheet();
    buildValidRule();
    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-type"), { target: { value: "sourceVerb" } });
    await waitFor(() => expect(screen.getByTestId("builder-cond-0-0-0-source")).toBeInTheDocument());

    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-source"), { target: { value: "webhook" } });

    const verbSelect = screen.getByTestId("builder-cond-0-0-0-verb") as HTMLSelectElement;
    const options = Array.from(verbSelect.options).map((o) => o.value);
    expect(options).toEqual(["send"]);

    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain("bld_srcverb_webhook_send");
    });
  });

  it("a paramRegex condition with an invalid pattern shows the inline hint and blocks dry-run/save via the existing compile-error gate", async () => {
    renderSheet();
    buildValidRule();

    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-type"), { target: { value: "paramRegex" } });
    await waitFor(() => expect(screen.getByTestId("builder-cond-0-0-0-field")).toBeInTheDocument());

    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-field"), { target: { value: "query" } });
    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-pattern"), { target: { value: "(unclosed" } });

    await waitFor(() => expect(screen.getByTestId("builder-cond-0-0-0-pattern-invalid")).toBeInTheDocument());
    expect(screen.getByTestId("builder-errors")).toBeInTheDocument();
    expect(screen.getByTestId("builder-dryrun-btn")).toBeDisabled();
    expect(screen.getByTestId("builder-save-btn")).toBeDisabled();

    // Fixing the pattern clears both the inline hint and the compile-error gate.
    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-pattern"), { target: { value: "^SELECT" } });
    await waitFor(() => expect(screen.queryByTestId("builder-cond-0-0-0-pattern-invalid")).not.toBeInTheDocument());
    expect(screen.queryByTestId("builder-errors")).not.toBeInTheDocument();

    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain('regex.match("^SELECT", val)');
    });
  });

  it("the NOT toggle wraps a condition and the compiled preview gains a `not ` prefix (and unwraps back on a second click)", async () => {
    renderSheet();
    buildValidRule(); // condition 0 = detector/sql_injection

    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain("bld_sql_injection");
      expect(rego).not.toContain("not bld_sql_injection");
    });
    expect(screen.getByTestId("builder-cond-0-0-0-not-toggle")).toHaveAttribute("aria-pressed", "false");

    fireEvent.click(screen.getByTestId("builder-cond-0-0-0-not-toggle"));

    expect(screen.getByTestId("builder-cond-0-0-0-not-toggle")).toHaveAttribute("aria-pressed", "true");
    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain("not bld_sql_injection");
    });
    // Toggling NOT does not itself introduce a compile error — the wrapped condition is still valid.
    expect(screen.queryByTestId("builder-errors")).not.toBeInTheDocument();

    // A second click unwraps it again.
    fireEvent.click(screen.getByTestId("builder-cond-0-0-0-not-toggle"));
    expect(screen.getByTestId("builder-cond-0-0-0-not-toggle")).toHaveAttribute("aria-pressed", "false");
    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).not.toContain("not bld_sql_injection");
      expect(rego).toContain("bld_sql_injection");
    });
  });
});

// --- per-instance rule-id generator (round B fix 1): a useRef inside the component, not module-level
// mutable state, so a remount starts fresh and two independently mounted sheets never share a counter. ---
describe("BuilderSheet — per-instance rule id generator (no cross-sheet collision)", () => {
  function ruleInternalIds(container: HTMLElement): string[] {
    return Array.from(container.querySelectorAll("[data-rule-internal-id]")).map(
      (el) => el.getAttribute("data-rule-internal-id") as string
    );
  }

  it("assigns unique, non-colliding ids to multiple rules within one sheet", () => {
    const { container } = render(<BuilderSheet namespace="default" onClose={() => {}} />);
    fireEvent.click(within(container).getByTestId("builder-add-rule"));
    fireEvent.click(within(container).getByTestId("builder-add-rule"));
    fireEvent.click(within(container).getByTestId("builder-add-rule"));
    const ids = ruleInternalIds(container);
    expect(ids).toHaveLength(3);
    expect(new Set(ids).size).toBe(3);
  });

  it("a remounted sheet starts its rule-id sequence fresh, not continuing a prior mount's count", () => {
    const first = render(<BuilderSheet namespace="default" onClose={() => {}} />);
    fireEvent.click(within(first.container).getByTestId("builder-add-rule"));
    fireEvent.click(within(first.container).getByTestId("builder-add-rule"));
    fireEvent.click(within(first.container).getByTestId("builder-add-rule"));
    const firstIds = ruleInternalIds(first.container);
    expect(firstIds[firstIds.length - 1]).toMatch(/_3$/); // third rule added -> sequence at 3
    first.unmount();

    const second = render(<BuilderSheet namespace="default" onClose={() => {}} />);
    fireEvent.click(within(second.container).getByTestId("builder-add-rule"));
    const secondIds = ruleInternalIds(second.container);
    // A module-level counter would carry over to _4 here; a fresh per-instance ref starts back at _1.
    expect(secondIds[0]).toMatch(/_1$/);
  });

  it("two simultaneously mounted sheets never collide or share a counter", () => {
    const sheetA = render(<BuilderSheet namespace="default" onClose={() => {}} />);
    const sheetB = render(<BuilderSheet namespace="default" onClose={() => {}} />);

    // Sheet A adds two rules first.
    fireEvent.click(within(sheetA.container).getByTestId("builder-add-rule"));
    fireEvent.click(within(sheetA.container).getByTestId("builder-add-rule"));
    // Sheet B, mounted independently, adds one rule — it must NOT have been bumped to _3 by A's activity.
    fireEvent.click(within(sheetB.container).getByTestId("builder-add-rule"));

    const aIds = ruleInternalIds(sheetA.container);
    const bIds = ruleInternalIds(sheetB.container);
    expect(aIds).toHaveLength(2);
    expect(bIds).toHaveLength(1);
    expect(bIds[0]).toMatch(/_1$/); // sheet B's own first rule, unaffected by sheet A's counter
    // No id collides across the two independently-keyed sheets.
    expect(new Set([...aIds, ...bIds]).size).toBe(3);

    sheetA.unmount();
    sheetB.unmount();
  });
});

// --- Phase 2c: Intent Allowlist mode --------------------------------------------------------------
describe("BuilderSheet — Intent Allowlist mode (Phase 2c)", () => {
  it("defaults to Tighten-only rules mode, and toggling to Intent allowlist hides the rules rail and shows the allowlist editor", async () => {
    renderSheet();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });

    // Starts in rules mode: the rules rail (Add rule button) is present, the allowlist editor is not.
    expect(screen.getByTestId("builder-mode-rules")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("builder-mode-allowlist")).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByTestId("builder-add-rule")).toBeInTheDocument();
    expect(screen.queryByTestId("builder-allowlist-tools")).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId("builder-mode-allowlist"));

    expect(screen.getByTestId("builder-mode-allowlist")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("builder-mode-rules")).toHaveAttribute("aria-pressed", "false");
    // Rules rail (and the Add rule button, and the Defaults section) is gone.
    expect(screen.queryByTestId("builder-add-rule")).not.toBeInTheDocument();
    expect(screen.queryByTestId("builder-defaults-decision")).not.toBeInTheDocument();
    // The allowlist editor is shown instead.
    expect(screen.getByTestId("builder-allowlist-tools")).toBeInTheDocument();
    expect(screen.getByTestId("builder-allowlist-refinement-readonly")).toBeInTheDocument();
    expect(screen.getByTestId("builder-allowlist-refinement-egress")).toBeInTheDocument();
    expect(screen.getByTestId("builder-allowlist-refinement-scope")).toBeInTheDocument();
    expect(screen.getByTestId("builder-allowlist-refinement-rate")).toBeInTheDocument();

    // An empty tool list warns (denies everything for the class).
    expect(screen.getByTestId("builder-allowlist-empty-warning")).toBeInTheDocument();

    // Compiled preview reflects the default-deny allowlist shape immediately.
    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain("package norviq.intent.builder_spike");
      expect(rego).toContain('default decision = "block"');
      expect(rego).toContain('default rule_id = "intent_default_deny"');
    });

    // Toggling back to rules mode restores the rules rail and hides the allowlist editor again.
    fireEvent.click(screen.getByTestId("builder-mode-rules"));
    expect(screen.getByTestId("builder-add-rule")).toBeInTheDocument();
    expect(screen.queryByTestId("builder-allowlist-tools")).not.toBeInTheDocument();
  });

  it("adding a tool updates the compiled preview to contain that tool (lower-cased) in allow_names, and the empty-allowlist warning clears", async () => {
    renderSheet();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });
    fireEvent.click(screen.getByTestId("builder-mode-allowlist"));
    expect(screen.getByTestId("builder-allowlist-empty-warning")).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("builder-allowlist-tool-input"), { target: { value: "Search_Docs" } });
    fireEvent.click(screen.getByTestId("builder-allowlist-tool-add"));

    expect(screen.getByTestId("builder-allowlist-tool-chip-Search_Docs")).toBeInTheDocument();
    // The warning clears once at least one tool is listed.
    expect(screen.queryByTestId("builder-allowlist-empty-warning")).not.toBeInTheDocument();
    // The input clears after adding, ready for the next tool.
    expect(screen.getByTestId("builder-allowlist-tool-input")).toHaveValue("");

    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain('allow_names = {"search_docs"}');
    });

    // Removing the tool via its chip's remove button brings the empty-allowlist warning back.
    fireEvent.click(screen.getByTestId("builder-allowlist-tool-remove-Search_Docs"));
    expect(screen.queryByTestId("builder-allowlist-tool-chip-Search_Docs")).not.toBeInTheDocument();
    expect(screen.getByTestId("builder-allowlist-empty-warning")).toBeInTheDocument();
  });

  it("pressing Enter in the tool input also adds the tool (not just the Add button)", async () => {
    renderSheet();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });
    fireEvent.click(screen.getByTestId("builder-mode-allowlist"));

    fireEvent.change(screen.getByTestId("builder-allowlist-tool-input"), { target: { value: "get_order" } });
    fireEvent.keyDown(screen.getByTestId("builder-allowlist-tool-input"), { key: "Enter" });

    expect(screen.getByTestId("builder-allowlist-tool-chip-get_order")).toBeInTheDocument();
  });

  it("toggling a refinement checkbox adds its guard (and helper vocabulary) into the compiled preview", async () => {
    renderSheet();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });
    fireEvent.click(screen.getByTestId("builder-mode-allowlist"));
    fireEvent.change(screen.getByTestId("builder-allowlist-tool-input"), { target: { value: "search_docs" } });
    fireEvent.click(screen.getByTestId("builder-allowlist-tool-add"));

    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).not.toContain("is_read");
      expect(rego).not.toContain("read_verbs");
    });

    const readonlyCheckbox = screen.getByTestId("builder-allowlist-refinement-readonly") as HTMLInputElement;
    expect(readonlyCheckbox.checked).toBe(false);
    fireEvent.click(readonlyCheckbox);
    expect(readonlyCheckbox.checked).toBe(true);

    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain("read_verbs = {");
      expect(rego).toContain("is_read { read_verbs[tool_verb] }");
      expect(rego).toContain("    is_read");
    });

    // Unchecking removes the guard again.
    fireEvent.click(readonlyCheckbox);
    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).not.toContain("is_read");
    });
  });

  it("switching modes preserves each mode's own state (rules survive a round trip through allowlist mode, and vice versa)", async () => {
    renderSheet();
    buildValidRule(); // scope + rule 0 (detector/sql_injection) in rules mode

    fireEvent.click(screen.getByTestId("builder-mode-allowlist"));
    fireEvent.change(screen.getByTestId("builder-allowlist-tool-input"), { target: { value: "search_docs" } });
    fireEvent.click(screen.getByTestId("builder-allowlist-tool-add"));

    fireEvent.click(screen.getByTestId("builder-mode-rules"));
    // The rule added before switching to allowlist mode is still there, untouched.
    expect(screen.getByTestId("builder-rule-0")).toBeInTheDocument();
    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain('blocks["sql_injection_blocked"]');
    });

    // Switching back to allowlist mode, the tool added earlier is still there too.
    fireEvent.click(screen.getByTestId("builder-mode-allowlist"));
    expect(screen.getByTestId("builder-allowlist-tool-chip-search_docs")).toBeInTheDocument();
  });
});

// --- Phase 2f: de-jargoned condition-type dropdown --------------------------------------------------
// The React Flow canvas builder is gone (Phase 2f consolidation) — this form-based sheet is
// now the ONLY visual builder, so its dropdown vocabulary can move from wire-ish jargon
// ("detector"/"tool in"/"source verb") to operator language, grouped by category.
describe("BuilderSheet — de-jargoned condition-type dropdown (Phase 2f)", () => {
  it("renders operator-language labels (not the old wire-name jargon), grouped into Content/Tool/Trust optgroups", () => {
    renderSheet();
    buildValidRule();

    const typeSelect = screen.getByTestId("builder-cond-0-0-0-type") as HTMLSelectElement;
    const optionTexts = Array.from(typeSelect.options).map((o) => o.text);
    expect(optionTexts).toEqual([
      "Content detector (injection / PII / secrets / destructive tool)",
      "Keyword in tool params",
      "Param matches regex",
      "Tool name is one of",
      "Source + verb (capability)",
      "Agent trust below"
    ]);
    // None of the old bare jargon values are still on screen as visible text.
    expect(screen.queryByText(/^detector$/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^tool in$/)).not.toBeInTheDocument();
    expect(screen.queryByText(/^source verb$/)).not.toBeInTheDocument();

    const groupLabels = Array.from(typeSelect.querySelectorAll("optgroup")).map((g) => g.getAttribute("label"));
    expect(groupLabels).toEqual(["Content", "Tool", "Trust"]);
  });

  it("shows a one-line hint near the dropdown for whichever type is currently selected, and it updates on type change", () => {
    renderSheet();
    buildValidRule(); // condition 0 defaults to type=detector

    expect(screen.getByTestId("builder-cond-0-0-0-hint")).toHaveTextContent(/built-in content scanner/i);

    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-type"), { target: { value: "toolIn" } });
    expect(screen.getByTestId("builder-cond-0-0-0-hint")).toHaveTextContent(/exactly matches one of the names/i);
  });
});

// --- Phase 2f: namespace honesty ---------------------------------------------------------------------
// PolicyCatalog no longer silently resolves the global "All namespaces" selector to "default" before
// handing it to BuilderSheet — it passes the raw value through, and BuilderSheet itself must gate Save
// (and Dry-Run, which also POSTs a namespace) behind an explicit, concrete choice.
describe("BuilderSheet — namespace honesty (Phase 2f)", () => {
  it("gates Dry-Run/Save on a concrete target namespace when the caller passes 'all', and always shows the create-target summary", () => {
    render(<BuilderSheet namespace="all" onClose={() => {}} />);

    // Nothing chosen yet — the summary sentence is ALWAYS rendered, even with nothing filled in, and the
    // required-namespace prompt is visible because the global scope was "All namespaces". The plain-
    // English sentence reads as "incomplete" until scope + namespace are both set; the muted small-text
    // line beneath it still shows the (dash) loader key — the honesty guarantee, preserved verbatim.
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent(/Pick who this policy is for to continue/i);
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent(/creates\s*—\s*\/\s*—/);
    expect(screen.getByTestId("builder-namespace-required-warning")).toBeInTheDocument();
    expect(screen.getByTestId("builder-target-namespace")).toHaveValue("");

    buildValidRule(); // a fully valid rule + agent class — everything BUT a namespace
    expect(screen.getByTestId("builder-dryrun-btn")).toBeDisabled();
    expect(screen.getByTestId("builder-save-btn")).toBeDisabled();

    // Picking a concrete namespace clears the gate and the prompt, and the sentence reflects it.
    fireEvent.change(screen.getByTestId("builder-target-namespace"), { target: { value: "default" } });
    expect(screen.queryByTestId("builder-namespace-required-warning")).not.toBeInTheDocument();
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent(
      "Applies to every `builder-spike` agent in namespace `default`."
    );
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent("creates default / builder-spike");
    expect(screen.getByTestId("builder-dryrun-btn")).not.toBeDisabled();
  });

  it("pre-fills (but keeps editable) the target namespace when the caller passes an already-concrete namespace, and does not gate on it", () => {
    renderSheet(); // namespace="default"
    expect(screen.getByTestId("builder-target-namespace")).toHaveValue("default");
    expect(screen.queryByTestId("builder-namespace-required-warning")).not.toBeInTheDocument();
    // Agent class still empty -> scope isn't complete yet, so the sentence reads as incomplete, but the
    // muted key line already shows the concrete namespace (honesty: never hides what's already known).
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent(/Pick who this policy is for to continue/i);
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent(/creates\s*default\s*\/\s*—/);
  });
});

// --- Phase 2f: tool-name autocomplete + unknown-tool warning ------------------------------------------
describe("BuilderSheet — tool-name autocomplete + unknown-tool warning (Phase 2f)", () => {
  it("warns (non-blocking) when a toolIn tool has never been observed in the target namespace, and stays silent for an observed one", async () => {
    server.use(
      http.get("/api/v1/cluster-info", () => HttpResponse.json({ cluster_id: "c1", cluster_name: "kind", namespaces: ["default"] })),
      http.get("/api/v1/audit/top-blocked", () => HttpResponse.json([{ tool_name: "delete_kb", count: 3 }])),
      http.get("/api/v1/audit/records", () =>
        HttpResponse.json([{ timestamp: "2026-07-01T00:00:00Z", tool_name: "search_kb", decision: "allow" }])
      ),
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({ valid: true, errors: [], total_records_checked: 0, newly_blocked: 0, recommendation: "n/a" })
      )
    );

    renderSheet(); // namespace="default" — already concrete, so the observed-tools fetch fires on mount
    buildValidRule();
    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-type"), { target: { value: "toolIn" } });
    await waitFor(() => expect(screen.getByTestId("builder-cond-0-0-0-tools")).toBeInTheDocument());

    // An observed tool (from top-blocked) — no warning once the fetch has resolved.
    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-tools"), { target: { value: "delete_kb" } });
    await waitFor(() => expect(screen.queryByTestId("builder-unknown-tool-warning")).not.toBeInTheDocument());

    // A typo'd/never-seen tool — warns, but the compile-error gate is untouched and Dry-Run stays enabled.
    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-tools"), { target: { value: "delete_kb_typo" } });
    await waitFor(() =>
      expect(screen.getByTestId("builder-unknown-tool-warning")).toHaveTextContent(/no agent has called "delete_kb_typo" yet/i)
    );
    expect(screen.queryByTestId("builder-errors")).not.toBeInTheDocument();
    expect(screen.getByTestId("builder-dryrun-btn")).not.toBeDisabled();

    // It never blocks Save either — dry-running and saving proceed exactly as normal with the warning up.
    fireEvent.click(screen.getByTestId("builder-dryrun-btn"));
    await waitFor(() => expect(screen.getByTestId("builder-save-btn")).not.toBeDisabled());
    expect(screen.getByTestId("builder-unknown-tool-warning")).toBeInTheDocument();
  });

  it("suppresses the unknown-tool warning entirely until a concrete target namespace has been chosen (nothing to check against yet)", () => {
    render(<BuilderSheet namespace="all" onClose={() => {}} />);
    buildValidRule();
    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-type"), { target: { value: "toolIn" } });
    fireEvent.change(screen.getByTestId("builder-cond-0-0-0-tools"), { target: { value: "totally_unseen_tool" } });

    expect(screen.queryByTestId("builder-unknown-tool-warning")).not.toBeInTheDocument();
  });
});

// --- Phase 3: tier picker (Agent class / Namespace / Workload) + reserved-scope guard --------------
describe("BuilderSheet — policy tier picker (Phase 3)", () => {
  it("defaults to the Agent class tier, and switching tiers swaps which identifier field(s) show", () => {
    renderSheet();
    // Tier picker is now a radiogroup of three cards (UX redesign) — aria-checked, not aria-pressed.
    expect(screen.getByTestId("builder-tier-picker")).toHaveAttribute("role", "radiogroup");
    expect(screen.getByTestId("builder-tier-class")).toHaveAttribute("aria-checked", "true");
    expect(screen.getByTestId("builder-tier-namespace")).toHaveAttribute("aria-checked", "false");
    expect(screen.getByTestId("builder-tier-workload")).toHaveAttribute("aria-checked", "false");
    expect(screen.getByTestId("builder-agent-class")).toBeInTheDocument();
    expect(screen.queryByTestId("builder-scope-identifier")).not.toBeInTheDocument();

    // Namespace tier: the Agent class field disappears — the (relabeled) Target namespace field IS the
    // scope identifier now (single field, testid swaps to builder-scope-identifier).
    fireEvent.click(screen.getByTestId("builder-tier-namespace"));
    expect(screen.getByTestId("builder-tier-namespace")).toHaveAttribute("aria-checked", "true");
    expect(screen.queryByTestId("builder-agent-class")).not.toBeInTheDocument();
    expect(screen.getByTestId("builder-scope-identifier")).toBeInTheDocument();
    expect(screen.queryByTestId("builder-target-namespace")).not.toBeInTheDocument();

    // Workload tier: a NEW workload-name identifier field appears, AND the Target namespace field is
    // still separately present (its own testid, unaffected) — a workload policy needs both.
    fireEvent.click(screen.getByTestId("builder-tier-workload"));
    expect(screen.getByTestId("builder-tier-workload")).toHaveAttribute("aria-checked", "true");
    expect(screen.getByTestId("builder-scope-identifier")).toBeInTheDocument();
    expect(screen.getByTestId("builder-target-namespace")).toBeInTheDocument();
    // "Deployments only" appears twice now (the workload card's own small print, always shown, plus the
    // identifier field's helper text once that tier is active) — assert at least one, not a single match.
    expect(screen.getAllByText(/deployments only/i).length).toBeGreaterThan(0);
  });

  it("namespace tier: the compiled rego guards on input.agent.namespace, not agent_class, and uses the ns_ package/rule-id token", async () => {
    renderSheet(); // namespace prop = "default" -> targetNamespace pre-filled "default"
    fireEvent.click(screen.getByTestId("builder-tier-namespace"));
    // The identifier field IS the pre-filled target namespace already ("default").
    expect(screen.getByTestId("builder-scope-identifier")).toHaveValue("default");

    fireEvent.click(screen.getByTestId("builder-add-rule"));
    fireEvent.change(screen.getByTestId("builder-rule-reason-0"), { target: { value: "Blocked a destructive tool" } });
    fireEvent.click(screen.getByTestId("builder-add-condition-0-0"));

    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain("package norviq.custom.ns_default");
      expect(rego).toContain('input.agent.namespace == "default"');
      expect(rego).not.toMatch(/agent_class ==/);
    });
    expect(screen.queryByTestId("builder-errors")).not.toBeInTheDocument();
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent(
      "Applies to every agent in namespace `default`, whatever its class."
    );
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent("creates default / namespace:default");
  });

  it("workload tier: the compiled rego guards on input.agent.namespace using the TARGET namespace field, and uses the wl_ package/rule-id token", async () => {
    renderSheet(); // namespace prop = "default"
    fireEvent.click(screen.getByTestId("builder-tier-workload"));
    fireEvent.change(screen.getByTestId("builder-scope-identifier"), { target: { value: "checkout" } });
    // Target namespace already pre-filled "default" from the sheet's namespace prop.
    fireEvent.click(screen.getByTestId("builder-add-rule"));
    fireEvent.change(screen.getByTestId("builder-rule-reason-0"), { target: { value: "Blocked a destructive tool" } });
    fireEvent.click(screen.getByTestId("builder-add-condition-0-0"));

    await waitFor(() => {
      const rego = (screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value;
      expect(rego).toContain("package norviq.custom.wl_checkout");
      expect(rego).toContain('input.agent.namespace == "default"');
      expect(rego).not.toMatch(/agent_class ==/);
    });
    expect(screen.queryByTestId("builder-errors")).not.toBeInTheDocument();
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent(
      "Applies to agents of Deployment `checkout` in namespace `default`."
    );
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent("creates default / deployment:checkout");
  });

  it("switching tiers preserves each tier's own typed identifier (no cross-tier data loss)", () => {
    renderSheet();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });
    fireEvent.click(screen.getByTestId("builder-tier-workload"));
    fireEvent.change(screen.getByTestId("builder-scope-identifier"), { target: { value: "checkout" } });
    fireEvent.click(screen.getByTestId("builder-tier-class"));
    expect(screen.getByTestId("builder-agent-class")).toHaveValue("builder-spike");
    fireEvent.click(screen.getByTestId("builder-tier-workload"));
    expect(screen.getByTestId("builder-scope-identifier")).toHaveValue("checkout");
  });

  it("choosing a tier card reveals ONLY that tier's own identifier field, never more than one at a time", () => {
    renderSheet();
    // Default (class): only the agent-class field is shown.
    expect(screen.getByTestId("builder-agent-class")).toBeInTheDocument();
    expect(screen.queryByTestId("builder-scope-identifier")).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId("builder-tier-namespace"));
    // Namespace: agent-class is gone, and the ONE identifier field shown is the (relabeled) namespace
    // field — no second, separate identifier input appears alongside it.
    expect(screen.queryByTestId("builder-agent-class")).not.toBeInTheDocument();
    expect(screen.getAllByTestId("builder-scope-identifier")).toHaveLength(1);
    expect(screen.queryByTestId("builder-target-namespace")).not.toBeInTheDocument();

    fireEvent.click(screen.getByTestId("builder-tier-workload"));
    // Workload: agent-class stays hidden; exactly one workload-name identifier field, plus the always-
    // needed target-namespace field (a second, distinct field — not a duplicate identifier).
    expect(screen.queryByTestId("builder-agent-class")).not.toBeInTheDocument();
    expect(screen.getAllByTestId("builder-scope-identifier")).toHaveLength(1);
    expect(screen.getByTestId("builder-target-namespace")).toBeInTheDocument();
  });
});

// --- UX redesign: numbered steps, plain-English sentence, progressive disclosure --------------------
describe("BuilderSheet — numbered steps (UX redesign)", () => {
  it("renders step ① active and steps ②/③ dimmed (locked) on a fresh sheet", () => {
    renderSheet();
    expect(screen.getByTestId("builder-step-1")).toHaveAttribute("data-step-state", "active");
    expect(screen.getByTestId("builder-step-2")).toHaveAttribute("data-step-state", "locked");
    expect(screen.getByTestId("builder-step-3")).toHaveAttribute("data-step-state", "locked");
    expect(screen.getByTestId("builder-step-1-chip")).toHaveTextContent(/needs input/i);
    // Locked steps stay fully present (an operator revisiting a saved policy must see everything) —
    // never hard-disabled/unclickable.
    expect(screen.getByTestId("builder-mode-rules")).not.toBeDisabled();
  });

  it("step ② flips from locked to active once step ① becomes valid (class tier)", () => {
    renderSheet(); // namespace="default" already concrete
    expect(screen.getByTestId("builder-step-2")).toHaveAttribute("data-step-state", "locked");

    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "report-gen" } });

    expect(screen.getByTestId("builder-step-1")).toHaveAttribute("data-step-state", "done");
    expect(screen.getByTestId("builder-step-1-chip")).toHaveTextContent(/done/i);
    expect(screen.getByTestId("builder-step-2")).toHaveAttribute("data-step-state", "active");
  });

  it("step ③ flips from locked to active once step ② has a valid rule", () => {
    renderSheet();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "report-gen" } });
    expect(screen.getByTestId("builder-step-3")).toHaveAttribute("data-step-state", "locked");

    fireEvent.click(screen.getByTestId("builder-add-rule"));
    fireEvent.change(screen.getByTestId("builder-rule-reason-0"), { target: { value: "Blocked a delete" } });
    fireEvent.click(screen.getByTestId("builder-add-condition-0-0"));

    expect(screen.getByTestId("builder-step-2")).toHaveAttribute("data-step-state", "done");
    expect(screen.getByTestId("builder-step-3")).toHaveAttribute("data-step-state", "active");
  });

  it("renders the correct plain-English sentence for each of the three tiers, always with the loader key alongside it", () => {
    renderSheet(); // namespace="default"

    // class tier
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "report-gen" } });
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent(
      "Applies to every `report-gen` agent in namespace `default`."
    );
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent("creates default / report-gen");

    // namespace tier
    fireEvent.click(screen.getByTestId("builder-tier-namespace"));
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent(
      "Applies to every agent in namespace `default`, whatever its class."
    );
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent("creates default / namespace:default");

    // workload tier
    fireEvent.click(screen.getByTestId("builder-tier-workload"));
    fireEvent.change(screen.getByTestId("builder-scope-identifier"), { target: { value: "checkout" } });
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent(
      "Applies to agents of Deployment `checkout` in namespace `default`."
    );
    expect(screen.getByTestId("builder-create-target")).toHaveTextContent("creates default / deployment:checkout");
  });
});

describe("BuilderSheet — reserved-scope guard (Phase 3, Item A / P1 fix)", () => {
  it('typing "__baseline__" as the agent class shows the reserved-scope error and disables Dry-run/Save, with no compiled rego', async () => {
    renderSheet();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "__baseline__" } });
    fireEvent.click(screen.getByTestId("builder-add-rule"));
    fireEvent.change(screen.getByTestId("builder-rule-reason-0"), { target: { value: "x" } });
    fireEvent.click(screen.getByTestId("builder-add-condition-0-0"));

    await waitFor(() => expect(screen.getByTestId("builder-scope-reserved-error")).toBeInTheDocument());
    expect(screen.getByTestId("builder-scope-reserved-error")).toHaveTextContent(/reserved\/managed scope/i);
    expect(screen.getByTestId("builder-dryrun-btn")).toBeDisabled();
    expect(screen.getByTestId("builder-save-btn")).toBeDisabled();
    expect((screen.getByTestId("monaco-editor") as HTMLTextAreaElement).value).not.toContain("package norviq.");
  });

  it('typing "__cluster__" as the namespace-tier identifier shows the reserved-scope error and disables Save', async () => {
    renderSheet();
    fireEvent.click(screen.getByTestId("builder-tier-namespace"));
    fireEvent.change(screen.getByTestId("builder-scope-identifier"), { target: { value: "__cluster__" } });
    fireEvent.click(screen.getByTestId("builder-add-rule"));
    fireEvent.change(screen.getByTestId("builder-rule-reason-0"), { target: { value: "x" } });
    fireEvent.click(screen.getByTestId("builder-add-condition-0-0"));

    await waitFor(() => expect(screen.getByTestId("builder-scope-reserved-error")).toBeInTheDocument());
    expect(screen.getByTestId("builder-save-btn")).toBeDisabled();
  });

  it("a normal agent class shows no reserved-scope error", () => {
    renderSheet();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "report-gen" } });
    expect(screen.queryByTestId("builder-scope-reserved-error")).not.toBeInTheDocument();
  });
});
