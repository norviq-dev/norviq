// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * Baseline controls — the surface where a customer turns a shipped detector into an enforced block.
 *
 * The assertions here are mostly about the two ways this screen could lie: showing "nothing is
 * enforcing" when it simply could not READ the controls, and sending a partial map on save (the
 * endpoint replaces a namespace's set wholesale, so a partial body silently resets every control the
 * operator did not touch).
 */

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { BaselineControls } from "./BaselineControls";
import * as client from "../../api/client";
import { clearApiCache } from "../../hooks/useApi";
import { AppProvider } from "../../store/AppContext";

/** `useMutationScope` reads the app-wide namespace scope, so the component needs the real provider —
 *  a stub would let a scope-gating regression through, which is the thing that hook exists to stop.
 *
 *  The route carries `?ns=`, which is the first rule in AppContext's namespace precedence. Without it
 *  the provider resolves to the "all" aggregate and every control renders disabled — correctly, since
 *  a namespace-scoped write must never target the phantom aggregate scope. `test_aggregate_scope_...`
 *  below asserts that refusal on purpose. */
function renderPanel(props: { namespace: string; isAdmin: boolean }, scope = "chatbot-prod") {
  return render(
    <MemoryRouter initialEntries={[`/policies/targets?ns=${scope}`]}>
      <AppProvider>
        <BaselineControls {...props} />
      </AppProvider>
    </MemoryRouter>,
  );
}

const CONTROLS = {
  namespace: "chatbot-prod",
  preset: "strict",
  default_effect: "monitor" as const,
  effects: ["off", "monitor", "deny"] as const,
  counts: { off: 0, monitor: 2, deny: 0 },
  controls: [
    {
      id: "deny_shell_execution",
      title: "Shell / command execution",
      description: "Catches shell metacharacters in tool parameters.",
      caveat: "trips on roughly 1 in 8 ordinary alphanumeric identifiers",
      effect: "monitor" as const,
      default_effect: "monitor" as const,
    },
    {
      id: "pii_detection",
      title: "PII egress",
      description: "Catches personal data leaving via a tool call.",
      caveat: "",
      effect: "monitor" as const,
      default_effect: "monitor" as const,
    },
  ],
};

beforeEach(() => {
  clearApiCache();
  vi.restoreAllMocks();
});

function mockFetch(data: unknown = CONTROLS) {
  return vi.spyOn(client, "fetchBaselineControls").mockResolvedValue(data as never);
}

function mockCompliance(controls: unknown[], scanned = 1200) {
  return vi.spyOn(client, "fetchPolicyCompliance").mockResolvedValue({
    namespace: "chatbot-prod", range: "7d", scanned, excluded_synthetic: 0, controls,
  } as never);
}

describe("baseline controls", () => {
  it("renders one row per control with its current effect", async () => {
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const row = await screen.findByTestId("baseline-control-deny_shell_execution");
    expect(row).toHaveAttribute("data-effect", "monitor");
    expect(await screen.findByTestId("baseline-control-pii_detection")).toBeInTheDocument();
  });

  it("shows the false-positive caveat inline, not behind a tooltip", async () => {
    // The moment someone clicks Enforce is exactly the moment they will not go and read the docs.
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const caveat = await screen.findByTestId("baseline-caveat-deny_shell_execution");
    expect(caveat.textContent).toContain("1 in 8");
    // A control with no known false-positive mode must not render an empty warning box.
    expect(screen.queryByTestId("baseline-caveat-pii_detection")).toBeNull();
  });

  it("reports an unreadable control set as unknown, never as 'nothing enforcing'", async () => {
    vi.spyOn(client, "fetchBaselineControls").mockRejectedValue(new Error("503 upstream"));
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const err = await screen.findByTestId("baseline-unreadable");
    expect(err.textContent).toContain("unknown");
    expect(screen.queryByTestId("baseline-counts")).toBeNull();
  });

  it("keeps Save disabled until something actually changes", async () => {
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const save = await screen.findByTestId("baseline-save");
    expect(save).toBeDisabled();

    await userEvent.click(await screen.findByTestId("baseline-deny_shell_execution-deny"));
    await waitFor(() => expect(save).toBeEnabled());
    expect(screen.getByTestId("baseline-dirty-deny_shell_execution")).toBeInTheDocument();
  });

  it("sends the FULL control map on save, not just the edits", async () => {
    // The endpoint replaces a namespace's set wholesale. A partial body would quietly reset every
    // control the operator did not touch back to the default.
    mockFetch();
    const save = vi.spyOn(client, "saveBaselineControls").mockResolvedValue({
      namespace: "chatbot-prod", preset: "strict",
      effects: { deny_shell_execution: "deny", pii_detection: "monitor" },
      enforcing: ["deny_shell_execution"], disabled: [],
    } as never);

    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    await userEvent.click(await screen.findByTestId("baseline-deny_shell_execution-deny"));
    await userEvent.click(screen.getByTestId("baseline-save"));

    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(save.mock.calls[0][1]).toEqual({
      deny_shell_execution: "deny",
      pii_detection: "monitor", // untouched, but still sent
    });
  });

  it("says plainly when nothing is enforcing after a save", async () => {
    mockFetch();
    vi.spyOn(client, "saveBaselineControls").mockResolvedValue({
      namespace: "chatbot-prod", preset: "strict",
      effects: {}, enforcing: [], disabled: ["deny_shell_execution"],
    } as never);

    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    await userEvent.click(await screen.findByTestId("baseline-deny_shell_execution-off"));
    await userEvent.click(screen.getByTestId("baseline-save"));

    const msg = await screen.findByTestId("baseline-msg");
    expect(msg.textContent).toContain("nothing is enforcing");
  });

  it("is read-only for a non-admin", async () => {
    mockFetch();
    renderPanel({ namespace: "chatbot-prod", isAdmin: false });
    expect(await screen.findByTestId("baseline-deny_shell_execution-deny")).toBeDisabled();
    expect(screen.getByTestId("baseline-save")).toBeDisabled();
  });

  it("shows what promoting a control would have cost, on the control's own row", async () => {
    // "Promote this to Enforce" is a question about what will break. Answering it two screens away
    // means it does not get answered.
    mockFetch();
    mockCompliance([{
      control_id: "deny_shell_execution", count: 1432,
      agent_classes: [{ name: "cmp-support", count: 1400 }, { name: "cmp-finance", count: 32 }],
      tools: [{ name: "get_order", count: 1200 }], namespaces: ["chatbot-prod"],
      first_seen: null, last_seen: null, samples: [],
    }]);
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const impact = await screen.findByTestId("baseline-impact-deny_shell_execution");
    expect(impact.textContent).toContain("1,432");
    expect(impact.textContent).toContain("2 agent classes");
    expect(impact.textContent).toContain("get_order");
    // A quiet control gets no line at all — "0 calls" on every row trains people to stop reading it.
    expect(screen.queryByTestId("baseline-impact-pii_detection")).toBeNull();
  });

  it("distinguishes 'compliant' from 'nothing has happened here yet'", async () => {
    // Zero non-compliant out of ZERO traffic is idle; out of 40,000 it is compliant. Rendering an
    // idle namespace as a clean bill of health is the exact lie `scanned` exists to prevent.
    mockFetch();
    mockCompliance([], 0);
    renderPanel({ namespace: "chatbot-prod", isAdmin: true });
    const scanned = await screen.findByTestId("baseline-scanned");
    expect(scanned).toHaveAttribute("data-scanned", "0");
    expect(scanned.textContent).toContain("nothing measured yet");
  });

  it("refuses to write when the aggregate 'all namespaces' scope is selected", async () => {
    // A namespace-scoped write under the aggregate stores a row literally namespaced "all", which
    // enforces nothing — a concrete namespace's read never sees it. The control must be inert, not
    // optimistic.
    mockFetch();
    renderPanel({ namespace: "all", isAdmin: true }, "all");
    expect(await screen.findByTestId("baseline-deny_shell_execution-deny")).toBeDisabled();
    expect(screen.getByTestId("baseline-save")).toBeDisabled();
  });
});
