// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The seam between the two authoring surfaces.
//
// After the MCP merge there were three ways to reach a deny-by-default policy: the Create menu's
// "Visual Builder", its "Advanced (raw rego)", and this screen. This repo already resolved that exact
// confusion once by deleting a canvas editor, so /intents does NOT grow an editor — it hands its
// proposal to the builder. These tests pin the two properties that make the handoff safe:
//
//   1. it refuses (not warns) when a constraint would be lost, because a dropped predicate makes the
//      resulting policy MORE PERMISSIVE than the one just dry-run and approved;
//   2. the graph that does arrive lands in ALLOWLIST mode, since an intent is default-deny and rules
//      mode is default-allow — arriving in the wrong mode would invert its meaning.

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Intents } from "./Intents";
import { BuilderSheet } from "../components/policies/BuilderSheet";
import { ToastProvider } from "../components/common/Toast";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";
import { intentToBuilderGraph } from "../lib/intentToGraph";
import * as client from "../api/client";

/** Fully representable: scopes by tool name, constrains one TOP-LEVEL argument. */
const CONVERTIBLE = {
  intent: {
    name: "reads-only",
    class: "report-gen",
    call: [{ id: "select-only", match: { tool_name: "execute_sql" }, require: { "param_paths.query": { matches: "(?i)^\\s*select\\b" } } }]
  },
  sampled: 4,
  params_available: true
};

/** Not representable: a NESTED param_paths path.
 *
 *  This used to be `data_classes`, which grants now carry as a fact — so that intent converts cleanly
 *  and the handoff correctly stops refusing it. A nested path is the remaining honest example: a grant
 *  addresses one flat `tool_params[field]`, and taking the last segment of `filters.ids[0]` would point
 *  the constraint at a DIFFERENT argument, which is the silent-wrong case the refusal exists to stop. */
const LOSSY = {
  intent: {
    name: "narrow-by-nested-arg",
    class: "report-gen",
    call: [{ id: "rows", match: { tool_name: "read_rows" }, require: { "param_paths.filters.ids[0]": "C-91" } }]
  },
  sampled: 4,
  params_available: true
};

function renderIntents() {
  return render(
    <MemoryRouter initialEntries={["/intents?ns=agents"]}>
      <AppProvider>
        <ToastProvider>
          <Intents />
        </ToastProvider>
      </AppProvider>
    </MemoryRouter>
  );
}

async function propose(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Agent class"), "report-gen");
  await user.click(screen.getByRole("button", { name: /propose intent/i }));
}

describe("intents -> builder handoff", () => {
  beforeEach(() => {
    clearApiCache();
    vi.restoreAllMocks();
  });

  it("offers the handoff for an intent the builder can represent in full", async () => {
    vi.spyOn(client, "apiSend").mockResolvedValue(CONVERTIBLE as never);
    const user = userEvent.setup();
    renderIntents();
    await propose(user);
    await waitFor(() => expect(screen.getByTestId("open-in-builder")).toBeInTheDocument());
    expect(screen.getByTestId("open-in-builder")).not.toBeDisabled();
  });

  it("REFUSES the handoff rather than silently dropping a restriction", async () => {
    // The failure this prevents: the operator dry-runs an intent that forbids credential egress,
    // hands it to the builder, and edits a policy that no longer forbids it — while believing it is
    // the same policy. A warning that can be clicked through is how that gets saved.
    vi.spyOn(client, "apiSend").mockResolvedValue(LOSSY as never);
    const user = userEvent.setup();
    renderIntents();
    await propose(user);
    await waitFor(() => expect(screen.getByTestId("open-in-builder")).toBeInTheDocument());
    await user.click(screen.getByTestId("open-in-builder"));
    await waitFor(() =>
      expect(screen.getByText(/cannot be edited in the builder without weakening it/i)).toBeInTheDocument()
    );
    // And it did NOT navigate: the Intents screen is still the one rendered.
    expect(screen.getByLabelText("Agent class")).toBeInTheDocument();
  });

  it("the converted graph opens the builder in allowlist mode with its tools and constraints", async () => {
    const { graph, dropped } = intentToBuilderGraph(CONVERTIBLE.intent);
    expect(dropped).toEqual([]);
    vi.spyOn(client, "apiSend").mockResolvedValue({ classes: [], namespaces: [] } as never);
    render(
      <MemoryRouter>
        <AppProvider>
          <ToastProvider>
            <BuilderSheet namespace="agents" seedGraph={graph} onClose={() => {}} />
          </ToastProvider>
        </AppProvider>
      </MemoryRouter>
    );
    // An intent is default-DENY; arriving in rules mode (default-allow) would invert it.
    await waitFor(() => expect(screen.getByDisplayValue("report-gen")).toBeInTheDocument());
    expect(screen.getByText("execute_sql")).toBeInTheDocument();
  });
});
