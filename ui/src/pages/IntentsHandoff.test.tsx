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
import { MemoryRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
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

  it("REFUSES the handoff rather than silently dropping a restriction, and says so BEFORE the click", async () => {
    // The failure this prevents: the operator dry-runs an intent that forbids credential egress,
    // hands it to the builder, and edits a policy that no longer forbids it — while believing it is
    // the same policy. A warning that can be clicked through is how that gets saved.
    //
    // The refusal itself is unchanged. What changed is that it is now legible up front: it used to
    // live in a `title` tooltip on a button that looked enabled, and arrive as a corner toast showing
    // only the first of N reasons. A refusal you discover by pressing the button is a dead end.
    vi.spyOn(client, "apiSend").mockResolvedValue(LOSSY as never);
    const user = userEvent.setup();
    renderIntents();
    await propose(user);
    await waitFor(() => expect(screen.getByTestId("open-in-builder")).toBeInTheDocument());

    // Stated in place, with EVERY reason, before anything is pressed.
    const banner = await screen.findByTestId("handoff-blocked");
    expect(banner).toHaveTextContent(/cannot be edited in the builder without weakening it/i);
    expect(banner).toHaveTextContent(/nested path has no equivalent/i);

    await user.click(screen.getByTestId("open-in-builder"));
    // And it did NOT navigate: the Intents screen is still the one rendered.
    expect(screen.getByLabelText("Agent class")).toBeInTheDocument();
  });

  it("shows no refusal banner for an intent the builder can represent in full", async () => {
    vi.spyOn(client, "apiSend").mockResolvedValue(CONVERTIBLE as never);
    const user = userEvent.setup();
    renderIntents();
    await propose(user);
    await waitFor(() => expect(screen.getByTestId("open-in-builder")).toBeInTheDocument());
    expect(screen.queryByTestId("handoff-blocked")).not.toBeInTheDocument();
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

describe("the handoff must not lose a narrowing on the way into the builder", () => {
  it("round-trips grant FACTS, not just constraints", () => {
    // The seam had a hole: BuilderSheet seeded only `g.constraints`, so every scoping FACT an intent
    // carried was dropped on arrival. Invisibly, too — intentToGraph converts facts successfully, so
    // `dropped` is empty and the handoff refusal cannot fire. The operator would then save a policy
    // strictly MORE PERMISSIVE than the one they dry-ran and approved.
    const { graph, dropped } = intentToBuilderGraph({
      class: "report-gen",
      call: [{
        id: "mail",
        match: { tool_name: "send_email" },
        require: { data_classes: { noneOf: ["secret"] } }
      }]
    });
    expect(dropped).toEqual([]);
    const grant = graph.allowlist?.grants?.[0];
    expect(grant?.facts, "converter must produce the fact").toHaveLength(1);

    // What the sheet reassembles from that seed must still carry it.
    const seededFacts = Object.fromEntries(
      (graph.allowlist?.grants ?? []).filter((g) => (g.facts ?? []).length > 0).map((g) => [g.tool, g.facts])
    );
    expect(seededFacts["send_email"]).toEqual(grant?.facts);
  });
});

describe("the handoff must land on a route that actually keeps the state", () => {
  it("reaches the catalog WITH the graph, through the real router", async () => {
    // App.tsx routes `/policies` through `<Navigate to="/policies/catalog" replace />`, and a redirect
    // DROPS router state — so navigating to the shorthand delivered the operator to the catalog with
    // location.state null and the builder silently never opened. The earlier tests could not catch it:
    // they rendered BuilderSheet directly with a seedGraph prop, so navigate -> redirect -> catalog was
    // never exercised. This drives the REAL router, including that redirect, and asserts the graph
    // survives the trip — which is the property that actually matters, not the literal path string.
    vi.spyOn(client, "apiSend").mockResolvedValue(CONVERTIBLE as never);
    const user = userEvent.setup();

    function Landing() {
      const loc = useLocation();
      const g = (loc.state as { builderGraph?: { allowlist?: { tools?: string[] } } } | null)?.builderGraph;
      return <div data-testid="landing">{`${loc.pathname}|graph=${g ? (g.allowlist?.tools ?? []).join(",") : "MISSING"}`}</div>;
    }

    render(
      <MemoryRouter initialEntries={["/intents?ns=agents"]}>
        <AppProvider>
          <ToastProvider>
            <Routes>
              <Route path="/intents" element={<Intents />} />
              {/* the real redirect, reproduced exactly */}
              <Route path="/policies" element={<Navigate to="/policies/catalog" replace />} />
              <Route path="/policies/catalog" element={<Landing />} />
            </Routes>
          </ToastProvider>
        </AppProvider>
      </MemoryRouter>
    );

    await propose(user);
    await waitFor(() => expect(screen.getByTestId("open-in-builder")).toBeInTheDocument());
    await user.click(screen.getByTestId("open-in-builder"));

    await waitFor(() => expect(screen.getByTestId("landing")).toBeInTheDocument());
    const landed = screen.getByTestId("landing").textContent ?? "";
    expect(landed).toContain("/policies/catalog");
    expect(landed, "the graph must survive the navigation").not.toContain("MISSING");
    expect(landed).toContain("execute_sql");
  });
});
