// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// FAIL-ON-BUG coverage for two evidence-attribution defects on the Compliance detail view:
//
//   DEF-038 — the "Enforcing policies & live evidence" rows printed the technique-WIDE `blocked`
//     total on EVERY covered-rule row, so a technique enforced by >1 rule repeated the same number
//     on each row and over-attributed all blocks to each rule. The fix renders each rule's OWN count
//     from the per-rule `blocked_by_rule` map the backend now ships.
//
//   DEF-039 — the [namespace, framework] scope-reset effect cleared drafted/selectedGaps/batchOutcome
//     but NOT `genClassMode`, so a specific class-scope picked in ns-A persisted across a namespace
//     switch and got submitted verbatim to generate-batch in ns-B (where that class doesn't exist),
//     yielding a zero-draft "no_affected_classes" batch. The fix resets genClassMode to "affected".
//
// Both tests FAIL against the pre-fix code (DEF-038: both rows read "40 blocked"; DEF-039: the POST
// carries class_mode "billing-agent") and PASS after the fix.

import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { Compliance } from "./Compliance";
import { AppProvider, useApp } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

const emptyTrend = (framework: string) =>
  http.get("/api/v1/compliance/:framework/trend", ({ params }) =>
    HttpResponse.json({ namespace: "default", range: "30d", framework: params.framework ?? framework, points: [] })
  );

// ---- DEF-038 ------------------------------------------------------------------------------------
// One ENFORCED ATLAS technique (AML.T0054) covered by TWO rules. The technique-wide total is 40,
// but per-rule the split is 25 / 15. The evidence rows must render the per-rule split, not 40/40.
function atlasTwoRulePayload() {
  return {
    namespace: "default",
    range: "24h",
    framework: "atlas",
    enforceable_total: 1,
    enforced: 1,
    gap: 0,
    oos: 0,
    coverage_pct: 100,
    covered: 1,
    total: 1,
    observed: 60,
    blocked: 40,
    agent_classes: 1,
    techniques: [
      {
        technique_id: "AML.T0054",
        name: "LLM Jailbreak",
        description: "Adversary crafts inputs that override the agent's guardrails.",
        scope: "enforceable",
        status: "enforced",
        policies: ["deny_shell_execution", "llm01_prompt_injection"],
        covered_policies: ["deny_shell_execution", "llm01_prompt_injection"],
        covered: true,
        observed: 60,
        blocked: 40, // technique-wide total (sum over both covered rules)
        blocked_by_rule: { deny_shell_execution: 25, llm01_prompt_injection: 15 },
        affected_classes: [{ class: "shell-runner", blocked: 40 }]
      }
    ]
  };
}

// Minimal, valid OWASP payload so the overview's second card still renders.
function owaspEmptyPayload() {
  return {
    namespace: "default",
    range: "24h",
    framework: "owasp",
    enforceable_total: 0,
    enforced: 0,
    gap: 0,
    oos: 0,
    coverage_pct: 0,
    covered: 0,
    total: 0,
    observed: 0,
    blocked: 0,
    agent_classes: 0,
    techniques: []
  };
}

function renderPage(initialEntry = "/") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <AppProvider>
        <Compliance />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("Compliance evidence rows — DEF-038 per-rule blocked attribution", () => {
  it("renders each covered rule's OWN blocked count, not the technique-wide total on every row", async () => {
    server.use(
      http.get("/api/v1/compliance/:framework/coverage", ({ params }) =>
        HttpResponse.json(params.framework === "owasp" ? owaspEmptyPayload() : atlasTwoRulePayload())
      ),
      emptyTrend("atlas")
    );
    renderPage();

    // Open the ATLAS card's detail (first "Open coverage detail →"); it auto-selects the enforced technique.
    const openButtons = await screen.findAllByText("Open coverage detail →");
    fireEvent.click(openButtons[0]);

    // Both covered-rule rows render.
    const denyRuleLabel = await screen.findByText("deny_shell_execution");
    const injRuleLabel = await screen.findByText("llm01_prompt_injection");
    const denyRow = denyRuleLabel.closest("div")!;
    const injRow = injRuleLabel.closest("div")!;

    // FAIL-ON-BUG: each row must show its OWN rule's blocked count (25 / 15), NOT the technique total (40).
    // Pre-fix, both rows printed fmt(t.blocked) === "40 blocked" and these assertions throw.
    expect(within(denyRow).getByText(/^25 blocked/)).toBeInTheDocument();
    expect(within(injRow).getByText(/^15 blocked/)).toBeInTheDocument();

    // The misattributed technique-wide "40 blocked" must appear on NEITHER row.
    expect(screen.queryAllByText(/^40 blocked/)).toHaveLength(0);
  });
});

// ---- DEF-039 ------------------------------------------------------------------------------------
// A helper mounted inside the provider so the test can drive a real namespace switch (namespace lives
// in AppContext, not a Compliance prop).
function NsSwitcher() {
  const { setNamespace } = useApp();
  return (
    <button data-testid="test-switch-ns" onClick={() => setNamespace("team-b")}>
      switch
    </button>
  );
}

// team-a: one GENERATABLE gap whose only affected class is "billing-agent" (populates the class-scope
// picker with that specific option).
function atlasTeamA() {
  return {
    namespace: "team-a",
    range: "24h",
    framework: "atlas",
    enforceable_total: 1,
    enforced: 0,
    gap: 1,
    oos: 0,
    coverage_pct: 0,
    covered: 0,
    total: 1,
    observed: 5,
    blocked: 0,
    agent_classes: 1,
    techniques: [
      {
        technique_id: "AML.T0100",
        name: "Gap In Team A",
        description: "d",
        scope: "enforceable",
        status: "gap",
        generatable: true,
        priority: "high",
        policies: ["some_rule"],
        covered_policies: [],
        covered: false,
        observed: 5,
        blocked: 0,
        affected_classes: [{ class: "billing-agent", blocked: 0 }]
      }
    ]
  };
}

// team-b: a DIFFERENT generatable gap whose only affected class is "payments-agent". "billing-agent"
// does not exist here — so a stale genClassMode='billing-agent' would be an off-list select value.
function atlasTeamB() {
  return {
    namespace: "team-b",
    range: "24h",
    framework: "atlas",
    enforceable_total: 1,
    enforced: 0,
    gap: 1,
    oos: 0,
    coverage_pct: 0,
    covered: 0,
    total: 1,
    observed: 3,
    blocked: 0,
    agent_classes: 1,
    techniques: [
      {
        technique_id: "AML.T0200",
        name: "Gap In Team B",
        description: "d",
        scope: "enforceable",
        status: "gap",
        generatable: true,
        priority: "medium",
        policies: ["other_rule"],
        covered_policies: [],
        covered: false,
        observed: 3,
        blocked: 0,
        affected_classes: [{ class: "payments-agent", blocked: 0 }]
      }
    ]
  };
}

describe("Compliance batch class-scope — DEF-039 genClassMode reset on namespace change", () => {
  it("resets the batch class-scope to 'affected' when the namespace changes (no stale class submitted)", async () => {
    let batchBody: { technique_ids?: string[]; class_mode?: string; namespace?: string } | null = null;
    server.use(
      http.get("/api/v1/compliance/:framework/coverage", ({ params, request }) => {
        const ns = new URL(request.url).searchParams.get("namespace");
        if (params.framework === "owasp") return HttpResponse.json({ ...owaspEmptyPayload(), namespace: ns ?? "all" });
        return HttpResponse.json(ns === "team-b" ? atlasTeamB() : atlasTeamA());
      }),
      emptyTrend("atlas"),
      http.post("/api/v1/compliance/:framework/generate-batch", async ({ request }) => {
        batchBody = (await request.json()) as { technique_ids?: string[]; class_mode?: string; namespace?: string };
        return HttpResponse.json({
          framework: "atlas",
          namespace: batchBody.namespace,
          class_mode: batchBody.class_mode,
          requested: batchBody.technique_ids?.length ?? 0,
          drafts_created: 1,
          results: [
            {
              status: "draft",
              draft_id: "d-b",
              technique_id: "AML.T0200",
              cls: "payments-agent",
              deeplink: "/policies/catalog?intent_draft=d-b"
            }
          ]
        });
      })
    );

    render(
      <MemoryRouter initialEntries={["/?ns=team-a"]}>
        <AppProvider>
          <NsSwitcher />
          <Compliance />
        </AppProvider>
      </MemoryRouter>
    );

    // Open the ATLAS detail for team-a.
    const openButtons = await screen.findAllByText("Open coverage detail →");
    fireEvent.click(openButtons[0]);

    // Check the team-a gap → the batch bar appears; pick the specific class 'billing-agent'.
    fireEvent.click(await screen.findByTestId("gap-select-AML.T0100"));
    const classmode = await screen.findByTestId("gap-batch-classmode");
    fireEvent.change(classmode, { target: { value: "billing-agent" } });
    expect((classmode as HTMLSelectElement).value).toBe("billing-agent");

    // Switch to team-b: the [namespace] scope-reset effect fires (clears selectedGaps + resets classmode).
    fireEvent.click(screen.getByTestId("test-switch-ns"));

    // The team-b gap renders; re-select it so the batch bar remounts, WITHOUT touching the classmode select.
    fireEvent.click(await screen.findByTestId("gap-select-AML.T0200"));
    await screen.findByTestId("gap-batch-generate");

    // Generate for the team-b selection.
    fireEvent.click(screen.getByTestId("gap-batch-generate"));

    // FAIL-ON-BUG: the batch must carry the safe default class_mode 'affected', not the stale 'billing-agent'.
    // Pre-fix, genClassMode is never reset on the namespace switch, so 'billing-agent' is submitted for team-b.
    await waitFor(() => expect(batchBody).not.toBeNull());
    expect(batchBody!.namespace).toBe("team-b");
    expect(batchBody!.class_mode).toBe("affected");
    expect(batchBody!.technique_ids).toEqual(["AML.T0200"]);
  });
});
