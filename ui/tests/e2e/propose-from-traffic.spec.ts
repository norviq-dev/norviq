// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Propose from traffic, against the REAL app and a real seeded cluster — no mocks.
//
// The seeder drives four tools through `/api/v1/evaluate` as `support-agent`, so `POST
// /intents/propose` has genuine audit rows to group into rules. That matters here more than on the
// other surfaces: the shapes this page renders are PRODUCED by the proposer, so a fixture would only
// prove the components render what I told them to.
//
// Two states this cluster reaches naturally and a fixture would have to fake:
//   - `params_available: false` — the audit log records no call arguments, so the proposal can only
//     name tools. This is the degraded state the design promotes to a primary one.
//   - a hoisted clause — the proposer attaches `data_classes noneOf ['secret']` to every rule.
//
// Prerequisites (see scripts/e2e.sh):
//   kubectl -n norviq port-forward svc/norviq-ui 3400:80
//   .venv/bin/python scripts/kind-e2e/seed.py
//   an admin JWT in $NRVQ_TOKEN_FILE

import { expect, test } from "./fixtures";

const CLASS = "support-agent";

async function propose(page: import("@playwright/test").Page) {
  await page.goto("/intents?ns=analytics");
  await page.getByLabel("Agent class").fill(CLASS);
  await page.getByRole("button", { name: /propose intent/i }).click();
  await expect(page.getByTestId("hoisted-clauses")).toBeVisible({ timeout: 30_000 });
}

test("a proposed rule reads as two questions, not a predicate dump", async ({ page, recorder }) => {
  await propose(page);
  // APPLIES TO answers "is this rule about the call I am worried about?"; ALLOWED IF answers "and
  // what must additionally hold?". Flattened into one line, every rule looked like it might govern
  // every call, so the operator read all of them or none.
  const card = page.locator('[data-testid^="rule-"]').first();
  await expect(card.getByText("Applies to")).toBeVisible();
  await expect(card.getByText("Allowed if")).toBeVisible();
  await expect(card).toContainText(/calls to/i);
  recorder.expectNoApiFailures();
  recorder.expectNoConsoleErrors();
});

test("the clause every rule repeats is stated once, above the set", async ({ page }) => {
  // The proposer attaches `data_classes noneOf ['secret']` to everything it emits. Repeated on each
  // card it costs a line per rule and buries the clauses that actually differ.
  await propose(page);
  const hoisted = page.getByTestId("hoisted-clauses");
  await expect(hoisted).toContainText(/Applied to every rule/i);
  await expect(hoisted).toContainText(/carries none of secret/i);
  await expect(page.locator('[data-testid^="rule-"]').first()).not.toContainText(/carries none of secret/i);
});

test("the engine's own predicate text is one click away, in the same dialect", async ({ page }) => {
  // An operator who has read a refusal needs to find the same string on the rule. Two dialects for
  // one clause is what the design brief explicitly forbids.
  await propose(page);
  const card = page.locator('[data-testid^="rule-"]').first();
  await card.getByRole("button", { name: "Show raw" }).click();
  await expect(card.locator("pre")).toContainText(/tool_name in \[/);
});

test("no recorded arguments is a primary state, not a footnote", async ({ page }) => {
  // The audit log for this class carries no call parameters, so a rule here grants a tool outright.
  // Saying that plainly is the difference between an informed draft and a surprise in production.
  await propose(page);
  const warning = page.getByTestId("params-warning");
  await expect(warning).toBeVisible();
  await expect(warning).toContainText(/Proposed from tool names only/i);
  await expect(warning).toContainText(/grants a tool outright/i);
});

test("a draft cannot be saved before the dry run, and the button says why", async ({ page }) => {
  // `.btn:disabled { pointer-events: none }` means a title on a disabled button can never be read,
  // so the reason has to be text beside it.
  await propose(page);
  await expect(page.getByTestId("save-draft")).toBeDisabled();
  await expect(page.getByTestId("draft-gate-reason")).toContainText(/Dry run it first/i);
});

test("editing the class no longer destroys the proposal", async ({ page }) => {
  // It used to clear on every keystroke, so correcting a typo threw away a dry run that had just
  // replayed the whole sample. The proposal names its own class; when they diverge the page says so.
  await propose(page);
  await page.getByLabel("Agent class").fill("support-agentt");
  await expect(page.getByTestId("proposal-stale")).toBeVisible();
  await expect(page.getByTestId("proposal-stale")).toContainText(CLASS);
  // The proposal is STILL on screen — that is the whole point.
  await expect(page.getByTestId("hoisted-clauses")).toBeVisible();
});

test("the dry run replays real traffic and reports what it would refuse", async ({ page, recorder }) => {
  await propose(page);
  await page.getByRole("button", { name: /dry run/i }).click();
  // Either outcome is valid against live traffic; what must hold is that the page states one of them
  // rather than leaving the operator to guess.
  await expect(
    page.getByTestId("no-blocks").or(page.getByTestId("near-misses"))
  ).toBeVisible({ timeout: 30_000 });
  recorder.expectNoApiFailures();
});
