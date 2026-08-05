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
//   - `params_available: false` with `params_detail: "keys"` — no argument VALUES are stored (the
//     default install stores none), but the argument NAMES the traffic carried are. This is the
//     degraded state the design promotes to a primary one. It used to be `detail: "none"`: before
//     argument-name capture existed, a default install recorded nothing at all and the proposal
//     could only name tools.
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

  // ASSERT THE CALL, then wait for a STRUCTURAL anchor.
  //
  // This helper originally waited on `hoisted-clauses`, which was wrong twice over. That element is
  // conditional on two or more rules sharing a clause — a property of the recorded traffic, not of
  // "a proposal rendered" — so it made every test in the file depend on how the proposer happened to
  // group today's audit rows. And nothing checked that the request succeeded, so any API failure
  // spent 30s waiting for an element that would never appear and then reported a missing locator
  // instead of the actual error. Intermittently red for a reason no message named.
  const call = page.waitForResponse((r) => r.url().includes("/api/v1/intents/propose"));
  await page.getByRole("button", { name: /propose intent/i }).click();
  expect((await call).status()).toBe(200);

  // A rule card is present whenever a proposal rendered at all, whatever its shape.
  await expect(page.locator('[data-testid^="rule-"]').first()).toBeVisible({ timeout: 30_000 });
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

test("the capture state is a primary state, not a footnote", async ({ page }) => {
  // This class's audit rows carry argument NAMES and no values, which is what a default install
  // records. Saying that plainly is the difference between an informed draft and a surprise in
  // production — an operator who reads an existence check as a value check has mis-scoped the rule.
  //
  // This asserted `params-warning` ("Proposed from tool names only") until argument-name capture
  // landed. That band is still correct and still tested, but it is now gated on `detail: "none"`,
  // which this cluster no longer reaches: the proposal knows `url`, `to` and `query`, so "tool names
  // only" would be a false statement about it.
  await propose(page);
  const band = page.getByTestId("params-keys");
  await expect(band).toBeVisible();
  await expect(band).toContainText(/Argument names recorded, values not/i);
  await expect(band).toContainText(/present/i);
  // The band claims names are recorded; this proves the page actually shows them. Without it the
  // assertion above passes against a screen whose whole point — the names — never rendered.
  await expect(page.getByTestId("unscoped-args")).toContainText(/no rule mentions/i);
  // And the superseded band must NOT also be on screen: the two make contradictory claims about
  // whether anything was captured, and rendering both would be worse than rendering either.
  await expect(page.getByTestId("params-warning")).toHaveCount(0);
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
  // The proposal is STILL on screen — that is the whole point. Anchored on a rule card rather than
  // the hoisted line, which is conditional on how the proposer grouped today's traffic.
  await expect(page.locator('[data-testid^="rule-"]').first()).toBeVisible();
});

test("the dry run replays real traffic and reports what it would refuse", async ({ page, recorder }) => {
  // The dry run REPLAYS every recorded call for the class, capped at 500, and each one is an OPA
  // evaluation. Cost therefore scales with how much traffic the cluster has accumulated: on a fresh
  // seed this class had 12 calls and the whole test took under 2s; after a day of seeding and
  // red-team runs it replays the full 500 and the API alone takes ~7s. That is the feature working,
  // not a regression — but it outgrew the default 60s budget once page load and three parallel
  // workers are added on top.
  test.setTimeout(120_000);
  await propose(page);
  await page.getByRole("button", { name: /dry run/i }).click();
  // Either outcome is valid against live traffic; what must hold is that the page states one of them
  // rather than leaving the operator to guess.
  await expect(
    page.getByTestId("no-blocks").or(page.getByTestId("near-misses"))
  ).toBeVisible({ timeout: 30_000 });
  recorder.expectNoApiFailures();
});

test("a proposed rule naming a look-alike tool says so, and says what it costs", async ({ page }) => {
  // The whole chain, end to end: the seeder drives `sеnd_email` (U+0435 CYRILLIC SMALL LETTER IE)
  // through /evaluate, the proposer groups those rows into a rule, and the card renders the name.
  //
  // A unit test proves `predicateSentence` annotates a value I hand it. Only this proves the value
  // reaching the card is REALLY spoofed — that the audit row, the proposer and the API preserve the
  // codepoint rather than normalising it away somewhere in between. If any of them started folding
  // the name, this test goes red and the unit tests stay green.
  //
  // Written as an escape, never pasted: a literal here is indistinguishable from the ASCII spelling,
  // so a copy-paste error would silently turn this into a test of the wrong tool.
  const HOMOGLYPH = "s\u0435nd_email";
  await propose(page);

  const note = page.getByTestId(/lookalike/).first();
  await expect(note).toBeVisible();
  // Position, not just the codepoint: "U+0435" says something is wrong, "s·nd_email" says where.
  await expect(note).toContainText("s·nd_email");
  await expect(note).toContainText("U+0435");
  // The consequence is the half an operator cannot derive from the badge alone.
  await expect(note).toContainText(/grants the look-alike/);

  // ...and the raw clause still carries the real codepoint. `Show raw` is the string an operator
  // greps the engine for; a "cleaned up" spelling there would be the same bug one layer down.
  const card = page.locator('[data-testid^="rule-"]').filter({ has: page.getByTestId(/lookalike/) }).first();
  await card.getByRole("button", { name: /show raw/i }).click();
  await expect(card.locator("pre")).toContainText(HOMOGLYPH);
});
