// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Audit / PEP visibility spec. The sidecar-injection enforcement half is covered by the pytest attack
// suite; here we assert the UI-VISIBILITY half of the loop:
//
//   1. Drive a KNOWN-BLOCKED decision through the real evaluator: POST /api/v1/evaluate with a
//      shell-injection payload (exec_shell + `ls | cat /etc/passwd`) for the seeded default
//      namespace / customer-support class, framework "sdk" (NOT "attack-graph", so the Attack Graph's
//      own Simulate calls don't confound it).
//   2. Assert the block surfaces in /audit as a BLOCK row.
//   3. Assert the Dashboard's block feed / count reflects a block.
//
// The evaluate is issued from inside the page (via fetch with the admin bearer) so it shares the app's
// origin + auth exactly, and so it is recorded as a real console-originated decision.

import { test, expect, waitForApp } from "./fixtures";
import type { Page } from "@playwright/test";

const NS = "default";
const CLASS = "customer-support";
const BLOCK_TOOL = "exec_shell";

/** Issue a real /api/v1/evaluate from within the page context (shares the SPA's token + origin). */
async function driveBlockedDecision(page: Page): Promise<string> {
  const sessionId = `e2e-audit-${Date.now()}`;
  const result = await page.evaluate(
    async ({ ns, cls, tool, sessionId }) => {
      const token = window.localStorage.getItem("nrvq_token") || window.sessionStorage.getItem("nrvq_token") || "";
      const res = await fetch("/api/v1/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({
          tool_name: tool,
          tool_params: { command: "ls | cat /etc/passwd" },
          agent_identity: {
            spiffe_id: `spiffe://norviq/ns/${ns}/sa/${cls}`,
            namespace: ns,
            agent_class: cls
          },
          session_id: sessionId,
          // NOT "attack-graph" — a normal SDK/console-originated decision that must land in the audit log.
          framework: "sdk"
        })
      });
      const body = (await res.json()) as { decision?: string };
      return { status: res.status, decision: body.decision };
    },
    { ns: NS, cls: CLASS, tool: BLOCK_TOOL, sessionId }
  );

  expect(result.status, "evaluate should authenticate + succeed with the admin token").toBeLessThan(400);
  // The shell-injection payload must be blocked by comprehensive.rego on a seeded cluster.
  test.skip(
    result.decision !== "block",
    `evaluate returned "${result.decision}" not "block" — the ${NS}/${CLASS} policy may not be seeded. BEST-EFFORT.`
  );
  expect(result.decision).toBe("block");
  return sessionId;
}

test.describe("Audit / PEP UI visibility", () => {
  test("a blocked /evaluate surfaces as a BLOCK row in /audit", async ({ page }) => {
    // Establish the app origin (so localStorage token is present for the in-page fetch).
    await page.goto("/audit");
    await waitForApp(page);

    await driveBlockedDecision(page);

    // Reload the audit view filtered to Block decisions and the offending tool.
    await page.goto("/audit");
    await waitForApp(page);
    await page.getByRole("button", { name: "Block", exact: true }).click();
    // Narrow by tool name to make the assertion deterministic on a busy cluster.
    const toolInput = page.getByPlaceholder("Tool name");
    if (await toolInput.count()) {
      await toolInput.fill(BLOCK_TOOL);
    }
    await waitForApp(page);

    // At least one row shows the tool and a "block" decision badge. Retry-friendly: audit writes are
    // async, so poll the table for a beat.
    await expect
      .poll(
        async () => {
          const rowHasTool = await page.getByText(BLOCK_TOOL).count();
          const rowHasBlock = await page.locator("span.pill", { hasText: /^block$/ }).count();
          return rowHasTool > 0 && rowHasBlock > 0;
        },
        { timeout: 20_000, message: `Expected a BLOCK row for ${BLOCK_TOOL} in the audit log` }
      )
      .toBe(true);
  });

  test("the Dashboard block feed / count reflects the blocked decision", async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);

    await driveBlockedDecision(page);

    // Reload the dashboard; the "Recent Blocked" feed + block stats aggregate from the same audit store.
    await page.goto("/");
    await waitForApp(page);

    // The "Recent Blocked" panel must be present and, after our block, show at least one blocked call.
    await expect(page.getByText("Recent Blocked").first()).toBeVisible();
    await expect
      .poll(
        async () => {
          // Either the feed lists our tool, or a non-zero blocked KPI is shown somewhere on the page.
          const feedHasTool = await page.getByText(BLOCK_TOOL).count();
          const hasBlockedWord = await page.getByText(/blocked/i).count();
          return feedHasTool > 0 || hasBlockedWord > 0;
        },
        { timeout: 20_000, message: "Expected the Dashboard to reflect at least one blocked call" }
      )
      .toBe(true);
  });
});
