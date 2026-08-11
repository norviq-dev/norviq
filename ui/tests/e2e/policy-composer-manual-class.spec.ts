// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Authoring a policy for an agent class that has NO labelled deployment, and proving it ENFORCES.
//
// WHY THIS WAS REWRITTEN RATHER THAN DELETED. It used to drive the guided composer, whose entry point
// ("New Policy (guided)") was removed in the Phase 2f consolidation — the Visual Builder is now the one
// authoring surface, with "Advanced (raw rego)" beside it. The spec kept clicking
// `getByRole("button", { name: "New Policy" })`, and because Playwright's `name` is a case-insensitive
// SUBSTRING by default that silently matched "New policy (raw rego)" and opened the wrong editor — so
// it failed looking for `composer-agent-class-input`, which only the retired sheet ever rendered.
//
// Deleting it was the tempting fix and would have quietly dropped a guarantee nothing else makes.
// `builder-scope-p1.spec.ts` drives the same free-text class field but stops at the compiled preview;
// nothing else proves that a class with NO deployment can be authored in the UI and actually flips a
// live /evaluate decision. That proof is the point of this file, so it is kept and retargeted.

import { test, expect, waitForApp } from "./fixtures";
import type { Page } from "@playwright/test";

const NS = "default";
const TOOL = "q2probe_tool";
// Novel per run, so no seeded or baseline policy blocks it and a flip is unambiguously OUR rule.
const KEYWORD = `q2probe${Date.now()}`;

async function ev(page: Page, cls: string, tool: string, params: Record<string, unknown>) {
  return page.evaluate(
    async ({ ns, agentClass, toolName, toolParams }) => {
      const token = localStorage.getItem("nrvq_token");
      const res = await fetch("/api/v1/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({
          tool_name: toolName,
          tool_params: toolParams,
          agent_identity: {
            spiffe_id: `spiffe://norviq/ns/${ns}/sa/${agentClass}`,
            namespace: ns,
            agent_class: agentClass
          },
          framework: "sdk"
        })
      });
      return res.json();
    },
    { ns: NS, agentClass: cls, toolName: tool, toolParams: params }
  );
}

test("a manual class with no deployment can be authored in the builder, and it ENFORCES", async ({ page }) => {
  // Saving drives a dry-run over recorded traffic and then a policy push, and OPA recompiles its whole
  // module store on that push — legitimately slower than a render-only spec.
  test.setTimeout(180_000);
  const CLS = `q2-manual-${Date.now()}`;

  // `?ns=` matters: the builder saves against ONE concrete namespace, so with the global scope on
  // "all" both Dry-run and Save stay disabled — their tooltip says "Pick a concrete target namespace
  // first". That is correct behaviour (a policy has to land somewhere), it just has to be satisfied.
  await page.goto(`/policies/catalog?ns=${NS}`);
  await waitForApp(page);

  // BEFORE: nothing is authored for this brand-new class, so the probe call is not blocked by us.
  const before = await ev(page, CLS, TOOL, { note: `hello ${KEYWORD}` });
  expect(before.decision).not.toBe("block");

  await page.getByRole("button", { name: "Visual Builder" }).click();
  await expect(page.getByTestId("builder-agent-class")).toBeVisible({ timeout: 20_000 });

  // The whole point: a FREE-TEXT class field, not a picker over deployed workloads. A class with no
  // labelled deployment must still be authorable — you write the policy before the agent ships.
  const classInput = page.getByTestId("builder-agent-class");
  expect(await classInput.evaluate((el) => el.tagName)).toBe("INPUT");
  await classInput.fill(CLS);

  // Tighten-only rules mode: block on a novel keyword.
  await page.getByTestId("builder-mode-rules").click();
  await page.getByTestId("builder-add-rule").click();
  await page.getByTestId("builder-rule-reason-0").fill("q2 probe keyword blocked");
  await page.getByTestId("builder-add-condition-0-0").click();
  await page.getByTestId("builder-cond-0-0-0-type").selectOption("keyword");
  await page.getByTestId("builder-cond-0-0-0-keywords").fill(KEYWORD);

  // Save is GATED on a valid dry-run of the CURRENT graph — a gate worth exercising in its own right.
  await expect(page.getByTestId("builder-save-btn")).toBeDisabled();
  await page.getByTestId("builder-dryrun-btn").click();
  await expect(page.getByTestId("builder-dryrun-result")).toBeVisible({ timeout: 60_000 });
  await expect(page.getByTestId("builder-save-btn")).toBeEnabled({ timeout: 30_000 });

  const [saveResp] = await Promise.all([
    page.waitForResponse((r) => r.url().includes("/api/v1/policies") && r.request().method() === "POST", { timeout: 60_000 }),
    page.getByTestId("builder-save-btn").click()
  ]);
  expect(saveResp.ok()).toBeTruthy();

  try {
    // AFTER — the EFFECT, not a 200. POLLED, never slept once: OPA recompiles its module store on a
    // policy push and the eval cache holds a decision for a few seconds, so a single immediate read
    // would be a coin toss.
    await expect
      .poll(async () => (await ev(page, CLS, TOOL, { note: `hello ${KEYWORD}` })).decision, { timeout: 40_000 })
      .toBe("block");

    // Control: tighten-only means a call WITHOUT the keyword is untouched by this policy.
    const benign = await ev(page, CLS, TOOL, { note: "nothing to see" });
    expect(benign.decision).not.toBe("block");
  } finally {
    // Never leave an enforcing policy behind for a throwaway class.
    await page.evaluate(
      async ({ ns, cls }) => {
        const token = localStorage.getItem("nrvq_token");
        await fetch(`/api/v1/policies/${ns}/${cls}`, {
          method: "DELETE",
          headers: token ? { Authorization: `Bearer ${token}` } : {}
        });
      },
      { ns: NS, cls: CLS }
    );
  }
});
