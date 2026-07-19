// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// PRIORITY spec — the Attack Graph (kill-chain triage), driven against the REAL app + backend. Covers
// the render, the four layout/scroll/weight REGRESSIONS, the selection→canvas→inspector drive, the
// what-if + scope-card interactions, and the GLOBAL positive-security intent flow — now an ALLOWLIST
// BUILDER (usage-driven checklist of observed tools + refinement toggles → coverage → draft →
// deep-link into /policies/catalog), with backend request assertions on:
//   GET  /api/v1/threats/attack-paths    (ns + range params)
//   GET  /api/v1/threats/intent-suggest  (ns + cls — seeds the checklist)
//   POST /api/v1/threats/intent-coverage (allow_tools + intent → generated rego + coverage)
//   POST /api/v1/threats/intent-draft    (allow_tools → durable dry-run draft + deep-link)
//   POST /api/v1/evaluate                (Simulate)
//
// Data-dependency note: these tests need at least one stored attack path in the served namespace(s).
// Where a specific state (e.g. an exploitable path with a togglable hop) is required and the live data
// does not present it, the assertion is written to degrade gracefully (test.skip with a clear reason)
// rather than to flake — flagged inline as BEST-EFFORT.

import { test, expect, waitForApp } from "./fixtures";
import type { Page, Locator } from "@playwright/test";

const CANVAS = "attack-graph-canvas";

async function gotoAttackGraph(page: Page): Promise<void> {
  await page.goto("/threats/graph");
  await waitForApp(page);
  await expect(page.getByTestId(CANVAS)).toBeVisible();
}

/** The count of ranked path rows in the left list (buttons under "Attack paths · worst first"). */
function pathRows(page: Page): Locator {
  // Rows are <button aria-pressed> inside the list column; scope to the list header's sibling area via role.
  return page.locator('button[aria-pressed]').filter({ hasText: "→" });
}

test.describe("Attack Graph", () => {
  test("renders ranked paths + stat strip counts, and calls attack-paths with ns/range", async ({ page }) => {
    // Backend assert: the fetch must carry ns + range query params.
    const pathsReq = page.waitForRequest(
      (r) => r.url().includes("/api/v1/threats/attack-paths") && /[?&]ns=/.test(r.url()) && /[?&]range=/.test(r.url())
    );
    await gotoAttackGraph(page);
    const req = await pathsReq;
    expect(req.url()).toMatch(/[?&]ns=/);
    expect(req.url()).toMatch(/[?&]range=/);

    // >= 1 ranked row.
    const rows = pathRows(page);
    const n = await rows.count();
    test.skip(n === 0, "No attack paths stored in the served namespace — cannot assert the ranked list. BEST-EFFORT.");
    expect(n).toBeGreaterThanOrEqual(1);

    // Stat strip shows the six labeled counters.
    for (const label of ["Critical paths", "High", "Chokepoints", "Max blast radius", "Exploitable", "Blocked"]) {
      await expect(page.getByText(label, { exact: true }).first()).toBeVisible();
    }
  });

  test("REGRESSION: kill-chain is HORIZONTAL (x-spread >> y-spread) and the canvas is not clipped", async ({ page }) => {
    await gotoAttackGraph(page);
    test.skip((await pathRows(page).count()) === 0, "No paths — cannot inspect chain layout. BEST-EFFORT.");

    // Read the rendered chain-node transforms. Nodes are laid out at increasing x, constant y → a row.
    const coords = await page.getByTestId(CANVAS).evaluate((svg) => {
      const nodes = Array.from(svg.querySelectorAll<SVGGElement>("g.ak-node"));
      return nodes.map((g) => {
        const t = g.getAttribute("transform") || "";
        const m = /translate\(([-\d.]+)\s*,\s*([-\d.]+)\)/.exec(t);
        return m ? { x: parseFloat(m[1]), y: parseFloat(m[2]) } : null;
      }).filter(Boolean) as Array<{ x: number; y: number }>;
    });
    test.skip(coords.length < 2, "Selected path has < 2 chain nodes — horizontality is trivial. BEST-EFFORT.");
    const xs = coords.map((c) => c.x);
    const ys = coords.map((c) => c.y);
    const xSpread = Math.max(...xs) - Math.min(...xs);
    const ySpread = Math.max(...ys) - Math.min(...ys);
    // Horizontal kill-chain: the chain fans left→right, nodes share a baseline (y-spread ~0).
    expect(xSpread).toBeGreaterThan(ySpread * 3 + 1);

    // Not clipped: the svg carries a viewBox (native letterbox fit) and its container has no horizontal
    // scrollbar (scrollWidth <= clientWidth + slack).
    const hasViewBox = await page.getByTestId(CANVAS).evaluate((svg) => !!svg.getAttribute("viewBox"));
    expect(hasViewBox).toBe(true);
    const canvasContainer = page.getByTestId(CANVAS).locator("xpath=..");
    const noHScroll = await canvasContainer.evaluate((el) => el.scrollWidth <= el.clientWidth + 2);
    expect(noHScroll).toBe(true);
  });

  test("REGRESSION: node labels are NORMAL weight (font-weight <= 550, not 700)", async ({ page }) => {
    await gotoAttackGraph(page);
    test.skip((await pathRows(page).count()) === 0, "No paths — no labels to weigh. BEST-EFFORT.");
    const weights = await page.getByTestId(CANVAS).evaluate((svg) => {
      const labels = Array.from(svg.querySelectorAll<SVGTextElement>("text.lbl"));
      return labels.map((el) => parseInt(getComputedStyle(el).fontWeight || "400", 10));
    });
    test.skip(weights.length === 0, "No rendered chain labels. BEST-EFFORT.");
    for (const w of weights) expect(w).toBeLessThanOrEqual(550);
  });

  test("REGRESSION: neither the path list nor the inspector has an inner scrollbar", async ({ page }) => {
    await gotoAttackGraph(page);
    test.skip((await pathRows(page).count()) === 0, "No paths — list/inspector not rendered. BEST-EFFORT.");

    // Inspector = role=complementary "Attack path inspector".
    const inspector = page.getByRole("complementary", { name: "Attack path inspector" });
    await expect(inspector).toBeVisible();
    const inspectorNoScroll = await inspector.evaluate((el) => el.scrollHeight <= el.clientHeight + 2);
    expect(inspectorNoScroll).toBe(true);

    // Path-list container: the parent div of the "Attack paths · worst first" header.
    const listContainer = page
      .getByText("Attack paths · worst first")
      .locator("xpath=..");
    const listNoScroll = await listContainer.evaluate((el) => el.scrollHeight <= el.clientHeight + 2);
    expect(listNoScroll).toBe(true);
  });

  test("selecting a path drives the canvas + inspector (MITRE / hops / trust / blast)", async ({ page }) => {
    await gotoAttackGraph(page);
    const rows = pathRows(page);
    test.skip((await rows.count()) === 0, "No paths to select. BEST-EFFORT.");
    await rows.first().click();

    const inspector = page.getByRole("complementary", { name: "Attack path inspector" });
    await expect(inspector).toBeVisible();
    await expect(inspector.getByText(/MITRE/)).toBeVisible();
    await expect(inspector.getByText("Hops", { exact: true })).toBeVisible();
    await expect(inspector.getByText("Min trust", { exact: true })).toBeVisible();
    await expect(inspector.getByText("Blast radius", { exact: true })).toBeVisible();
  });

  test("clicking a node opens the scope card", async ({ page }) => {
    await gotoAttackGraph(page);
    test.skip((await pathRows(page).count()) === 0, "No paths — no nodes. BEST-EFFORT.");
    // Click the first chain node group (agent, source).
    const node = page.getByTestId(CANVAS).locator("g.ak-node").first();
    await expect(node).toBeVisible();
    await node.click({ force: true });
    // Scope card exposes a "Close scope card" button.
    await expect(page.getByRole("button", { name: "Close scope card" })).toBeVisible();
  });

  test("clicking a hop toggles a what-if (the 'what-if block active' pill appears)", async ({ page }) => {
    await gotoAttackGraph(page);
    const rows = pathRows(page);
    test.skip((await rows.count()) === 0, "No paths. BEST-EFFORT.");

    // Prefer the inspector's per-step what-if toggle (deterministic vs clicking an svg hit-line).
    // Select rows until we find one with a togglable (non-blocked) step.
    const count = Math.min(await rows.count(), 8);
    let toggled = false;
    for (let i = 0; i < count; i++) {
      await rows.nth(i).click();
      const toggle = page.getByRole("button", { name: /Block this step \(what-if\)/ }).first();
      if (await toggle.count()) {
        await toggle.click();
        toggled = true;
        break;
      }
    }
    test.skip(!toggled, "No path with a togglable (non-blocked) hop in the top rows. BEST-EFFORT.");
    // The what-if preview pill on the canvas.
    await expect(page.getByText("What-if block active · path neutralized")).toBeVisible();
  });

  // Fix 3 (console-fixes-batch2): DENY-ALL default. The allowlist opens EMPTY — EVERY observed-tool checkbox
  // starts UNCHECKED (positive security: the operator explicitly opts each intended tool in), and the generated
  // policy denies everything for the class (empty allow_names). Rewritten from the OLD normal-tool=CHECKED default.
  test("intent ALLOWLIST BUILDER: opening fires intent-suggest → renders a DENY-ALL checklist (every checkbox unchecked)", async ({ page }) => {
    await gotoAttackGraph(page);
    test.skip((await pathRows(page).count()) === 0, "No paths — the global intent button is disabled. BEST-EFFORT.");

    // Opening the modal MUST fire GET /api/v1/threats/intent-suggest for the active class (ns + cls params).
    const suggestReq = page.waitForRequest(
      (r) => r.url().includes("/api/v1/threats/intent-suggest") && /[?&]ns=/.test(r.url()) && /[?&]cls=/.test(r.url())
    );
    await page.getByRole("button", { name: "Define intended behaviour" }).first().click();
    const modal = page.getByRole("dialog", { name: "Define intended behaviour" });
    await expect(modal).toBeVisible();
    // Grouped-by-class selector (global mode still groups by class).
    await expect(modal.getByText("Agent class · grouped")).toBeVisible();
    const suggest = await suggestReq;
    expect(suggest.url()).toMatch(/[?&]cls=/);

    // The checklist heading is present; wait for the observed-tools load to settle then assert ≥1 checkbox.
    await expect(modal.getByText(/Intended tools/)).toBeVisible();
    const checkboxes = modal.getByRole("checkbox");
    // The suggest may legitimately be empty for a class (no observed tools in 24h) — the modal then shows a
    // default-deny explainer and the checklist is empty. Only assert the checklist shape when tools exist.
    const n = await checkboxes.count();
    test.skip(n === 0, "intent-suggest returned no observed tools for the active class — checklist is empty (default-deny explainer shown). BEST-EFFORT.");
    expect(n).toBeGreaterThanOrEqual(1);

    // DENY-ALL default (Fix 3): EVERY tool checkbox defaults UNCHECKED — no tool (normal, chokepoint, or egress)
    // is pre-allowed. Assert ALL of them are unchecked, not just the chokepoint rows.
    for (let i = 0; i < n; i++) {
      await expect(checkboxes.nth(i)).not.toBeChecked();
    }

    // A chokepoint tool, when present, is still FLAGGED (⚠ reached … via … — intended?) — the flag is retained.
    const chokeChip = modal.getByText("chokepoint", { exact: true });
    if (await chokeChip.count()) {
      await expect(modal.getByText(/reached .* via .* — intended\?/).first()).toBeVisible();
    }

    // The generated policy panel proves the DENY-ALL default: an EMPTY allow set (allow_names := {} or set())
    // — i.e. it denies everything for the class until a tool is checked. Wait for the initial coverage
    // round-trip to render the block-default rule; the empty-allow shape is tolerant of {} vs set().
    const regoPre = modal.locator("pre");
    await expect(modal.getByText(/default decision = "block"/)).toBeVisible();
    const regoText = (await regoPre.innerText()).replace(/\s+/g, " ");
    expect(regoText).toMatch(/allow_names\s*:?=?\s*(\{\s*\}|set\(\s*\))/);
  });

  // Fix 3 (console-fixes-batch2): from the DENY-ALL empty default, CHECKING a tool must ADD it to the next
  // intent-coverage POST's allow_tools AND surface it in the generated rego's allow_names. Rewritten from the
  // OLD "flip whatever-default" test (which assumed some tools start checked).
  test("intent ALLOWLIST BUILDER: checking a tool ADDS it to allow_tools + allow_names (from the empty default)", async ({ page }) => {
    await gotoAttackGraph(page);
    test.skip((await pathRows(page).count()) === 0, "No paths — cannot open builder. BEST-EFFORT.");

    await page.getByRole("button", { name: "Define intended behaviour" }).first().click();
    const modal = page.getByRole("dialog", { name: "Define intended behaviour" });
    await expect(modal).toBeVisible();
    await expect(modal.getByText(/Intended tools/)).toBeVisible();

    const checkboxes = modal.getByRole("checkbox");
    const n = await checkboxes.count();
    test.skip(n === 0, "intent-suggest returned no observed tools — no checkbox to toggle. BEST-EFFORT.");

    // DENY-ALL default: the first checkbox starts UNCHECKED. Capture its tool name (aria-label "Intended: <name>").
    const first = checkboxes.first();
    await expect(first).not.toBeChecked();
    const toolName = ((await first.getAttribute("aria-label")) || "").replace(/^Intended:\s*/i, "").trim();
    expect(toolName.length).toBeGreaterThan(0);

    // Capture the body of the NEXT coverage POST triggered by CHECKING the tool.
    const coverageReq = page.waitForRequest(
      (r) => r.url().includes("/api/v1/threats/intent-coverage") && r.method() === "POST"
    );
    await first.click({ force: true });
    expect(await first.isChecked()).toBe(true);
    const req = await coverageReq;
    const body = req.postDataJSON() as { allow_tools?: string[]; intent?: Record<string, boolean> };
    expect(Array.isArray(body.allow_tools)).toBe(true);
    // The newly-checked tool must be in the POSTed allow_tools (deny-all → opt-in adds it).
    expect(body.allow_tools).toContain(toolName);
    // And allow_tools equals the live checked set (exactly the ones the operator opted in).
    const checkedNames = await modal.evaluate((root) =>
      Array.from(root.querySelectorAll<HTMLInputElement>('input[type="checkbox"]'))
        .filter((c) => c.checked)
        .map((c) => (c.getAttribute("aria-label") || "").replace(/^Intended:\s*/i, "").trim())
        .filter(Boolean)
    );
    expect([...(body.allow_tools ?? [])].sort()).toEqual([...checkedNames].sort());

    // The generated-rego panel now names the checked tool in allow_names.
    await expect(modal.getByText(/default decision = "block"/)).toBeVisible();
    await expect(modal.locator("pre")).toContainText(toolName);
  });

  // Fix 2 (console-fixes-batch2): coverage denominator is PER-CLASS, not over ALL classes' paths. The modal's
  // grouped class selector shows "<N> paths" for the SELECTED class; the coverage total must equal THAT N (the
  // backend returns the class's path count), NOT the global total. Rewritten from the OLD "denom == total
  // visible paths" behaviour. Also asserts the per-class note ("Other classes each need their own intent policy").
  test("intent ALLOWLIST BUILDER: coverage total is PER-CLASS (== the selected class's path count)", async ({ page }) => {
    await gotoAttackGraph(page);
    test.skip((await pathRows(page).count()) === 0, "No paths — cannot open builder. BEST-EFFORT.");

    // The GLOBAL panel-head total, over ALL visible paths across ALL classes.
    const subText = await page.getByText(/attack paths · precomputed from the runtime asset graph/).innerText();
    const globalTotal = parseInt((subText.match(/(\d+)\s+attack paths/) || [])[1] ?? "0", 10);
    expect(globalTotal).toBeGreaterThan(0);

    await page.getByRole("button", { name: "Define intended behaviour" }).first().click();
    const modal = page.getByRole("dialog", { name: "Define intended behaviour" });
    await expect(modal).toBeVisible();
    await expect(modal.getByText(/Intended tools/)).toBeVisible();

    // The grouped class selector shows the SELECTED class's own path count as "<N> paths". Read that N.
    const clsCountText = await modal.getByText(/^\d+\s+paths$/).first().innerText();
    const classPaths = parseInt((clsCountText.match(/(\d+)/) || [])[1] ?? "0", 10);
    test.skip(classPaths === 0, "Selected class reported 0 paths in the grouped selector. BEST-EFFORT.");

    // The coverage read-out (covered/total). Fix 2: the denominator is the SELECTED class's path count.
    const readout = modal.locator("text=/^\\d+\\/\\d+$/").first();
    await expect(readout).toBeVisible();
    // Wait for the coverage round-trip to reflect the per-class total (it may briefly seed from paths.length).
    await expect
      .poll(async () => parseInt((await readout.innerText()).split("/")[1], 10), { timeout: 15_000 })
      .toBe(classPaths);
    const denom = parseInt((await readout.innerText()).split("/")[1], 10);
    expect(denom).toBe(classPaths);
    // Per-class coverage is a subset of the global total (a single class never spans every class's paths, unless
    // there's only one class — hence <=, not <).
    expect(denom).toBeLessThanOrEqual(globalTotal);

    // The per-class scoping note is present (Fix 2): other classes each need their own intent policy.
    await expect(modal.getByText(/Other classes each need their own intent policy/)).toBeVisible();

    // Changing the allowlist re-runs coverage: flip a refinement toggle (always present) and confirm a POST.
    const coverageReq = page.waitForRequest(
      (r) => r.url().includes("/api/v1/threats/intent-coverage") && r.method() === "POST"
    );
    await modal.getByRole("button", { name: /Read-only/ }).click();
    await coverageReq;
    // The read-out still renders a valid n/total after the update, and the total stays the per-class denominator.
    await expect(readout).toBeVisible();
    expect(parseInt((await readout.innerText()).split("/")[1], 10)).toBe(classPaths);
  });

  test("Apply intent policy → intent-draft (allow_tools body) → deep-link into /policies/catalog (visible dry-run row)", async ({ page }) => {
    await gotoAttackGraph(page);
    test.skip((await pathRows(page).count()) === 0, "No paths — cannot draft. BEST-EFFORT.");

    await page.getByRole("button", { name: "Define intended behaviour" }).first().click();
    const modal = page.getByRole("dialog", { name: "Define intended behaviour" });
    await expect(modal).toBeVisible();
    await expect(modal.getByText(/Intended tools/)).toBeVisible();

    // Enable a refinement toggle so Apply is enabled regardless of the seeded checklist defaults, and wait
    // for the coverage round-trip to settle.
    const coverageReq = page.waitForRequest(
      (r) => r.url().includes("/api/v1/threats/intent-coverage") && r.method() === "POST"
    );
    await modal.getByRole("button", { name: /Read-only/ }).click();
    await coverageReq;

    // Apply → POST intent-draft; capture its body and assert allow_tools is carried.
    const draftReq = page.waitForRequest(
      (r) => r.url().includes("/api/v1/threats/intent-draft") && r.method() === "POST"
    );
    await modal.getByRole("button", { name: "Apply intent policy" }).click();
    const req = await draftReq;
    const body = req.postDataJSON() as { allow_tools?: string[] };
    // allow_tools is always present in the draft body (may be [] if the class had no observed tools + only
    // toggles were used) — assert the key exists and is an array.
    expect(Array.isArray(body.allow_tools)).toBe(true);

    // Confirmation button deep-links to /policies/catalog?intent_draft=<id>.
    const confirm = modal.getByRole("button", { name: /Draft created · dry-run in Policies/ });
    await expect(confirm).toBeVisible();
    await confirm.click();

    // We land on the catalog with the deep-link param and a visible, dry-run-labeled draft row.
    await expect(page).toHaveURL(/\/policies\/catalog\?.*intent_draft=/);
    await waitForApp(page);
    await expect(page.getByText("Intent drafts · dry-run (not enforcing)")).toBeVisible();
    await expect(page.locator('[data-testid^="intent-draft-"]').first()).toBeVisible();
    await expect(page.getByText(/Dry-run/i).first()).toBeVisible();
  });

  test("Simulate path issues real POST /api/v1/evaluate calls", async ({ page }) => {
    await gotoAttackGraph(page);
    const rows = pathRows(page);
    test.skip((await rows.count()) === 0, "No paths to simulate. BEST-EFFORT.");
    await rows.first().click();

    const evalReq = page.waitForRequest(
      (r) => r.url().includes("/api/v1/evaluate") && r.method() === "POST"
    );
    // The panel-head "Simulate path" button (primary) is always present when a path is selected.
    await page.getByRole("button", { name: "Simulate path" }).click();
    const req = await evalReq;
    const body = req.postDataJSON() as { framework?: string; tool_name?: string };
    // Simulate tags its calls with framework "attack-graph" (so the audit-PEP test can exclude them).
    expect(body.framework).toBe("attack-graph");
    expect(typeof body.tool_name).toBe("string");
  });
});
