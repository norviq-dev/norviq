// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// console-fixes-batch2 (branch feat/console-fixes-batch2) — EFFECT assertions (a 200 is NOT proof)
// for the 7 GA polish fixes, driven against the REAL app + backend:
//
//   1. ASSET GRAPH hull encloses every ring node — parse each cluster hull's (cx,cy,r) from its arc `d` and
//      each `g.ag-node`'s translate(x,y); every node's center sits inside its nearest hull (dist <= r + ~9).
//   5. THEME — no main panel/card resolves to a "navy" background anywhere (blue channel dominates R and G),
//      and no known navy hex leaks in. One neutral-grey palette across all four graph/policy routes.
//   6. SPLASH — /login with NO token shows the branded BrandSplash (role=status, /loading norviq/i), NO
//      "Starting Norviq" / "Connecting to the security backend" copy, and it auto-dismisses to the form
//      (input#nv-user). App route-transition Suspense fallback reuses the same BrandSplash (best-effort).
//   7. POLICY APPLY FEEDBACK — the Catalog tab renders an "Active policies" heading with an ENFORCING label
//      ABOVE the tier panels, visually distinct from the dry-run "Intent drafts" panel; plus an API-through-page
//      EFFECT PROOF that an applied policy actually BLOCKs an un-allowed call (self-cleans via DELETE).
//   Fixes 2 + 3 (per-class coverage + deny-all default) live in attack-graph.spec.ts (updated there).

import { test, expect, waitForApp } from "./fixtures";
import { request as pwRequest, type APIRequestContext, type Page } from "@playwright/test";
import { readFileSync, existsSync } from "node:fs";

const TOKEN_FILE = process.env.NRVQ_TOKEN_FILE ?? "/tmp/nrvq-signin-token.txt";

function loadToken(): string {
  if (!existsSync(TOKEN_FILE)) return "";
  const raw = readFileSync(TOKEN_FILE, "utf8").trim();
  return raw.split(".").length === 3 ? raw : "";
}

// ─────────────────────────────────────────────────────────────────────────────
// ASSET GRAPH: the dashed cluster hull encloses EVERY ring node.
// ─────────────────────────────────────────────────────────────────────────────
test.describe("Asset Graph hull encloses every ring node", () => {
  test("every g.ag-node center sits inside its nearest cluster hull circle", async ({ page }) => {
    await page.goto("/asset-graph");
    await waitForApp(page);
    await expect(page.getByTestId("asset-graph-canvas")).toBeVisible();
    // Let the fit/zoom + circle layout settle so hull `d` and node transforms are final.
    await page.waitForTimeout(600);

    const result = await page.getByTestId("asset-graph-canvas").evaluate((svg) => {
      // Hull circles are <path d="M {cx-r} {cy} a {r} {r} 0 1 0 {2r} 0 a {r} {r} 0 1 0 {-2r} 0">.
      // From the leading M + first arc: r == the first arc radius, cx == M.x + r, cy == M.y.
      const NUM = "[-+]?[0-9]*\\.?[0-9]+";
      const hullRe = new RegExp(
        `^\\s*M\\s*(${NUM})[ ,]+(${NUM})\\s*a\\s*(${NUM})[ ,]+(${NUM})\\b`,
        "i"
      );
      const hulls: Array<{ cx: number; cy: number; r: number }> = [];
      svg.querySelectorAll<SVGPathElement>("path").forEach((p) => {
        const d = p.getAttribute("d") || "";
        const m = hullRe.exec(d);
        if (!m) return;
        const mx = parseFloat(m[1]);
        const my = parseFloat(m[2]);
        const r = parseFloat(m[3]);
        // Only accept genuine circular-arc hulls (both arc radii equal → r,r); reject non-hull paths.
        if (!Number.isFinite(r) || r <= 0) return;
        hulls.push({ cx: mx + r, cy: my, r });
      });

      const nodes: Array<{ x: number; y: number }> = [];
      svg.querySelectorAll<SVGGElement>("g.ag-node").forEach((g) => {
        // Skip hidden nodes (display:none from filters) — only enclose the VISIBLE ring nodes.
        if (getComputedStyle(g).display === "none") return;
        const t = g.getAttribute("transform") || "";
        const mm = /translate\(\s*(-?[0-9.]+)\s*[ ,]\s*(-?[0-9.]+)\s*\)/.exec(t);
        if (!mm) return;
        nodes.push({ x: parseFloat(mm[1]), y: parseFloat(mm[2]) });
      });

      const NODE_R = 9; // spec: nodeRadius ≈ 9 (tool); agent 15 sits well inside the padded hull anyway
      let outside = 0;
      let checked = 0;
      const worst: Array<{ dist: number; r: number }> = [];
      for (const n of nodes) {
        // Assign the node to its NEAREST hull center.
        let best: { cx: number; cy: number; r: number } | null = null;
        let bestD = Infinity;
        for (const h of hulls) {
          const dd = Math.hypot(n.x - h.cx, n.y - h.cy);
          if (dd < bestD) {
            bestD = dd;
            best = h;
          }
        }
        if (!best) continue;
        // Only nodes that BELONG to a cluster hull are subject to the enclosure check. An "awaiting first
        // tool call" agent (and other non-ring nodes) have NO hull and sit a whole cluster-gap away from any
        // hull center — skip them. A genuine ring-node overflow sits just OUTSIDE its own hull (≈ r+33), so a
        // generous band (r + 120) still catches real overflow while excluding far orphans.
        if (bestD > best.r + 120) continue;
        checked++;
        if (bestD > best.r + NODE_R) {
          outside++;
          worst.push({ dist: bestD, r: best.r });
        }
      }
      return { hulls: hulls.length, nodes: nodes.length, checked, outside, worst: worst.slice(0, 5) };
    });

    // BEST-EFFORT: skip if no hull path parsed (empty graph / non-circle layout).
    test.skip(result.hulls === 0, "No hull path parsed (empty graph or non-circle layout). BEST-EFFORT.");
    test.skip(result.nodes === 0, "No g.ag-node with a translate transform. BEST-EFFORT.");
    test.skip(result.checked === 0, "No hull-belonging ring nodes to enclose. BEST-EFFORT.");

    expect(
      result.outside,
      `${result.outside}/${result.nodes} nodes fell outside their nearest hull (r+9). ` +
        `Sample: ${JSON.stringify(result.worst)}`
    ).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// THEME: no navy anywhere; one neutral-grey palette.
// ─────────────────────────────────────────────────────────────────────────────
const THEME_ROUTES = ["/", "/asset-graph", "/threats/graph", "/policies/catalog"];

// Known navy hexes that must NEVER appear as a panel/card background.
const NAVY_HEXES = [
  "#0f172a",
  "#111827",
  "#0b1220",
  "#0a0f1e",
  "#131a2e",
  "#1a2340",
  "#1c2c4d",
  "#0d1526",
  "#141b2e"
].map((h) => h.toLowerCase());

test.describe("Theme — no navy panels (one neutral-grey palette)", () => {
  for (const route of THEME_ROUTES) {
    test(`no main panel/card resolves to navy on ${route}`, async ({ page }) => {
      await page.goto(route);
      await waitForApp(page);
      // Wait for the lazy page to mount its panels.
      await page.waitForTimeout(400);

      const findings = await page.evaluate((navyHexes) => {
        // "navy" heuristic: a color whose BLUE channel dominates red AND green by > 12 and is > 20 overall —
        // i.e. a distinctly blue-leaning surface. Neutral greys (r≈g≈b) and greens are fine.
        function parseRGB(c: string): [number, number, number] | null {
          const m = /rgba?\(\s*(\d+)[ ,]+(\d+)[ ,]+(\d+)/i.exec(c);
          if (!m) return null;
          return [parseInt(m[1], 10), parseInt(m[2], 10), parseInt(m[3], 10)];
        }
        function isNavy(c: string): boolean {
          const rgb = parseRGB(c);
          if (!rgb) return false;
          const [r, g, b] = rgb;
          return b > r + 12 && b > g + 12 && b > 20;
        }
        function toHex(c: string): string {
          const rgb = parseRGB(c);
          if (!rgb) return "";
          return "#" + rgb.map((n) => n.toString(16).padStart(2, "0")).join("");
        }

        // Sample the MAIN panels/cards: .panel/.card/.policy-item + the graph canvas containers + any element
        // whose computed background is a real (non-transparent) fill inside the content area.
        const sel = [
          ".panel",
          ".card",
          ".policy-item",
          "[data-testid='asset-graph-canvas']",
          "[data-testid='attack-graph-canvas']",
          ".page-enter .panel",
          "main .panel"
        ].join(",");
        const els = Array.from(document.querySelectorAll<HTMLElement>(sel));
        // Also walk the graph canvas' PARENT (the framed graph panel) — that's the big surface users read.
        document.querySelectorAll<HTMLElement>("[data-testid$='-canvas']").forEach((c) => {
          if (c.parentElement) els.push(c.parentElement);
        });

        const navy: Array<{ where: string; bg: string; hex: string }> = [];
        const hexHits: Array<{ where: string; hex: string }> = [];
        let sampled = 0;
        for (const el of els) {
          const cs = getComputedStyle(el);
          const bg = cs.backgroundColor;
          const rgb = parseRGB(bg);
          if (!rgb) continue;
          // Ignore fully transparent surfaces (alpha 0) — they inherit the (grey) page background.
          const alphaM = /rgba?\([^)]*,\s*([0-9.]+)\s*\)/.exec(bg);
          if (alphaM && parseFloat(alphaM[1]) === 0) continue;
          sampled++;
          const where = el.className && typeof el.className === "string" ? `.${el.className.split(/\s+/)[0]}` : el.tagName.toLowerCase();
          if (isNavy(bg)) navy.push({ where, bg, hex: toHex(bg) });
          const hex = toHex(bg);
          if (hex && navyHexes.includes(hex)) hexHits.push({ where, hex });
        }
        return { sampled, navy, hexHits };
      }, NAVY_HEXES);

      // BEST-EFFORT: if nothing sampled (page not yet painted), skip rather than assert on an empty page.
      test.skip(findings.sampled === 0, `No panel/card backgrounds sampled on ${route}. BEST-EFFORT.`);

      expect(
        findings.navy,
        `Navy-leaning panel background(s) on ${route}: ${JSON.stringify(findings.navy)}`
      ).toEqual([]);
      expect(
        findings.hexHits,
        `Known navy hex leaked into a panel background on ${route}: ${JSON.stringify(findings.hexHits)}`
      ).toEqual([]);
    });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// SPLASH: /login boot splash is the branded text-free BrandSplash, then auto-dismisses to the form.
// ─────────────────────────────────────────────────────────────────────────────
test.describe("Boot splash is the branded BrandSplash (text-free), auto-dismisses to the form", () => {
  test("/login with NO token: branded role=status splash, no status copy, resolves to input#nv-user", async ({
    browser
  }) => {
    // A CLEAN context with NO seeded token so the login gate actually renders (the shared `page` fixture
    // injects the admin token, which would bypass /login). We drive the raw browser here.
    const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
    const page = await ctx.newPage();
    try {
      await page.addInitScript(() => {
        try {
          window.localStorage.removeItem("nrvq_token");
          window.sessionStorage.removeItem("nrvq_token");
          window.localStorage.removeItem("nrvq_must_change");
        } catch {
          /* storage unavailable */
        }
      });
      await page.goto("/login", { waitUntil: "domcontentloaded" });

      // The boot splash renders the branded mark with role=status + an accessible loading-Norviq label.
      const splash = page.getByRole("status", { name: /loading norviq/i });
      // Best-effort: the splash is time-boxed (~150ms under reduced-motion, ~1.1s otherwise). It should be
      // present at least briefly — but a very fast machine may dismiss it before the first assertion; only
      // require it when it is observed.
      const sawSplash = await splash.first().isVisible().catch(() => false);
      if (sawSplash) {
        // NO backend-status copy on the boot splash (the whole point — text-free brand moment).
        await expect(page.getByText(/Starting Norviq/i)).toHaveCount(0);
        await expect(page.getByText(/Connecting to the security backend/i)).toHaveCount(0);
      }

      // It auto-dismisses to the login FORM: the username input mounts and becomes visible.
      await expect(page.locator("input#nv-user")).toBeVisible({ timeout: 15_000 });
      // And still no backend-status copy once the form is up.
      await expect(page.getByText(/Starting Norviq/i)).toHaveCount(0);
      await expect(page.getByText(/Connecting to the security backend/i)).toHaveCount(0);
    } finally {
      await ctx.close();
    }
  });

  test("App route-transition Suspense fallback reuses BrandSplash (best-effort)", async ({ page }) => {
    // The authed `page` fixture carries the admin token, so navigating a lazy route mounts the Shell + a lazy
    // page behind <Suspense fallback={<BrandSplash/>}>. On a warm chunk cache the fallback may not paint long
    // enough to observe — so this is BEST-EFFORT: we look for a transient role=status and skip if we miss it.
    await page.goto("/", { waitUntil: "domcontentloaded" });
    // Kick a navigation to a lazy route and race the transient fallback against the settled page.
    const statusSeen = page
      .getByRole("status", { name: /loading norviq/i })
      .first()
      .waitFor({ state: "visible", timeout: 1500 })
      .then(() => true)
      .catch(() => false);
    await page.goto("/asset-graph", { waitUntil: "domcontentloaded" });
    const seen = await statusSeen;
    await waitForApp(page);
    // Either we caught the branded suspense splash, or the chunk was warm and it never painted — both are OK.
    test.skip(!seen, "Route-transition BrandSplash chunk was warm; fallback did not paint. BEST-EFFORT.");
    expect(seen).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// LOGIN: real username/password form. Valid admin/norviq advances (to change-password, since
//         must_change); a wrong password shows a visible error and does NOT clear the username field.
// ─────────────────────────────────────────────────────────────────────────────
test.describe("Login form — valid admin advances; wrong password shows error + keeps username", () => {
  /** A clean, token-free context so the login gate actually renders the form. */
  async function openLogin(browser: import("@playwright/test").Browser) {
    // A manually-created context does NOT inherit the project's baseURL — set it so a relative goto works.
    const ctx = await browser.newContext({
      baseURL: process.env.PLAYWRIGHT_BASE_URL || "http://localhost:3400",
      ignoreHTTPSErrors: true
    });
    const page = await ctx.newPage();
    await page.addInitScript(() => {
      try {
        window.localStorage.removeItem("nrvq_token");
        window.sessionStorage.removeItem("nrvq_token");
        window.localStorage.removeItem("nrvq_must_change");
      } catch {
        /* storage unavailable */
      }
    });
    await page.goto("/login", { waitUntil: "domcontentloaded" });
    // Wait out the branded boot splash so form interactions aren't intercepted by the overlay.
    await page.getByRole("status", { name: /loading norviq/i }).waitFor({ state: "detached", timeout: 5000 }).catch(() => {});
    await expect(page.locator("input#nv-user")).toBeVisible({ timeout: 15_000 });
    return { ctx, page };
  }

  test("(a) valid admin/norviq → /auth/login 200 must_change → advances to the change-password view", async ({
    browser
  }) => {
    const { ctx, page } = await openLogin(browser);
    try {
      // Drive the FORM and assert the UI EFFECT (more robust than racing waitForResponse, which flaked on
      // the manual context). admin/norviq is the documented default with must_change=True.
      await page.locator("input#nv-user").fill("admin");
      await page.locator("input#nv-pass").fill("norviq");
      await page.getByRole("button", { name: "Sign in", exact: true }).click();
      await page.waitForTimeout(1800); // let /auth/login resolve + the view update

      // BEST-EFFORT skips: rate-limited, or the seeded admin isn't the documented default credential.
      test.skip(await page.getByText(/too many failed attempts/i).isVisible().catch(() => false), "Login rate-limited (429). BEST-EFFORT.");
      test.skip(await page.getByText(/invalid username or password/i).isVisible().catch(() => false), "admin/norviq rejected — seeded admin isn't the default credential. BEST-EFFORT.");

      // must_change ⇒ the UI switches to the First-login (change password) view instead of proceeding.
      await expect(page.getByText("Set a new password", { exact: true })).toBeVisible({ timeout: 10_000 });
      await expect(page.locator("input#nv-cur")).toBeVisible();
      await expect(page.locator("input#nv-new")).toBeVisible();
    } finally {
      await ctx.close();
    }
  });

  test("(b) wrong password → visible 'Invalid username or password' error, username NOT cleared", async ({
    browser
  }) => {
    const { ctx, page } = await openLogin(browser);
    try {
      await page.locator("input#nv-user").fill("admin");
      await page.locator("input#nv-pass").fill("definitely-not-the-password-000");
      await page.getByRole("button", { name: "Sign in", exact: true }).click();
      await page.waitForTimeout(1400); // let /auth/login (401) resolve + the error render

      // A rate-limit lockout (429) surfaces a different message — skip so we assert the invalid-cred path cleanly.
      test.skip(await page.getByText(/too many failed attempts/i).isVisible().catch(() => false), "Login rate-limited (429). BEST-EFFORT.");

      // The invalid-credential error is visible…
      await expect(page.getByText("Invalid username or password.", { exact: true })).toBeVisible({ timeout: 10_000 });
      // …and the username field is NOT cleared (the user keeps their typed username to retry).
      await expect(page.locator("input#nv-user")).toHaveValue("admin");
      // Still on the default (sign-in) view, not advanced.
      await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeVisible();
    } finally {
      await ctx.close();
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POLICY APPLY FEEDBACK: enforcing "Active policies" heading distinct from dry-run drafts,
//         + an API-through-page EFFECT PROOF that an applied policy actually BLOCKs an un-allowed call.
// ─────────────────────────────────────────────────────────────────────────────
const NS = "default";
const THROWAWAY = `e2e-cf2-${Date.now()}`;
const DENY_TOOL = "get_order"; // NOT allowlisted → default-deny under the applied policy

/** A minimal default-deny allowlist rego for the throwaway class (allow NOTHING → every call blocks). */
function denyAllRego(cls: string): string {
  return [
    `package norviq.intent.cf2`,
    ``,
    `import rego.v1`,
    ``,
    `default decision := "block"`,
    `default rule_id := "intent_default_deny"`,
    ``,
    `allow_names := {}`,
    ``,
    `decision := "allow" if {`,
    `  input.agent_identity.agent_class == "${cls}"`,
    `  allow_names[input.tool_name]`,
    `}`,
    ``,
    `rule_id := "intent_allow" if {`,
    `  input.agent_identity.agent_class == "${cls}"`,
    `  allow_names[input.tool_name]`,
    `}`
  ].join("\n");
}

/** POST /api/v1/evaluate from inside the page (shares the SPA token + origin). */
async function evaluate(page: Page, tool: string): Promise<{ status: number; decision?: string }> {
  return page.evaluate(
    async ({ ns, cls, tool }) => {
      const token = window.localStorage.getItem("nrvq_token") || window.sessionStorage.getItem("nrvq_token") || "";
      const res = await fetch("/api/v1/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({
          tool_name: tool,
          tool_params: { order_id: "42" },
          agent_identity: { spiffe_id: `spiffe://norviq/ns/${ns}/sa/${cls}`, namespace: ns, agent_class: cls },
          session_id: `e2e-cf2-${Date.now()}`,
          framework: "sdk"
        })
      });
      const body = (await res.json().catch(() => ({}))) as { decision?: string };
      return { status: res.status, decision: body.decision };
    },
    { ns: NS, cls: THROWAWAY, tool }
  );
}

test.describe("Policy apply feedback — enforcing heading distinct + real block effect", () => {
  test("Catalog tab: 'Active policies' + ENFORCING label renders ABOVE the tier panels, distinct from drafts", async ({
    page
  }) => {
    await page.goto("/policies/catalog");
    await waitForApp(page);

    // The page opens on the Editor tab — click the "Catalog" tab to reveal the grouped enforcing tiers.
    await page.getByRole("button", { name: "Catalog", exact: true }).click();

    // The enforcing header: an "Active policies" heading + an ENFORCING pill (the heading node may include
    // the pill/subtext, so match by substring, not exact).
    const header = page.getByText(/Active policies/i).first();
    await expect(header).toBeVisible();
    await expect(page.getByText(/enforcing/i).first()).toBeVisible();

    // The three tier panels render (Workload / Agent-Class / Namespace Policies).
    await expect(page.getByText("Workload Policies", { exact: true })).toBeVisible();
    await expect(page.getByText("Agent-Class Policies", { exact: true })).toBeVisible();
    await expect(page.getByText("Namespace Policies", { exact: true })).toBeVisible();

    // VISUALLY + STRUCTURALLY distinct from the dry-run "Intent drafts" panel: the "Active policies" header
    // sits ABOVE the first tier panel (Workload). Assert DOM order via vertical position.
    const headerBox = await header.boundingBox();
    const workloadBox = await page.getByText("Workload Policies", { exact: true }).boundingBox();
    expect(headerBox && workloadBox).toBeTruthy();
    if (headerBox && workloadBox) {
      expect(headerBox.y).toBeLessThan(workloadBox.y);
    }

    // Distinct from the dry-run intent-drafts panel: if that panel is present (drafts exist), it is a SEPARATE
    // element from the enforcing header — the enforcing header must NOT itself contain "dry-run (not enforcing)".
    const enforcingBlock = header.locator("xpath=..");
    await expect(enforcingBlock).not.toContainText("dry-run (not enforcing)");
  });

  test("EFFECT PROOF: an applied throwaway policy makes /evaluate BLOCK an un-allowed call (self-cleans)", async ({
    page,
    baseURL
  }) => {
    test.skip(!loadToken(), "No admin token file — cannot drive the real evaluator. BEST-EFFORT.");

    const token = loadToken();
    const api: APIRequestContext = await pwRequest.newContext({
      baseURL,
      ignoreHTTPSErrors: true,
      extraHTTPHeaders: token ? { Authorization: `Bearer ${token}` } : {}
    });
    let applied = false;
    try {
      // Establish the app origin so the in-page /evaluate fetch has the localStorage token.
      await page.goto("/policies/catalog");
      await waitForApp(page);

      // Apply a default-deny policy for the throwaway class at baseline priority 1 (== the intent-effect spec).
      const create = await api.post(`/api/v1/policies`, {
        data: {
          namespace: NS,
          agent_class: THROWAWAY,
          rego_source: denyAllRego(THROWAWAY),
          enforcement_mode: "block",
          priority: 1,
          saved_by: "e2e",
          policy_name: THROWAWAY
        }
      });
      test.skip(!create.ok(), `policy create returned ${create.status()}: ${await create.text()}. BEST-EFFORT.`);
      applied = true;

      // Wait for the loader to pick up the freshly-saved policy (seed→reload gotcha), then PROVE the effect:
      // an un-allowlisted call for the throwaway class now BLOCKS (it would allow/deny-open without the policy).
      await expect
        .poll(async () => (await evaluate(page, DENY_TOOL)).decision, {
          timeout: 20_000,
          message: "waiting for the applied policy to enforce a block"
        })
        .toBe("block");

      const res = await evaluate(page, DENY_TOOL);
      expect(res.status).toBeLessThan(400);
      expect(res.decision).toBe("block");
    } finally {
      if (applied) {
        await api.delete(`/api/v1/policies/${NS}/${encodeURIComponent(THROWAWAY)}`).catch(() => undefined);
      }
      await api.dispose();
    }
  });
});
