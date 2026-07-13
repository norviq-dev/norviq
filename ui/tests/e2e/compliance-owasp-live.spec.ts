// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// OWASP-LIVE E2E. Drives the REAL SPA + API on the live kind cluster and asserts the EFFECT that OWASP LLM Top 10
// (2025) is a SECOND live, switchable framework alongside MITRE ATLAS — NOT a mock. Every assertion is anchored to a
// DIRECT ?framework= API call: the no-mock guard proves each card's donut label equals its own coverage endpoint, the
// OWASP enforced/gap split is the REAL loaded-rego computation (4 enforced / 6 enforceable, LLM07/LLM10 gaps, 4 OOS —
// not the design's illustrative numbers), the switcher opens the OWASP detail, an OWASP GAP → generate makes a real
// dry-run draft, export streams a real OWASP pack, and both live cards render a non-empty emblem.

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

async function api(page: Page, path: string): Promise<{ status: number; body: any }> {
  return page.evaluate(async (path) => {
    const token = localStorage.getItem("nrvq_token");
    const res = await fetch(path, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, path);
}
async function apiPost(page: Page, path: string, payload: unknown) {
  return page.evaluate(async ({ path, payload }) => {
    const token = localStorage.getItem("nrvq_token");
    const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(payload) });
    return { status: res.status, body: await res.json().catch(() => null) };
  }, { path, payload });
}

test.describe("OWASP LLM as a 2nd LIVE framework — EFFECT proofs on the live console", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
  });

  test("P1 real-rego: OWASP coverage is computed from the loaded rego, not the mock (4/6=67%, LLM07/LLM10 gaps, 4 OOS)", async ({ page }) => {
    const cov = await api(page, "/api/v1/mitre/coverage?range=24h&framework=owasp");
    expect(cov.status).toBe(200);
    expect(cov.body.framework).toBe("owasp");
    // The honest, real-rego split — NOT the design's illustrative 5/enforced.
    expect(cov.body.enforced).toBe(4);
    expect(cov.body.enforceable_total).toBe(6);
    expect(cov.body.gap).toBe(2);
    expect(cov.body.oos).toBe(4);
    expect(cov.body.coverage_pct).toBe(67); // 4/6 rounded
    const byId = Object.fromEntries((cov.body.techniques as any[]).map((t) => [t.technique_id, t]));
    // The two enforceable-but-unloaded controls are GAPS (honest), not fabricated as "enforced".
    expect(byId["LLM07:2025"].status).toBe("gap");
    expect(byId["LLM10:2025"].status).toBe("gap");
    // A supply-chain / poisoning / embedding / misinformation control is OUT-OF-SCOPE (shown, not counted).
    expect(byId["LLM03:2025"].status).toBe("out_of_scope");
    // A real loaded rule drives an enforced control.
    expect(byId["LLM06:2025"].status).toBe("enforced");
  });

  test("P1 default + unknown: framework defaults to atlas; an unknown framework 404s (no silent fallback)", async ({ page }) => {
    const dflt = await api(page, "/api/v1/mitre/coverage?range=24h");
    expect(dflt.status).toBe(200);
    expect(dflt.body.framework).toBe("atlas");
    const bad = await api(page, "/api/v1/mitre/coverage?range=24h&framework=nope");
    expect(bad.status).toBe(404);
  });

  test("P1 no-mock: BOTH live cards render their OWN coverage % from their OWN endpoint", async ({ page }) => {
    const atlas = await api(page, "/api/v1/mitre/coverage?range=24h&framework=atlas");
    const owasp = await api(page, "/api/v1/mitre/coverage?range=24h&framework=owasp");
    expect(atlas.status).toBe(200);
    expect(owasp.status).toBe(200);
    const aPct = Math.round(atlas.body.coverage_pct);
    const oPct = Math.round(owasp.body.coverage_pct);

    const bad: string[] = [];
    page.on("response", (r) => { if (r.status() >= 400 && r.url().includes("/api/")) bad.push(`${r.status()} ${r.url()}`); });
    await page.goto("/compliance");
    await waitForApp(page);
    await page.waitForTimeout(1500);

    // Each card's donut carries an aria-label `${pct}% of enforceable enforced` — the DISPLAYED value must equal each
    // framework's OWN API call. This is the no-mock guard: the numbers are not fabricated and not shared.
    await expect(page.getByRole("img", { name: new RegExp(`^${aPct}% of enforceable`) }).first()).toBeVisible({ timeout: 8000 });
    await expect(page.getByRole("img", { name: new RegExp(`^${oPct}% of enforceable`) }).first()).toBeVisible();
    // Both framework names present on the overview (two live cards).
    await expect(page.getByText("MITRE ATLAS").first()).toBeVisible();
    await expect(page.getByText(/OWASP LLM Top 10 \(2025\)/).first()).toBeVisible();
    expect(bad, `unexpected 4xx/5xx on /compliance: ${bad.join(", ")}`).toEqual([]);
  });

  test("P2 emblems: each live card + each roadmap row renders a non-empty framework emblem", async ({ page }) => {
    await page.goto("/compliance");
    await waitForApp(page);
    await page.waitForTimeout(1200);
    // Every live framework card renders its emblem (data-testid emblem-<id>), and it is non-empty (has SVG children).
    for (const id of ["atlas", "owasp"]) {
      const emblem = page.locator(`[data-testid="emblem-${id}"]`).first();
      await expect(emblem).toBeVisible();
      expect(await emblem.locator("*").count()).toBeGreaterThan(0);
    }
    // Roadmap rows also render marks (owasp-agentic uses the owasp mark; nist/iso/eu their own).
    for (const id of ["nist", "iso", "eu"]) {
      await expect(page.locator(`[data-testid="emblem-${id}"]`).first()).toBeVisible();
    }
  });

  test("P1 switcher: opening the OWASP card drives the detail view to OWASP (Excessive Agency / LLM06:2025)", async ({ page }) => {
    const owasp = await api(page, "/api/v1/mitre/coverage?range=24h&framework=owasp");
    const enforced = (owasp.body.techniques as any[]).find((t) => t.technique_id === "LLM06:2025");
    expect(enforced.name).toBe("Excessive Agency");

    await page.goto("/compliance");
    await waitForApp(page);
    await page.waitForTimeout(1200);
    // Open the OWASP card's detail (the 2nd "Open coverage detail →" button — atlas card is first, owasp second).
    await page.getByRole("button", { name: /Open coverage detail/i }).nth(1).click();
    // The OWASP-only control name is now in the detail technique tree (ATLAS has no "Excessive Agency" technique)…
    await expect(page.getByText("Excessive Agency").first()).toBeVisible({ timeout: 8000 });
    // …and the selected control's id is OWASP-formatted (LLM0x:2025) — impossible under ATLAS, whose ids are AML.Txxxx.
    await expect(page.getByText(/LLM0\d:2025/).first()).toBeVisible();
    await expect(page.getByText(/AML\.T\d/).first()).toBeVisible(); // shown only as the cross-ref "also …", proving mapping
    // Now click the Excessive Agency row → its own id LLM06:2025 surfaces in the selected panel.
    await page.getByText("Excessive Agency").first().click();
    await expect(page.getByText(/LLM06:2025/).first()).toBeVisible({ timeout: 8000 });
  });

  test("P1 GAP→generate: an OWASP gap generates a real dry-run draft; an OOS control is refused", async ({ page }) => {
    // LLM07:2025 is enforceable-but-unloaded (a GAP) → generate a real tighten-only dry-run draft (never enforces).
    const gen = await apiPost(page, "/api/v1/mitre/coverage/generate", { technique_id: "LLM07:2025", namespace: "default", agent_class: "customer-support", framework: "owasp" });
    expect(gen.status).toBe(200);
    expect(gen.body.draft_id).toMatch(/^dmitre/);
    expect(gen.body.enforcement).toBe("draft");
    const drafts = await api(page, "/api/v1/threats/intent-drafts?namespace=all");
    expect(((drafts.body.drafts ?? []) as any[]).some((d) => String(d.draft_id).startsWith("dmitre"))).toBeTruthy();

    // An OUT-OF-SCOPE control (LLM03 Supply Chain) has no runtime tool-call handle → generate refuses it (422).
    const oos = apiPost(page, "/api/v1/mitre/coverage/generate", { technique_id: "LLM03:2025", namespace: "default", agent_class: "customer-support", framework: "owasp" });
    expect((await oos).status).toBe(422);
    // NOTE: the draft lives in the dedicated intent_drafts table (dry-run, non-enforcing) — no cleanup, and it must
    // NOT be "cleaned" by deleting the real customer-support POLICY.
  });

  test("P1 export: the OWASP evidence pack streams a real file labelled 'OWASP LLM Top 10 (2025)' with 10 controls", async ({ page }) => {
    const exp = await page.evaluate(async () => {
      const token = localStorage.getItem("nrvq_token");
      const res = await fetch("/api/v1/mitre/coverage/export?range=24h&format=json&framework=owasp", { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      const text = await res.text();
      let parsed: any = null; try { parsed = JSON.parse(text); } catch { /* keep null */ }
      return {
        status: res.status,
        type: res.headers.get("content-type"),
        disposition: res.headers.get("content-disposition"),
        framework: parsed?.framework,
        controlCount: Array.isArray(parsed?.controls) ? parsed.controls.length : -1
      };
    });
    expect(exp.status).toBe(200);
    expect(exp.framework).toBe("OWASP LLM Top 10 (2025)");
    expect(exp.controlCount).toBe(10);
    expect(exp.disposition || "").toContain("owasp");
  });
});
