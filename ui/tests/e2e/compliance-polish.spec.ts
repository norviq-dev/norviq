// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// COMPLIANCE POLISH E2E. Drives the REAL SPA + API on the live kind cluster and asserts the EFFECT of the
// four semantics/hygiene refinements: per-framework blocked (ATLAS ≠ OWASP, each == its own rule-block sum),
// control-scoped + traceable remediation drafts (real class, control tag, refinement; honest empty when none),
// framework-neutral /compliance/{framework}/* routes (== the legacy /mitre alias), dedup by (framework,
// control, class). No-mock guard: each card's blocked equals a DIRECT API call.

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

test.describe("Compliance polish — EFFECT proofs on the live console", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForApp(page);
  });

  test("per-framework blocked differs, and each equals its OWN framework's coverage endpoint (no-mock)", async ({ page }) => {
    const atlas = await api(page, "/api/v1/compliance/atlas/coverage?range=24h");
    const owasp = await api(page, "/api/v1/compliance/owasp/coverage?range=24h");
    expect(atlas.status).toBe(200);
    expect(owasp.status).toBe(200);
    // ATLAS maps every OWASP rule PLUS extras (cross_tenant_access, llm05_supply_chain), so its blocked total is
    // >= OWASP's, and — with any activity on those extra rules — strictly different. Not the old shared global.
    expect(atlas.body.blocked).toBeGreaterThanOrEqual(owasp.body.blocked);
    expect(atlas.body.blocked).not.toBe(owasp.body.blocked);

    // No-mock guard: the value the OWASP card renders equals the OWASP coverage endpoint's blocked.
    const bad: string[] = [];
    page.on("response", (r) => { if (r.status() >= 400 && r.url().includes("/api/")) bad.push(`${r.status()} ${r.url()}`); });
    await page.goto("/compliance");
    await waitForApp(page);
    await page.waitForTimeout(1500);
    const fmt = (n: number) => n.toLocaleString("en-US");
    await expect(page.getByText(`${fmt(atlas.body.blocked)} blocked`, { exact: false }).first()).toBeVisible({ timeout: 8000 });
    await expect(page.getByText(`${fmt(owasp.body.blocked)} blocked`, { exact: false }).first()).toBeVisible();
    expect(bad, `unexpected 4xx/5xx on /compliance: ${bad.join(", ")}`).toEqual([]);
  });

  test("a gap→generate draft is scoped to a REAL class, tagged with its control, and refinement-appropriate", async ({ page }) => {
    // LLM01 with NO agent_class → the backend derives the real active class (not a 'default' deny-all) + tags it.
    //
    // NOT LLM07, which this used to use. Some OWASP controls are deliberately NOT auto-generatable as
    // runtime policy, and the API says so precisely: LLM07 (System Prompt Leakage) and LLM10
    // (Unbounded Consumption) both return `status: "escalate"` with `draft_id: null` and the reason —
    // "this risk doesn't show up in agent tool-call traffic, so there is no signal a policy rule could
    // match at enforcement time". That is the product being honest rather than emitting a rule that
    // enforces nothing, so the spec moves to a control that genuinely generates.
    const gen = await apiPost(page, "/api/v1/compliance/owasp/generate", { technique_id: "LLM01:2025", namespace: "default" });
    expect(gen.status).toBe(200);
    expect(gen.body.status).toBe("draft");
    expect(gen.body.cls).toBeTruthy();
    expect(gen.body.cls).not.toBe("default");
    expect(gen.body.control_name).toBe("Prompt Injection");
    expect(gen.body.framework).toBe("owasp");

    // Control-appropriate refinement: the generated draft pre-enables the refinement that MATCHES its
    // control, rather than a generic one. Excessive Agency (LLM06) pulls in the shell-execution deny.
    const agency = await apiPost(page, "/api/v1/compliance/owasp/generate", { technique_id: "LLM06:2025", namespace: "default" });
    expect(agency.body.refinement).toContain("llm06_excessive_agency");

    // ...and an out-of-scope control is REFUSED with its reason, never a vacuous draft.
    const oos = await apiPost(page, "/api/v1/compliance/owasp/generate", { technique_id: "LLM07:2025", namespace: "default" });
    expect(oos.body.status).toBe("escalate");
    expect(oos.body.draft_id).toBeNull();
    expect(oos.body.message).toMatch(/can't be auto-generated|outside runtime enforcement/i);

    // The draft is persisted WITH its provenance (framework + control) — traceable in the intent-drafts feed.
    const drafts = await api(page, "/api/v1/threats/intent-drafts?ns=default");
    const tagged = ((drafts.body.drafts ?? []) as any[]).find((d) => d.source_control_id === "LLM01:2025");
    expect(tagged, "the LLM01 draft must carry its source control tag").toBeTruthy();
    expect(tagged.source_framework).toBe("owasp");
    expect(tagged.source_control_name).toBe("Prompt Injection");

    // Honest-empty: a namespace with no active non-synthetic class → NO vacuous default draft.
    const empty = await apiPost(page, "/api/v1/compliance/owasp/generate", { technique_id: "LLM01:2025", namespace: "e2e-empty-ns-zzz" });
    expect(empty.body.status).toBe("no_affected_classes");
    expect(empty.body.draft_id).toBeNull();
    const emptyDrafts = await api(page, "/api/v1/threats/intent-drafts?ns=e2e-empty-ns-zzz");
    expect(((emptyDrafts.body.drafts ?? []) as any[]).length).toBe(0);
  });

  test("UI: the generated draft's provenance is shown in Policy Catalog (row + review header)", async ({ page }) => {
    // Ensure a tagged draft exists, then open its deep-link in the Policy Catalog.
    // LLM01 rather than LLM07: see the note above — LLM07 is deliberately escalate-only, so it never
    // yields a draft_id and this deep-link would be `?intent_draft=null`.
    const gen = await apiPost(page, "/api/v1/compliance/owasp/generate", { technique_id: "LLM01:2025", namespace: "default" });
    const draftId = gen.body.draft_id as string;
    await page.goto(`/policies/catalog?intent_draft=${encodeURIComponent(draftId)}`);
    await waitForApp(page);
    // Row provenance label + auto-opened review header both name the originating control.
    await expect(page.getByTestId(`intent-draft-source-${draftId}`)).toContainText("OWASP LLM · LLM01:2025 Prompt Injection", { timeout: 8000 });
    await expect(page.getByTestId("intent-draft-source-header")).toContainText("LLM01:2025 Prompt Injection");
  });

  test("/compliance/{framework}/* == the legacy /mitre alias; /mitre stays ATLAS; unknown framework 404s", async ({ page }) => {
    const neutral = await api(page, "/api/v1/compliance/owasp/coverage?range=24h");
    const legacy = await api(page, "/api/v1/mitre/coverage?range=24h&framework=owasp");
    expect(neutral.body.framework).toBe("owasp");
    expect(legacy.body.framework).toBe("owasp");
    expect(neutral.body.enforced).toBe(legacy.body.enforced);
    expect(neutral.body.enforceable_total).toBe(legacy.body.enforceable_total);
    expect(neutral.body.blocked).toBe(legacy.body.blocked);

    const dflt = await api(page, "/api/v1/mitre/coverage?range=24h");
    expect(dflt.body.framework).toBe("atlas");
    expect((await api(page, "/api/v1/compliance/nope/coverage")).status).toBe(404);
    // trend + export neutral routes are live too
    expect((await api(page, "/api/v1/compliance/owasp/trend?range=30d")).status).toBe(200);
  });

  test("re-generating a control is idempotent; two controls for the same class are two drafts", async ({ page }) => {
    // Two GENERATABLE controls. This used LLM07 and LLM10, which are both deliberately escalate-only
    // (see the note in the gap→generate test) — so both draft_ids were null, and `null !== null` is
    // false, i.e. the "two distinct drafts" assertion could never hold no matter what the code did.
    const g1 = await apiPost(page, "/api/v1/compliance/owasp/generate", { technique_id: "LLM01:2025", namespace: "default" });
    const g2 = await apiPost(page, "/api/v1/compliance/owasp/generate", { technique_id: "LLM01:2025", namespace: "default" });
    const g3 = await apiPost(page, "/api/v1/compliance/owasp/generate", { technique_id: "LLM06:2025", namespace: "default" });
    expect(g1.body.draft_id).toBeTruthy();                // guard: a null id would make both checks vacuous
    expect(g1.body.draft_id).toBe(g2.body.draft_id);      // LLM01 twice → ONE draft (idempotent)
    expect(g1.body.draft_id).not.toBe(g3.body.draft_id);  // LLM01 vs LLM06 → TWO distinct drafts
    // both distinct-control drafts coexist for the same class
    const drafts = await api(page, "/api/v1/threats/intent-drafts?ns=default");
    const ids = new Set(((drafts.body.drafts ?? []) as any[]).map((d) => d.draft_id));
    expect(ids.has(g1.body.draft_id) && ids.has(g3.body.draft_id)).toBeTruthy();
  });
});
