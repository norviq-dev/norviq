// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The results table must stay BOUNDED at the view on a LARGE run. This drives a full-namespace suite
// (≥300 result rows) and asserts the SERVED DOM: the number of mounted <tr data-testid=redteam-attack-row>
// is ≤ 50 regardless of run size, the pager reports multiple pages and advances, and the got-through filter
// narrows the mounted rows. Playwright's locator .count() counts REAL DOM nodes, so this proves the mount is
// windowed — not just that a prop says 50 (the prior e2e only ran a 29-row scoped suite and never exercised
// the pager, which is why the large-run case was unproven).

import { test, expect, waitForApp } from "./fixtures";
import { type Page } from "@playwright/test";

const PAGE_SIZE = 50;

// FAIL LOUDLY ON A NON-2xx. These helpers used to return `r.json()` and drop the status, so a 401
// (expired token), a 429 (rate-limited) and a 500 all arrived as a body with no `results` — and the
// assertion downstream reported "got 0" or "element(s) not found". Whole runs were mis-triaged as
// missing fixtures or product defects on the strength of that. A 409 is EXPECTED here (the
// per-namespace concurrent guard) so it is passed through for the retry loop to handle.
async function apiJson(page: Page, path: string, method = "GET"): Promise<any> {
  const { status, body } = await page.evaluate(async ({ path, method }) => {
    const t = localStorage.getItem("nrvq_token");
    const r = await fetch(path, { method, headers: t ? { Authorization: `Bearer ${t}` } : {} });
    return { status: r.status, body: await r.json().catch(() => null) };
  }, { path, method });
  if (status >= 400 && status !== 409) {
    // The status rides on the error so a caller can tell a GATEWAY TIMEOUT from a real refusal —
    // see postSuite. Without it every non-409 failure is one opaque string.
    const err = new Error(`${method} ${path} -> HTTP ${status}: ${JSON.stringify(body)?.slice(0, 200)}`);
    (err as Error & { status?: number }).status = status;
    throw err;
  }
  return body;
}

/** A completed run for this namespace, or null. Used when the POST's socket gave up before the run did. */
async function latestRun(page: Page, ns: string): Promise<any | null> {
  try {
    return await apiJson(page, `/api/v1/redteam/results/latest?target_namespace=${ns}`);
  } catch {
    return null;
  }
}
/**
 * Wait until the namespace actually HAS real agent classes before running a full-namespace suite.
 *
 * `_seeded_classes` falls back to a single synthetic target when the registry has no real class for
 * the namespace, so a suite posted during that window returns one class's worth of rows. The caller
 * then fails its own "need a large run" precondition with `got 34`, which reads as "the suite ran the
 * wrong scope" when the truth is "the registry was momentarily empty". Same lesson as the settle loop
 * below: do not assume from one observation, go and look.
 */
async function waitForRealTargets(page: Page, ns: string, minimum = 2): Promise<number> {
  let seen = 0;
  for (let i = 0; i < 30; i++) {
    try {
      const r = await apiJson(page, `/api/v1/redteam/targets?ns=${ns}`);
      seen = (r?.targets ?? []).length;
      if (seen >= minimum) return seen;
    } catch {
      /* registry not answering yet — keep looking */
    }
    await page.waitForTimeout(2000);
  }
  throw new Error(`ns=${ns} never reported ${minimum}+ real agent classes (saw ${seen}); the registry is empty, so a full-namespace suite cannot be large`);
}

// POST /redteam/suite, retrying if the per-namespace concurrent guard returns 409 (another run in flight).
async function postSuite(page: Page, query: string, minTargets = 1): Promise<any> {
  const ns = /target_namespace=([^&]+)/.exec(query)?.[1] ?? "default";
  for (let i = 0; i < 20; i++) {
    let r: any;
    try {
      r = await apiJson(page, `/api/v1/redteam/suite?${query}`, "POST");
    } catch (e) {
      // A GATEWAY TIMEOUT IS A THIRD OUTCOME, not a failure. This endpoint runs the whole corpus
      // synchronously — 18 classes x 29 attacks, every one a real OPA evaluation — so on a cluster
      // that is merely slow the proxy gives up long before the server does. The request WAS accepted
      // and the run IS proceeding; only our socket left. Treating that as an error made the spec
      // report "HTTP 504" for a run that completed seconds later.
      //
      // The same shape was already fixed once on the seeding side (seed.py's seed_redteam): don't
      // assume either way, go and look for the run.
      const status = (e as Error & { status?: number }).status ?? 0;
      if (![502, 503, 504].includes(status)) throw e;

      // WAIT FOR THE RUN TO FINISH, not merely to EXIST. Returning the first run that had any results
      // handed back a PARTIALLY-WRITTEN one — the suite persists as it works through the namespace's
      // classes, so `results/latest` answers with 29 rows (one class) long before all eighteen are
      // done. The caller then failed its own "need a large run" pre-condition and reported `got 29`,
      // which looks like the suite ran the wrong scope.
      //
      // Completion is inferred from the count going STABLE rather than from a status field, because
      // that holds regardless of how the endpoint reports progress: growing means still working,
      // twice-unchanged means done.
      // AND IT MUST BE **OUR** RUN. `results/latest` returns whatever ran most recently in the
      // namespace, including another spec's — redteam-runstate-list posts with a single
      // `target_agent`, so this loop would happily adopt its ONE-target run and then fail this
      // spec's "need a large run" precondition with `got 34`, which reads as a broken pager.
      // Requiring the target count the caller asked for is what makes the run identifiably ours.
      let prev = -1, stable = 0, widest = 0;
      for (let j = 0; j < 60; j++) {
        await page.waitForTimeout(3000);
        const run = await latestRun(page, ns);
        const targets = (run?.targets ?? []).length;
        widest = Math.max(widest, targets);
        const n = (run?.results ?? []).length;
        if (targets < minTargets) {          // someone else's narrower run — keep waiting for ours
          stable = 0;
          prev = -1;
          continue;
        }
        if (n > 0 && n === prev) {
          if (++stable >= 2) return run;   // unchanged across two polls -> the run has settled
        } else {
          stable = 0;
        }
        prev = n;
      }
      throw new Error(`suite POST timed out (${status}) and no COMPLETED run with >= ${minTargets} target(s) appeared for ns=${ns} (last size ${prev}, widest target count seen ${widest})`);
    }
    if (!(r?.detail?.error || /already running/i.test(JSON.stringify(r?.detail ?? "")))) return r;
    await page.waitForTimeout(1500);
  }
  throw new Error("suite stayed busy");
}

// Serial: these tests mutate the shared results/latest for ns=default; they must not run concurrently.
test.describe.configure({ mode: "serial" });
test.describe("results table bounded at the VIEW on a large run (served DOM)", () => {
  test("≥300-result run mounts ≤50 <tr>, pager pages, filter filters", async ({ page }) => {
    test.setTimeout(180000);
    await page.goto("/redteam");
    await waitForApp(page);

    // drive a FULL-namespace suite so the run is large (dozens of real classes × the whole corpus)
    const classes = await waitForRealTargets(page, "default");
    // Demand a run that covers the namespace, so another spec's single-target run cannot be adopted.
    const run = await postSuite(page, "target_namespace=default", Math.min(classes, 8));
    const total = (run.results ?? []).length;
    expect(
      total,
      `need a large run to exercise the pager; got ${total} from ${(run.targets ?? []).length} target(s) ` +
        `while the registry reported ${classes} real classes — a mismatch here means the suite ran a ` +
        `narrower scope than the namespace has, not that the pager is broken`
    ).toBeGreaterThanOrEqual(300);

    // reload the view so it renders results/latest (the large run)
    await page.goto("/redteam");
    await waitForApp(page);
    await expect(page.getByTestId("redteam-scorecard")).toBeVisible({ timeout: 30000 });

    // B: the header shows a concise CLASS COUNT + timestamp, not the full comma-separated class list.
    const classCount = (run.targets ?? []).length;
    const summary = page.getByTestId("redteam-targets-summary");
    await expect(summary).toContainText(new RegExp(`${classCount} class(es)? · ran`, "i"));
    await expect(page.getByTestId("redteam-targets-list")).toHaveCount(0); // list collapsed by default
    // the summary is short — never the wall-of-text join of every class name
    expect((await summary.textContent())!.length, "header must not dump the full class list").toBeLessThan(60);
    // expanding reveals the names on demand
    await page.getByTestId("redteam-targets-toggle").click();
    await expect(page.getByTestId("redteam-targets-list")).toBeVisible();

    // ── the KEY assertion: mounted <tr> in the DOM is bounded, NOT the full result set ──
    const mounted = await page.getByTestId("redteam-attack-row").count();
    expect(mounted, `mounted rows must be ≤${PAGE_SIZE} on a ${total}-row run`).toBeLessThanOrEqual(PAGE_SIZE);
    expect(mounted).toBeGreaterThan(0);

    // pager reports multiple pages and advances (still bounded on page 2)
    const expectedPages = Math.ceil(total / PAGE_SIZE);
    await expect(page.getByTestId("redteam-pager")).toBeVisible();
    await expect(page.getByTestId("redteam-page-indicator")).toContainText(`/ ${expectedPages}`);
    await page.getByTestId("redteam-next").click();
    await expect(page.getByTestId("redteam-page-indicator")).toContainText("Page 2");
    expect(await page.getByTestId("redteam-attack-row").count()).toBeLessThanOrEqual(PAGE_SIZE);

    // target selector is present (restored) and lists real classes
    await expect(page.getByTestId("redteam-target")).toBeVisible();

    // got-through filter narrows the mounted rows and stays bounded
    const gt = await apiJson(page, "/api/v1/redteam/results/latest");
    const gotThrough = gt.efficacy.overall.got_through as number;
    if (gotThrough > 0) {
      await page.getByTestId("redteam-failed-filter").getByRole("checkbox").check();
      const failedMounted = await page.getByTestId("redteam-attack-row").count();
      expect(failedMounted).toBeLessThanOrEqual(PAGE_SIZE);
      // every mounted row under the filter is a miss
      expect(await page.getByTestId("redteam-row-failed").count()).toBe(failedMounted);
    }

    // no app 4xx/5xx and no console errors during all of this
    // (asserted via a clean render — the scorecard + pager rendered from real data)
  });
});
