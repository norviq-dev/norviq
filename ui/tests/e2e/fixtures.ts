// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Shared test fixtures:
//   • `page`      — a normal Playwright page but with the admin token injected via addInitScript on
//                   EVERY navigation (belt-and-suspenders on top of the storageState from global-setup;
//                   guarantees the SPA never bounces to /login mid-test even across hard reloads).
//   • `recorder`  — a network + console recorder that collects (a) any /api/v1 response with status>=400
//                   and (b) any console.error / pageerror. Exposes expectNoApiFailures() and
//                   expectNoConsoleErrors() so every smoke test can assert a clean, real page.
//
// Nothing here mocks the network — the suite drives the REAL app + backend.

import { test as base, expect, type Page, type Request as PWRequest } from "@playwright/test";
import { readFileSync, existsSync } from "node:fs";

const TOKEN_FILE = process.env.NRVQ_TOKEN_FILE ?? "/tmp/nrvq-signin-token.txt";

function loadToken(): string {
  if (!existsSync(TOKEN_FILE)) return "";
  const raw = readFileSync(TOKEN_FILE, "utf8").trim();
  return raw.split(".").length === 3 ? raw : "";
}

// Some console noise is expected and NOT a defect (dev-time React warnings, third-party font/telemetry
// chatter, benign favicon 404s). Anything matching these is ignored by expectNoConsoleErrors().
const IGNORED_CONSOLE = [
  /Download the React DevTools/i,
  /React Router Future Flag Warning/i,
  /\[vite\]/i,
  /favicon\.ico/i,
  /ResizeObserver loop/i
];

export interface ApiFailure {
  url: string;
  status: number;
  method: string;
}

export class NetworkRecorder {
  readonly apiFailures: ApiFailure[] = [];
  readonly consoleErrors: string[] = [];

  /** /api/v1 responses with status >= 400 that we should never see with an admin token on a seeded cluster. */
  expectNoApiFailures(): void {
    expect(
      this.apiFailures,
      `Unexpected /api/v1 failures:\n${this.apiFailures.map((f) => `  ${f.status} ${f.method} ${f.url}`).join("\n")}`
    ).toEqual([]);
  }

  expectNoConsoleErrors(): void {
    const real = this.consoleErrors.filter((m) => !IGNORED_CONSOLE.some((re) => re.test(m)));
    expect(real, `Unexpected console errors:\n${real.map((m) => `  ${m}`).join("\n")}`).toEqual([]);
  }
}

export const test = base.extend<{ recorder: NetworkRecorder }>({
  // Re-declare `page` to always carry the admin token, independent of the persisted storageState.
  page: async ({ page }, use) => {
    const token = loadToken();
    if (token) {
      await page.addInitScript((tok) => {
        try {
          window.localStorage.setItem("nrvq_token", tok as string);
          window.localStorage.removeItem("nrvq_must_change");
        } catch {
          /* storage unavailable */
        }
      }, token);
    }
    await use(page);
  },

  recorder: async ({ page }: { page: Page }, use) => {
    const rec = new NetworkRecorder();

    page.on("response", (resp) => {
      const url = resp.url();
      if (url.includes("/api/v1") && resp.status() >= 400) {
        const req: PWRequest = resp.request();
        rec.apiFailures.push({ url, status: resp.status(), method: req.method() });
      }
    });
    page.on("console", (msg) => {
      if (msg.type() === "error") rec.consoleErrors.push(msg.text());
    });
    page.on("pageerror", (err) => {
      rec.consoleErrors.push(`pageerror: ${err.message}`);
    });

    await use(rec);
  }
});

export { expect };

/** Wait for the SPA to settle: network idle + the authenticated Shell chrome mounted (not the login gate). */
export async function waitForApp(page: Page): Promise<void> {
  await page.waitForLoadState("networkidle");
}

/**
 * Detect whether a route redirected to `/` (used to skip fleet-gated routes). Returns the final
 * pathname after navigation settles.
 */
export async function finalPath(page: Page): Promise<string> {
  return page.evaluate(() => window.location.pathname);
}

/**
 * Start a RedTeam suite and return the SETTLED `results/latest` for its namespace.
 *
 * Three specs had their own copy of this, each returning the POST response. The POST answers as soon
 * as the run is ACCEPTED, so a run still being scored carries no `efficacy` — and every caller then
 * reads `run.efficacy.overall`, which throws a TypeError naming neither the suite nor the wait. It is
 * intermittent by construction: whether it passes depends on how loaded the host was that minute.
 *
 * Two identical polls, not one. The run is written incrementally, so a single sighting of `efficacy`
 * can be a partially-scored run whose totals move again under the assertion. Requiring the same
 * fingerprint twice is what makes "finished" distinguishable from "in progress" — the same reason
 * scripts/kind-e2e/seed.py waits for a stable count rather than sleeping once after a push.
 */
export async function suiteSettled(page: Page, query: string): Promise<any> {
  const ns = new URLSearchParams(query).get("target_namespace") ?? "default";

  const latestOf = async () =>
    page.evaluate(async (n) => {
      const t = localStorage.getItem("nrvq_token");
      const res = await fetch(`/api/v1/redteam/results/latest?ns=${n}`, {
        headers: t ? { Authorization: `Bearer ${t}` } : {},
      });
      return res.ok ? res.json() : null;
    }, ns);

  // The run_id already on record BEFORE we ask for anything. It is what lets the "someone else's run
  // is in flight" path below stay honest: we accept that run's results only once they belong to a
  // DIFFERENT run than the one that was already there, so a settled-but-stale result can never be
  // mistaken for the fresh one this helper promises.
  const priorRunId = (await latestOf())?.run_id ?? null;

  const post = async () =>
    page.evaluate(async (q) => {
      const t = localStorage.getItem("nrvq_token");
      const res = await fetch(`/api/v1/redteam/suite?${q}`, {
        method: "POST",
        headers: t ? { Authorization: `Bearer ${t}` } : {},
      });
      return res.json();
    }, query);

  // ONE attempt, then WAIT — never a retry loop against "already running".
  //
  // This used to POST up to 20 times at 1500ms and throw "redteam suite stayed busy across 20
  // attempts" after 30s. The specs run with --workers=1, so nothing is racing us: the busy signal
  // means an EARLIER spec's run (a UI-driven "Run suite" click) is still executing server-side, and a
  // suite on a real cluster takes minutes — measured at 148s on AKS against ~seconds on kind. So the
  // budget was never going to be enough, and every retry spent a round trip re-asking a question whose
  // answer could not change until that run finished. It failed only on the slower cluster, which is
  // exactly where the gate needs to mean something.
  //
  // Waiting for the in-flight run is not a workaround, it is the contract: this helper's job is to
  // return a SETTLED scored run for the namespace, and a run already producing one for that same
  // namespace satisfies that. The `priorRunId` guard keeps it from accepting a stale one.
  const first = await post();
  const busy = (first as { detail?: unknown })?.detail;
  const waitingOnSomeoneElse = !!busy && /already running/i.test(JSON.stringify(busy));
  if (!!busy && !waitingOnSomeoneElse) {
    throw new Error(`POST /redteam/suite refused: ${JSON.stringify(busy)}`);
  }
  if (waitingOnSomeoneElse) {
    // A whole foreign suite may have to drain first, which can outlast the default per-test budget.
    test.setTimeout(300_000);
  }

  // Two identical polls, not one. The run is written incrementally, so a single sighting of `efficacy`
  // can be a partially-scored run whose totals move again under the assertion.
  let prev = "";
  const deadline = Date.now() + (waitingOnSomeoneElse ? 240_000 : 90_000);
  while (Date.now() < deadline) {
    const latest = await latestOf();
    const o = latest?.efficacy?.overall;
    // While waiting on a foreign run, ignore the record that was already there — settling on it would
    // assert against results this call did not produce.
    const isFresh = !waitingOnSomeoneElse || (latest?.run_id && latest.run_id !== priorRunId);
    if (o && isFresh) {
      const fingerprint = `${latest.run_id}|${o.total}|${o.caught}|${o.got_through}|${latest.pass_rate}`;
      if (fingerprint === prev) return latest;
      prev = fingerprint;
    }
    await page.waitForTimeout(1500);
  }
  throw new Error(
    `redteam results/latest for ns=${ns} never settled` +
      (waitingOnSomeoneElse ? ` (waited out an in-flight run; prior run_id ${priorRunId})` : "")
  );
}
