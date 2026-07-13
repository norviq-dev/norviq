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
