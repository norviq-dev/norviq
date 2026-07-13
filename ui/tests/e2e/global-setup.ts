// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Global setup: read the admin token from disk (NO secret in code) and write a Playwright
// storageState.json that seeds the SPA's localStorage `nrvq_token` for the app origin. The SPA's
// login gate (App.tsx: `if (!getToken()) return <Login/>`) then passes straight through to the
// authenticated Shell — so every test starts already signed in as role=admin, namespace=*.
//
// The token is HS256 (role=admin) and is produced by the deploy scripts at /tmp/nrvq-signin-token.txt.
// Override with NRVQ_TOKEN_FILE if it lives elsewhere.

import { chromium, type FullConfig } from "@playwright/test";
import { readFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const TOKEN_FILE = process.env.NRVQ_TOKEN_FILE ?? "/tmp/nrvq-signin-token.txt";
const STATE_PATH = resolve(__dirname, "artifacts/storageState.json");

function readToken(): string {
  if (!existsSync(TOKEN_FILE)) {
    throw new Error(
      `[global-setup] admin token file not found at ${TOKEN_FILE}. ` +
        `Set NRVQ_TOKEN_FILE or generate it (deploy scripts write /tmp/nrvq-signin-token.txt).`
    );
  }
  const raw = readFileSync(TOKEN_FILE, "utf8").trim();
  if (!raw || raw.split(".").length !== 3) {
    throw new Error(`[global-setup] token at ${TOKEN_FILE} is not a JWT (expected header.body.sig).`);
  }
  return raw;
}

export default async function globalSetup(config: FullConfig) {
  const token = readToken();
  const baseURL = config.projects[0]?.use?.baseURL ?? process.env.PLAYWRIGHT_BASE_URL ?? "http://localhost:3400";

  mkdirSync(dirname(STATE_PATH), { recursive: true });

  // Open the app origin once and stamp the token into localStorage, then persist storageState. We use a
  // real browser context (rather than hand-writing the JSON) so the origin is captured exactly as the
  // running SPA expects it — no origin-mismatch surprises.
  const browser = await chromium.launch();
  const context = await browser.newContext({ ignoreHTTPSErrors: true, baseURL });
  const page = await context.newPage();
  try {
    // A bare navigation is enough to establish the origin for localStorage; the SPA may bounce to /login
    // on this first load (no token yet) — that's fine, we set the token immediately after.
    await page.goto("/", { waitUntil: "domcontentloaded" });
  } catch {
    // The app may be unreachable during --list (author/typecheck) runs; the storageState is still written
    // so listing succeeds. The real run (post-redeploy) will have a live origin.
  }
  await context.addInitScript((tok) => {
    try {
      window.localStorage.setItem("nrvq_token", tok as string);
      window.localStorage.removeItem("nrvq_must_change");
    } catch {
      /* storage unavailable */
    }
  }, token);
  await page.evaluate((tok) => {
    try {
      window.localStorage.setItem("nrvq_token", tok as string);
      window.localStorage.removeItem("nrvq_must_change");
    } catch {
      /* origin not yet established */
    }
  }, token);

  await context.storageState({ path: STATE_PATH });
  await browser.close();
}
