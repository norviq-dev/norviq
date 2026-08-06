// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The vitest config that is ACTUALLY in effect — asserted, not assumed.
 *
 * `tsconfig.node.json` is `composite`, which cannot be combined with `noEmit`, so `tsc -b` (run by
 * `npm run build`) has to emit somewhere. It used to emit beside its input, producing `vite.config.js`
 * and `vite.config.d.ts` — and both were committed.
 *
 * Vite resolves `vite.config.js` BEFORE `vite.config.ts`. So the moment the emitted copy drifted from
 * the source, the real config silently stopped being the one in effect, and nothing said so. Two
 * settings went missing, both of which corrupt this suite rather than break it:
 *
 *   1. `environmentOptions.jsdom.url` — pinned to :59999 precisely because jsdom defaults to
 *      http://localhost:3000, msw runs with `onUnhandledRequest: "bypass"`, and :3000 is where this
 *      project's own docs tell you to port-forward the console. An unmocked request then goes to the
 *      REAL network, is accepted by nginx, never answered, and hangs until the test times out. The
 *      suite's outcome depended on whether the developer happened to have the console open.
 *   2. `testTimeout` — 30s in the source, 5s by default. `setup.ts` sets `asyncUtilTimeout` to 15s, so
 *      the stale config inverted them: the whole-test clock fired first and you lost testing-library's
 *      "unable to find element" DOM dump, which is the only thing that makes such a failure diagnosable.
 *
 * The emit now goes to `node_modules/.tmp/`, but a future `outDir` change or a stray commit could bring
 * the shadow back. These two assertions are the tripwire.
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

describe("the vitest config in effect is vite.config.ts, not a stale emitted shadow", () => {
  it("pins jsdom's origin off :3000, so an unmocked request cannot reach a port-forwarded console", () => {
    // The observable consequence of the right config being loaded. If a shadow returns, this is
    // http://localhost:3000 and every unmocked request in the suite becomes a real network call.
    expect(window.location.origin).toBe("http://localhost:59999");
  });

  it("has no emitted config beside the source that could shadow it", () => {
    // Cheap and direct: the shadow is a FILE, so look for the file. This catches the case where someone
    // changes `outDir` back, or commits the artifact again, even if the origin above still happens to
    // match because the two copies have not drifted yet.
    const ui = resolve(__dirname, "../..");
    for (const shadow of ["vite.config.js", "vite.config.mjs", "vite.config.d.ts"]) {
      // The path is `resolve()` of a fixed directory and a member of the literal array above; no external
      // input reaches it, and the call only ever tests for existence.
      // eslint-disable-next-line security/detect-non-literal-fs-filename -- justified above
      expect(existsSync(resolve(ui, shadow)), `${shadow} shadows vite.config.ts — Vite resolves it first`).toBe(false);
    }
  });
});

/**
 * nginx defaults `proxy_read_timeout` to 60s. The `/api/` block did not override it, so any API call
 * slower than a minute got nginx's own 504 while the API kept working and finished the job.
 *
 * Measured on AKS: `POST /api/v1/redteam/suite` returned `504 Gateway Time-out (nginx/1.27.5)` at 61s,
 * and the run still completed server-side scoring 26/26 — the console's headline security action
 * reporting failure for something that had succeeded, and the operator's natural retry then hitting a
 * legitimate "already running" refusal.
 *
 * Asserted here because it is INVISIBLE on kind, where the same suite finishes inside the minute. A
 * default that is only ever wrong on a big or distant cluster is exactly the kind that ships.
 */
describe("ui/nginx.conf — the /api proxy must outlast a long admin action", () => {
  it("sets a read timeout on /api/ well above nginx's 60s default", () => {
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- a fixed repo path, not input
    const conf = readFileSync(resolve(process.cwd(), "nginx.conf"), "utf8");
    const apiBlock = conf.slice(conf.indexOf("location /api/"));
    const block = apiBlock.slice(0, apiBlock.indexOf("}"));
    const m = /proxy_read_timeout\s+(\d+)s/.exec(block);
    expect(m, "the /api/ block must set proxy_read_timeout — the default 60s 504s a red-team suite").toBeTruthy();
    expect(Number(m![1])).toBeGreaterThanOrEqual(120);
  });

  it("does not hold an /api request open for a whole session the way a websocket may", () => {
    // /ws/ legitimately uses 3600s. A request that has not answered in minutes is a fault worth
    // surfacing, not something to hold a worker on, so the two must not be given the same budget.
    // eslint-disable-next-line security/detect-non-literal-fs-filename -- a fixed repo path, not input
    const conf = readFileSync(resolve(process.cwd(), "nginx.conf"), "utf8");
    const apiBlock = conf.slice(conf.indexOf("location /api/"));
    const block = apiBlock.slice(0, apiBlock.indexOf("}"));
    const m = /proxy_read_timeout\s+(\d+)s/.exec(block);
    expect(Number(m![1])).toBeLessThan(3600);
  });
});
