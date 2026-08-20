// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Coverage for the surfaces this branch fixed, none of which any existing spec touched — so the suite
// could have run fully green while every one of these bugs was live:
//
//   1. The Audit Log's LIVE TAIL ignored "Real traffic only". The websocket payload carried no
//      `framework` field, so the client's `framework === "redteam"` test compared `undefined` and never
//      matched: red-team AND synthetic/probe rows streamed into a filtered view while the fetched rows
//      beneath them were correctly excluded. Two views of one population, disagreeing, in an audit tool.
//   2. Tool Call Volume rendered NOTHING for a single bucket (a line has no segment to stroke and
//      `symbol: "none"` suppressed the only drawable mark) while its tooltip still reported real numbers.
//   3. /audit/volume bucketed by HOUR for every range, so `1h` could only ever produce one point.
//   4. The Overview "Would-block" tile was structurally 0 in Monitor mode — the engine softens every
//      would-block to an `audit` decision and emits no `block`, but the tile counted only blocks.
//
// Traffic is generated through the REAL /evaluate API against the same cluster the console reads, so
// each assertion is about the product's own behaviour rather than a fixture.

import { readFileSync, existsSync } from "node:fs";
import { test, expect } from "./fixtures";
import type { APIRequestContext, Page } from "@playwright/test";

const TOKEN_FILE = process.env.NRVQ_TOKEN_FILE ?? "/tmp/nrvq-signin-token.txt";
const API = process.env.NRVQ_API_URL ?? "http://127.0.0.1:18080";
const NS = process.env.NRVQ_E2E_NAMESPACE ?? "analytics";

function token(): string {
  if (!existsSync(TOKEN_FILE)) return "";
  return readFileSync(TOKEN_FILE, "utf8").trim();
}

/**
 * Retry a request against transient TRANSPORT failures.
 *
 * These specs reach the API through a `kubectl port-forward`, which drops connections under
 * concurrency — surfacing as `socket hang up` partway through a run. That is the tunnel failing, not the
 * product, and letting it fail the assertion turns a harness artifact into a false defect report. Only
 * transport errors are retried: an HTTP status the server actually returned is a real result and is
 * handed straight back to the assertion.
 */
async function withTransportRetry<T>(fn: () => Promise<T>, attempts = 3): Promise<T> {
  let last: unknown;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (e) {
      last = e;
      const msg = String((e as Error)?.message ?? e);
      if (!/socket hang up|ECONNRESET|ECONNREFUSED|EPIPE|fetch failed/i.test(msg)) throw e;
      await new Promise((r) => setTimeout(r, 750 * (i + 1)));
    }
  }
  throw last;
}

/** Drive one real evaluation. `framework`/`agentClass` decide whether the row counts as real traffic. */
async function evaluate(
  req: APIRequestContext,
  opts: { tool: string; params: Record<string, unknown>; agentClass: string; framework: string }
): Promise<number> {
  const res = await withTransportRetry(() => req.post(`${API}/api/v1/evaluate`, {
    headers: { Authorization: `Bearer ${token()}`, "Content-Type": "application/json" },
    data: {
      tool_name: opts.tool,
      tool_params: opts.params,
      framework: opts.framework,
      session_id: "e2e-audit-filters",
      agent_identity: {
        spiffe_id: `spiffe://norviq/ns/${NS}/sa/${opts.agentClass}`,
        namespace: NS,
        agent_class: opts.agentClass,
        service_account: opts.agentClass,
        framework: opts.framework
      }
    }
  }));
  return res.status();
}

/** The "Showing N of M records…" caption is the Audit Log's own statement of what it is displaying. */
async function shownTotal(page: Page): Promise<number> {
  const caption = await page.getByText(/Showing\s+\d+\s+of\s+\d+\s+records/).first().innerText();
  return Number(/of\s+(\d+)\s+records/.exec(caption)?.[1] ?? -1);
}

test.describe("Audit Log — real-traffic-only applies to the LIVE TAIL, not just fetched rows", () => {
  test("red-team and synthetic rows never stream into a filtered view, and DO appear when unfiltered", async ({
    page,
    request,
    recorder
  }) => {
    test.skip(token() === "", "needs an admin token file");

    await page.goto(`/audit?ns=${NS}`);
    await expect(page.getByRole("heading", { name: "Audit Log" })).toBeVisible({ timeout: 15000 });

    // Ensure the real-traffic-only view is active (it is the default; assert rather than assume).
    const toggle = page.getByRole("button", { name: /real traffic only|showing all/i }).first();
    if (/showing all/i.test(await toggle.innerText())) await toggle.click();
    await expect(page.getByText(/real traffic only/i).first()).toBeVisible();

    const before = await shownTotal(page);
    expect(before).toBeGreaterThanOrEqual(0);

    // (a) red-team FRAMEWORK — the half the client believed it was filtering.
    // (b) synthetic/probe CLASS — the half it never tested at all (framework is a normal one here).
    for (let i = 0; i < 3; i++) {
      expect(await evaluate(request, { tool: "search_kb", params: { query: "e2e" }, agentClass: "report-gen", framework: "redteam" })).toBe(200);
      expect(await evaluate(request, { tool: "search_kb", params: { query: "e2e" }, agentClass: "probe-e2e-filter", framework: "langchain" })).toBe(200);
    }

    // Give the websocket time to deliver anything it is going to deliver. A filter that is working looks
    // exactly like a dead stream at this point — which is why the unfiltered half of this test exists.
    await page.waitForTimeout(4000);

    await expect(page.getByText(new RegExp(`of\\s+${before}\\s+records`))).toBeVisible();
    await expect(page.getByText("probe-e2e-filter")).toHaveCount(0);

    // Now prove the stream is ALIVE and the rows really arrived: unfiltered must show them.
    await page.getByRole("button", { name: /real traffic only/i }).first().click();
    await expect(page.getByText(/showing all/i).first()).toBeVisible();

    await expect
      .poll(async () => shownTotal(page), { timeout: 20000, message: "unfiltered total must include the test rows" })
      .toBeGreaterThan(before);
    await expect(page.getByText("probe-e2e-filter").first()).toBeVisible({ timeout: 10000 });

    recorder.expectNoApiFailures();
  });
});

test.describe("Overview — Tool Call Volume", () => {
  test("renders a mark for a single bucket instead of an empty panel", async ({ page, request }) => {
    test.skip(token() === "", "needs an admin token file");

    // Guarantee at least one real row in the window so the chart has something to plot.
    await evaluate(request, { tool: "search_kb", params: { query: "e2e-volume" }, agentClass: "report-gen", framework: "langchain" });

    await page.goto(`/?ns=${NS}`);
    await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible({ timeout: 15000 });

    // Scope to the PANEL that contains both the title and a canvas — the Overview paints several charts
    // (coverage gauge, trust donut), so a bare `canvas` locator asserts on whichever happens to be first
    // and would pass while the volume chart stayed blank.
    const panel = page.locator("div:has(> canvas), div:has(canvas)").filter({ hasText: "Tool Call Volume" }).last();
    await panel.scrollIntoViewIfNeeded();

    // The series is canvas-rendered, so assert on the canvas having actually painted rather than on DOM
    // nodes: a blank panel and a drawn one differ only in pixels. A near-uniform canvas means nothing
    // was drawn — precisely the bug (tooltip worked, chart was empty).
    const canvas = panel.locator("canvas").first();
    await expect(canvas).toBeVisible({ timeout: 15000 });
    const painted = await canvas.evaluate((el: HTMLCanvasElement) => {
      const ctx = el.getContext("2d");
      if (!ctx || el.width === 0 || el.height === 0) return false;
      const { data } = ctx.getImageData(0, 0, el.width, el.height);
      const seen = new Set<string>();
      for (let i = 0; i < data.length; i += 4) {
        if (data[i + 3] === 0) continue; // transparent
        seen.add(`${data[i]},${data[i + 1]},${data[i + 2]}`);
        if (seen.size > 2) return true; // axis + gridlines + an actual series
      }
      return false;
    });
    expect(painted, "the volume chart painted nothing — a lone bucket must still draw its point").toBe(true);
  });

  test("bucket granularity follows the selected range", async ({ request }) => {
    test.skip(token() === "", "needs an admin token file");

    // Asserted at the API rather than through the canvas: bucket WIDTH is not observable in pixels, and
    // this is the cause the chart fix only treated the symptom of. Every range used to bucket hourly.
    const get = async (range: string) => {
      const res = await withTransportRetry(() =>
        request.get(`${API}/api/v1/audit/volume?range=${range}&namespace=${NS}`, {
          headers: { Authorization: `Bearer ${token()}` }
        })
      );
      expect(res.status()).toBe(200);
      return (await res.json()) as Array<{ time: string }>;
    };

    const hour = await get("1h");
    const month = await get("30d");
    // `1h` buckets at 5 minutes (HH:MM, minutes not pinned to :00); `30d` buckets daily (00:00).
    if (hour.length > 0) expect(hour[0].time).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
    if (month.length > 0) expect(month[0].time).toMatch(/ 00:00$/);

    // THE THIRD ASSERTION USED TO BE
    //     expect(month.length).toBeLessThanOrEqual(hour.length + month.length)
    // which reduces to `0 <= hour.length` — true for every possible response, so no input, no
    // regression and no server bug could ever make it red. Its comment claimed "a wide range must
    // aggregate, never emit more points than a narrow one", and that PROPERTY IS ALSO FALSE: 30 daily
    // buckets legitimately outnumber the ~12 five-minute buckets in an hour. The line asserted nothing
    // and documented something untrue.
    //
    // What granularity actually implies is a CEILING per range, which is exactly the regression the
    // test exists to catch (every range used to bucket hourly — 30d would then return ~720 points).
    // A couple of buckets of slack each way absorbs boundary alignment.
    if (hour.length > 0) expect(hour.length, "1h must bucket at 5 minutes, not hourly").toBeLessThanOrEqual(14);
    if (month.length > 0) expect(month.length, "30d must bucket daily, not hourly").toBeLessThanOrEqual(32);
  });
});

test.describe("Overview — Monitor mode reports what WOULD have been blocked", () => {
  test("would_blocked counts softened decisions while blocked stays 0", async ({ request }) => {
    test.skip(token() === "", "needs an admin token file");
    const auth = { Authorization: `Bearer ${token()}`, "Content-Type": "application/json" };
    // `chatbot-prod` is a namespace out of the DOCS, not out of this cluster. kind-e2e installs with
    // policyQuotaNamespaces={agents,analytics} and seed.py seeds `analytics` + `default`, so no policy
    // has ever existed for `chatbot-prod`. NRVQ_NO_POLICY_DECISION is "allow", so all four calls below
    // returned allow/default_allow; `_apply_posture` softens only block and escalate, so there was
    // nothing to soften and would_blocked was correctly 0. The tile was not lying — the fixture was
    // empty, and "no policy here" and "the counter is broken" produced the identical silent 0.
    //
    // `analytics` is a namespace this cluster actually governs: the chart renders
    // baseline-cluster-guard-analytics with preset `strict` at enforcementMode `audit`, so a block
    // there is already recorded as `policy_audit_would_block:` — which is exactly the mechanism under
    // test, and one WOULD_BLOCK_RULE_PREFIXES counts.
    const target = process.env.NRVQ_E2E_MONITOR_NS ?? "analytics";

    const settingsUrl = `${API}/api/v1/settings?namespace=${target}`;
    const before = await (await withTransportRetry(() => request.get(settingsUrl, { headers: auth }))).json();
    const priorMode = before?.enforcement_mode ?? "block";

    const flip = await withTransportRetry(() =>
      request.put(settingsUrl, { headers: auth, data: { enforcement_mode: "audit" } })
    );
    test.skip(flip.status() >= 400, `cannot set monitor mode on ${target}`);

    try {
      await new Promise((r) => setTimeout(r, 6000)); // namespace posture is cached in-proc

      // The counter BEFORE this test's own traffic — see the delta assertions below.
      const baseline = await (
        await withTransportRetry(() =>
          request.get(`${API}/api/v1/audit/stats?range=1h&namespace=${target}`, { headers: auth })
        )
      ).json();

      // ASSERT ON THIS TEST'S OWN TRAFFIC, not just on an aggregate. Reading /audit/stats blind is what
      // made this spec unable to tell "the namespace has no policy", "the class was filtered as
      // synthetic", "the posture never converged" and "the counter is broken" apart — every one of them
      // is the same silent 0. The evaluate response carries the decision and rule_id for the very call
      // just made, so the softening is verified where it happens.
      const softened: string[] = [];
      for (let i = 0; i < 4; i++) {
        const ev = await withTransportRetry(() => request.post(`${API}/api/v1/evaluate`, {
          headers: auth,
          data: {
            tool_name: "execute_sql",
            // DISTINCT per call. Four byte-identical evaluates coalesce: `event.mcp`-keyed evaluation
            // caching returns the first decision for the rest, so one audit row is written and the
            // delta below was 1 where the loop count says 4. Varying the table keeps every call a
            // genuine block of the same shape while giving each its own cache key — which is what makes
            // this a test of the COUNTER rather than of the cache.
            tool_params: { query: `DROP TABLE payments_${i}` },
            framework: "langchain",
            session_id: "e2e-monitor",
            agent_identity: {
              spiffe_id: `spiffe://norviq/ns/${target}/sa/chatbot`,
              namespace: target,
              agent_class: "chatbot",
              service_account: "chatbot",
              framework: "langchain"
            }
          }
        }));
        const body = await ev.json();
        softened.push(String(body.rule_id ?? ""));
      }

      // A softened would-block carries the prefix; a live block or a plain allow does not. This fails
      // loudly and specifically when the fixture is wrong: `default_allow` means the namespace has no
      // policy, a bare `deny_*` means the posture never softened.
      expect(
        softened.every((r) => r.startsWith("policy_audit_would_block:") || r.startsWith("monitor_would_block:")),
        `expected every call to be SOFTENED in ${target}; got rule_ids ${JSON.stringify(softened)}`
      ).toBe(true);

      // POLL, never read once. `_persist_behavior` is queued as BACKGROUND work — the evaluate response
      // returns before its audit row is written — so a single read after four calls sees however many
      // happened to have landed. Measured across runs: 0 with the wrong namespace, then 1, then 2. The
      // decisions were never in doubt (the per-call assertion above passed every time); only their rows
      // were still in flight. Reading once turned an async write into an arithmetic-looking failure.
      let stats = baseline;
      for (let i = 0; i < 40; i++) {
        stats = await (
          await withTransportRetry(() =>
            request.get(`${API}/api/v1/audit/stats?range=1h&namespace=${target}`, { headers: auth })
          )
        ).json();
        if ((stats.would_blocked ?? 0) - (baseline.would_blocked ?? 0) >= 4) break;
        await new Promise((r) => setTimeout(r, 500));
      }

      // The bug: the tile relabels itself "Would-block" in Monitor mode but read `blocked`, which is 0
      // BY CONSTRUCTION here — so the one mode whose whole purpose is showing what would have been
      // stopped reported that nothing would have been.
      //
      // Deltas rather than absolutes. `analytics` is a shared namespace in this cluster and other specs
      // drive traffic through it, so pinning `blocked` to exactly 0 would make this test fail for
      // somebody else's reasons — and, worse, pass for them too.
      expect(stats.would_blocked - baseline.would_blocked,
        "monitor mode must report the would-blocks this test just generated").toBeGreaterThanOrEqual(4);
      expect(stats.blocked - baseline.blocked,
        "monitor mode emits no live block — this must not be inflated").toBe(0);
      expect(stats.would_block_rate_pct).toBeGreaterThan(0);
    } finally {
      // Always hand the namespace back exactly as found — a monitored tenant left behind is a silently
      // unenforced one.
      await withTransportRetry(() =>
        request.put(settingsUrl, { headers: auth, data: { enforcement_mode: priorMode } })
      );
    }
  });
});
