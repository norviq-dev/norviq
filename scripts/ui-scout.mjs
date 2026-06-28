// SPDX-License-Identifier: Apache-2.0
// UI Scout — customer-eval Playwright script for Norviq Security Console
// Runs headless Chromium, injects admin JWT, visits all routes, screenshots + gathers evidence.
import { chromium } from "playwright";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";

const ENV = JSON.parse(readFileSync(path.resolve(".reviews/customer-eval/env.json"), "utf8"));
const BASE = ENV.urls.ui_a;          // http://127.0.0.1:18081
const API  = ENV.urls.api_a;         // http://127.0.0.1:18080
const ADMIN_TOKEN = ENV.tokens.admin;

const SHOTS = path.resolve(".reviews/customer-eval/findings/ui-shots");
mkdirSync(SHOTS, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const results = [];

// ── page factory ──────────────────────────────────────────────────────────────
async function newPage(context) {
  const page = await context.newPage();
  const consoleErrors = [];
  const networkErrors = [];
  const apiCalls = [];
  const wsEvents = [];

  page.on("console", (m) => {
    if (m.type() === "error") consoleErrors.push(m.text().slice(0, 400));
  });
  page.on("pageerror", (e) => consoleErrors.push("PAGEERROR: " + String(e).slice(0, 400)));
  page.on("response", (r) => {
    const u = r.url();
    const s = r.status();
    // capture any API call
    if (u.includes("/api/") || u.includes(API)) {
      apiCalls.push({ url: u, status: s });
    }
    if (s >= 400) {
      networkErrors.push({ url: u, status: s });
    }
  });
  page.on("websocket", (ws) => {
    wsEvents.push("ws-open:" + ws.url());
    ws.on("socketerror", (e) => wsEvents.push("ws-error:" + String(e).slice(0, 120)));
    ws.on("close", () => wsEvents.push("ws-close"));
  });

  return { page, consoleErrors, networkErrors, apiCalls, wsEvents };
}

// ── visit helper ──────────────────────────────────────────────────────────────
async function visit(context, name, route, interact) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, "-");
  const { page, consoleErrors, networkErrors, apiCalls, wsEvents } = await newPage(context);
  const rec = {
    name, route, slug, rendered: false,
    consoleErrors, networkErrors, apiCalls, wsEvents,
    interactions: {}, notes: [],
  };

  try {
    // Navigate to the actual origin first so localStorage is accessible
    await page.goto(BASE + route, { waitUntil: "domcontentloaded", timeout: 25000 });
    // Inject token into localStorage on the real origin, then reload
    await page.evaluate((t) => { try { localStorage.setItem("nrvq_token", t); } catch(e){} }, ADMIN_TOKEN);
    await page.reload({ waitUntil: "domcontentloaded", timeout: 25000 });
    await sleep(3500); // let API calls fire + render settle
    const bodyText = (await page.locator("body").innerText().catch(() => "")).trim();
    rec.rendered = bodyText.length > 0;
    rec.bodyLength = bodyText.length;
    rec.title = await page.title().catch(() => "");
    rec.bodySample = bodyText.replace(/\s+/g, " ").slice(0, 400);
    if (interact) await interact(page, rec);
  } catch (e) {
    rec.notes.push("NAV/INTERACT ERROR: " + String(e).slice(0, 300));
  }

  try {
    await page.screenshot({ path: path.join(SHOTS, `${slug}.png`), fullPage: true });
    rec.screenshot = `.reviews/customer-eval/findings/ui-shots/${slug}.png`;
  } catch (e) {
    rec.notes.push("screenshot failed: " + String(e).slice(0, 120));
  }

  results.push(rec);
  await page.close();
  const errCount = consoleErrors.length + networkErrors.length;
  console.log(`[done] ${name}: rendered=${rec.rendered} bodyLen=${rec.bodyLength} consoleErr=${consoleErrors.length} netErr=${networkErrors.length} api=${apiCalls.length}`);
  if (consoleErrors.length) console.log(`  consoleErrors: ${consoleErrors.slice(0,3).join(" | ")}`);
  if (networkErrors.length) console.log(`  netErrors: ${networkErrors.map(e=>e.status+" "+e.url.slice(0,80)).slice(0,5).join(" | ")}`);
  return rec;
}

// ── interaction helpers ───────────────────────────────────────────────────────
const clickByText = async (page, rx, timeout = 5000) => {
  const el = page.getByRole("button", { name: rx }).first();
  await el.waitFor({ state: "visible", timeout });
  await el.click();
  return true;
};

async function probeClusterSelector(page, rec) {
  // Look for a cluster selector in the top bar
  const clusterSelInfo = {};

  // Try to find any dropdown/select that mentions cluster or lumina
  const allSelects = await page.locator("select").all();
  clusterSelInfo.selectCount = allSelects.length;

  // Look for combobox or dropdown with cluster-related text
  const clusterText = await page.getByText(/lumina|cluster/i).allInnerTexts().catch(() => []);
  clusterSelInfo.clusterTextFound = clusterText.slice(0, 5);

  // Check for any top-bar / header cluster UI
  const headerHtml = await page.locator("header, nav, [class*='header'], [class*='topbar'], [class*='top-bar']").first().innerHTML().catch(() => "");
  clusterSelInfo.headerSample = headerHtml.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").slice(0, 300);

  // Try clicking any cluster selector
  const before = rec.apiCalls.length;
  let switched = false;
  try {
    // Try native select with cluster/namespace options
    for (const sel of allSelects) {
      const opts = await sel.evaluate(s => [...s.options].map(o => o.text));
      clusterSelInfo.selectOptions = opts;
      if (opts.some(o => /lumina-b|cluster.b/i.test(o))) {
        await sel.selectOption({ label: opts.find(o => /lumina-b/i.test(o)) });
        switched = true;
        clusterSelInfo.switchMethod = "native-select";
        break;
      }
    }
  } catch (e) { clusterSelInfo.selectErr = String(e).slice(0, 100); }

  if (!switched) {
    // Try combobox / button-based cluster selector
    try {
      const combo = page.getByRole("combobox").first();
      if (await combo.count()) {
        await combo.click({ timeout: 2000 });
        await sleep(800);
        const opts = await page.getByRole("option").allInnerTexts().catch(() => []);
        clusterSelInfo.comboOptions = opts;
        const bOpt = opts.find(o => /lumina-b|cluster.b/i.test(o));
        if (bOpt) {
          await page.getByRole("option", { name: bOpt }).click({ timeout: 2000 });
          switched = true;
          clusterSelInfo.switchMethod = "combobox";
        }
      }
    } catch (e) { clusterSelInfo.comboErr = String(e).slice(0, 100); }
  }

  await sleep(2000);
  const newCalls = rec.apiCalls.slice(before);
  clusterSelInfo.switched = switched;
  clusterSelInfo.newApiCallsAfterSwitch = newCalls.map(c => ({ url: c.url.replace(BASE, ""), status: c.status }));
  clusterSelInfo.clusterBDataSeen = newCalls.some(c => /lumina.b|cluster.b/i.test(c.url));
  return clusterSelInfo;
}

// ── main ─────────────────────────────────────────────────────────────────────
async function main() {
  const browser = await chromium.launch({
    headless: true,
    args: ["--no-proxy-server", "--proxy-bypass-list=*", "--disable-extensions"],
  });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });

  // Token injection handled per-page via page.evaluate + reload (avoids SecurityError on about:blank)

  // ── 1. Dashboard ─────────────────────────────────────────────────────────
  await visit(context, "Dashboard", "/", async (page, rec) => {
    const body = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
    rec.interactions.hasBlockRate = /block.?rate|blocked/i.test(body);
    rec.interactions.hasTrustDist = /trust.?(distribution|score|level)/i.test(body);
    rec.interactions.hasTopBlocked = /top.?blocked|blocked.?tool/i.test(body);
    rec.interactions.hasKPIs = /\d+/.test(body); // any numeric KPI
    rec.interactions.hasAgentNames = /support.?bot|rogue.?bot|ledger.?bot|kiosk.?bot|mixed.?bot/i.test(body);
    rec.interactions.hasBanner = /unavailable|partial|error|seeding/i.test(body);
    // Check for chart/graph elements
    rec.interactions.svgCount = await page.locator("svg").count().catch(() => 0);
    rec.interactions.cardCount = await page.locator("[class*='card'], [class*='metric'], [class*='stat']").count().catch(() => 0);
  });

  // ── 2. Policy Catalog ────────────────────────────────────────────────────
  await visit(context, "Policy Catalog", "/policies/catalog", async (page, rec) => {
    await sleep(2000);
    rec.interactions.monacoMounted = (await page.locator(".monaco-editor").count()) > 0;
    rec.interactions.rowCount = await page.locator("table tr, [role='row']").count().catch(() => 0);
    rec.interactions.policyNames = await page.getByText(/allow|block|rogue|ledger|support|kiosk|mixed/i).allInnerTexts().catch(() => []);

    // Dry-Run button
    try {
      await clickByText(page, /dry.?run/i, 6000);
      await sleep(3000);
      const dr = await page.locator("body").innerText().catch(() => "");
      rec.interactions.dryRunResult = /records|checked|block|calls|would|recommend|result|decision/i.test(dr)
        ? dr.replace(/\s+/g, " ").slice(0, 400)
        : "(no result text found)";
      await page.screenshot({ path: path.join(SHOTS, "policy-catalog-dryrun.png"), fullPage: true });
    } catch (e) {
      rec.interactions.dryRunResult = "Dry-Run not triggered: " + String(e).slice(0, 150);
    }

    // Probe cluster/namespace selector
    rec.interactions.clusterSelector = await probeClusterSelector(page, rec);
  });

  // ── 3. Audit Log ─────────────────────────────────────────────────────────
  await visit(context, "Audit Log", "/audit", async (page, rec) => {
    await sleep(1500);
    rec.interactions.rowCount = await page.locator("table tbody tr, [role='row']").count().catch(() => 0);
    rec.interactions.liveIndicator = (await page.getByText(/live/i).count()) > 0;
    rec.interactions.hasDecisionCol = /decision|allow|block|escalate/i.test(await page.locator("body").innerText().catch(() => ""));

    // Click filter tab "block" if present
    const before = rec.apiCalls.length;
    try {
      const blockTab = page.getByText(/^block$/i).or(page.getByRole("button", { name: /block/i })).first();
      if (await blockTab.count()) {
        await blockTab.click({ timeout: 3000 });
        await sleep(1500);
        rec.interactions.filterRefetch = rec.apiCalls.slice(before).map((c) => ({ url: c.url, status: c.status }));
        await page.screenshot({ path: path.join(SHOTS, "audit-filtered.png"), fullPage: true });
      } else {
        rec.interactions.filterRefetch = "no block tab found";
      }
    } catch (e) { rec.notes.push("filter tab: " + String(e).slice(0, 100)); }

    // Probe cluster selector
    rec.interactions.clusterSelector = await probeClusterSelector(page, rec);
  });

  // ── 4. Agents ─────────────────────────────────────────────────────────────
  await visit(context, "Agents", "/agents", async (page, rec) => {
    const body = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
    rec.interactions.rowCount = await page.locator("table tbody tr, [role='row']").count().catch(() => 0);
    rec.interactions.hasTrustScore = /trust.?score|score/i.test(body);
    rec.interactions.hasSignals = /signal|anomal|behav/i.test(body);
    rec.interactions.agentNames = /support.?bot|rogue.?bot|ledger.?bot|kiosk.?bot|mixed.?bot/i.test(body);
    rec.interactions.frozenKiosk = /frozen|kiosk/i.test(body);
    rec.interactions.emptyState = /no agents|nothing|empty/i.test(body);
    rec.interactions.has401 = rec.apiCalls.filter(c => c.status === 401).length > 0;

    // Probe cluster selector
    rec.interactions.clusterSelector = await probeClusterSelector(page, rec);
  });

  // ── 5. Policy Tester ──────────────────────────────────────────────────────
  await visit(context, "Policy Tester", "/test", async (page, rec) => {
    const body = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
    rec.interactions.isStub = /coming.?soon|not.?yet|placeholder|todo/i.test(body);

    try {
      // Try preset selection
      const presetEl = page.getByText(/sql.?injection|preset|example/i).first();
      if (await presetEl.count()) { await presetEl.click().catch(() => {}); }
      const before = rec.apiCalls.length;
      await clickByText(page, /evaluate|run|test|submit/i, 5000);
      await sleep(2500);
      rec.interactions.evaluateMadeApiCall = rec.apiCalls.length > before;
      const out = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
      rec.interactions.evaluateResult = /allow|block|escalate|audit|decision|result|error/i.test(out)
        ? out.slice(0, 400)
        : "(no result text)";
      await page.screenshot({ path: path.join(SHOTS, "policy-tester-result.png"), fullPage: true });
    } catch (e) {
      rec.interactions.evaluateResult = "Evaluate not triggered: " + String(e).slice(0, 150);
    }
  });

  // ── 6. Attack Graph ───────────────────────────────────────────────────────
  await visit(context, "Attack Graph", "/threats/graph", async (page, rec) => {
    await sleep(2500);
    rec.interactions.svgPaths = await page.locator("svg path, svg line").count().catch(() => 0);
    rec.interactions.svgCircles = await page.locator("svg circle").count().catch(() => 0);
    rec.interactions.svgNodes = await page.locator("svg [class*='node'], svg g").count().catch(() => 0);
    const body = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
    rec.interactions.isStub = /coming.?soon|placeholder|not.?yet/i.test(body);
    rec.interactions.hasPathData = /attack.?path|path.?score|lateral|pivot|escalat/i.test(body);

    // Simulate button
    const before = rec.apiCalls.length;
    try {
      await clickByText(page, /simulate/i, 4000);
      await sleep(2000);
      rec.interactions.simulateMadeApiCall = rec.apiCalls.length > before;
      rec.interactions.simulateNote = rec.apiCalls.length > before
        ? "made API call(s): " + rec.apiCalls.slice(before).map(c=>c.url.replace(BASE,"")+":"+c.status).join(", ")
        : "no network call (client-only or stub)";
      await page.screenshot({ path: path.join(SHOTS, "attack-graph-simulated.png"), fullPage: true });
    } catch (e) { rec.interactions.simulateNote = "Simulate not found: " + String(e).slice(0, 120); }

    // Probe cluster selector
    rec.interactions.clusterSelector = await probeClusterSelector(page, rec);
  });

  // ── 7. MITRE Coverage ─────────────────────────────────────────────────────
  await visit(context, "MITRE Coverage", "/threats/mitre", async (page, rec) => {
    const body = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
    rec.interactions.isStub = /coming.?soon|placeholder|not.?yet|todo/i.test(body);
    rec.interactions.hasMatrix = (await page.locator("table, [class*='matrix'], [class*='mitre'], svg").count()) > 0;
    rec.interactions.hasTactic = /initial.?access|execution|persistence|privilege|defense|credential|discovery|lateral|collection|exfiltrat|impact/i.test(body);
    rec.interactions.cellCount = await page.locator("td, [class*='cell'], [class*='technique']").count().catch(() => 0);
    rec.interactions.bodySample = body.slice(0, 400);
  });

  // ── 8. Asset Graph ─────────────────────────────────────────────────────────
  await visit(context, "Asset Graph", "/asset-graph", async (page, rec) => {
    await sleep(2500);
    rec.interactions.svgCircles = await page.locator("svg circle").count().catch(() => 0);
    rec.interactions.svgLinks = await page.locator("svg line, svg path").count().catch(() => 0);
    rec.interactions.svgNodes = await page.locator("svg g").count().catch(() => 0);
    const body = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
    rec.interactions.isStub = /coming.?soon|placeholder|not.?yet/i.test(body);
    rec.interactions.hasAssets = /service|agent|tool|namespace|spiffe/i.test(body);

    // Click a node to see detail panel
    try {
      const node = page.locator("svg circle").first();
      if (await node.count()) {
        await node.click({ timeout: 3000, force: true });
        await sleep(1500);
        const afterClick = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
        rec.interactions.nodeDetailOpened = /detail|spiffe|trust|type:|agent|service/i.test(afterClick);
        await page.screenshot({ path: path.join(SHOTS, "asset-graph-node-clicked.png"), fullPage: true });
      } else {
        rec.interactions.nodeDetailOpened = false;
        rec.interactions.noNodeToClick = true;
      }
    } catch (e) { rec.notes.push("node click: " + String(e).slice(0, 100)); }

    // Probe cluster selector
    rec.interactions.clusterSelector = await probeClusterSelector(page, rec);
  });

  // ── 9. Settings General ───────────────────────────────────────────────────
  await visit(context, "Settings General", "/settings/general", async (page, rec) => {
    const body = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
    rec.interactions.hasForm = (await page.locator("input, select, textarea").count()) > 0;
    rec.interactions.isStub = /coming.?soon|placeholder|not.?yet/i.test(body);

    const before = rec.apiCalls.length;
    try {
      await clickByText(page, /^save/i, 4000);
      await sleep(1500);
      rec.interactions.saveMadeApiCall = rec.apiCalls.length > before;
      rec.interactions.saveToast = (await page.getByText(/saved|success|updated/i).count()) > 0;
      rec.interactions.saveNote = rec.apiCalls.length > before
        ? "PATCH/PUT made: " + rec.apiCalls.slice(before).map(c => c.url.replace(BASE,"")+":"+c.status).join(", ")
        : "no network call (button is no-op or not found)";
    } catch (e) { rec.interactions.saveNote = "Save not found: " + String(e).slice(0, 150); }
  });

  // ── 10. Settings Account ──────────────────────────────────────────────────
  await visit(context, "Settings Account", "/settings/account", async (page, rec) => {
    const body = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
    rec.interactions.isStub = /coming.?soon|placeholder|not.?yet/i.test(body);
    rec.interactions.hasLogout = /logout|sign.?out/i.test(body);
    rec.interactions.hasUserInfo = /lumina.?secops|admin|role|email/i.test(body);
    rec.interactions.bodySample = body.slice(0, 300);

    // Probe logout
    try {
      const logoutBtn = page.getByRole("button", { name: /logout|sign.?out/i }).first();
      if (await logoutBtn.count()) {
        rec.interactions.logoutButtonExists = true;
        // Do NOT click it — would end the session
      } else {
        rec.interactions.logoutButtonExists = false;
      }
    } catch (e) { rec.notes.push("logout probe: " + String(e).slice(0, 80)); }
  });

  // ── Cluster selector deep-dive on Dashboard ───────────────────────────────
  // Re-visit dashboard with explicit cluster selector probe
  const clusterRec = { name: "ClusterSelector-Dashboard", route: "/", interactions: {}, notes: [], apiCalls: [] };
  {
    const { page, consoleErrors, networkErrors, apiCalls, wsEvents } = await newPage(context);
    clusterRec.consoleErrors = consoleErrors;
    clusterRec.networkErrors = networkErrors;
    clusterRec.apiCalls = apiCalls;
    try {
      await page.goto(BASE + "/", { waitUntil: "domcontentloaded", timeout: 20000 });
      await page.evaluate((t) => { try { localStorage.setItem("nrvq_token", t); } catch(e){} }, ADMIN_TOKEN);
      await page.reload({ waitUntil: "domcontentloaded", timeout: 20000 });
      await sleep(3000);
      clusterRec.interactions.clusterSelector = await probeClusterSelector(page, clusterRec);
      await page.screenshot({ path: path.join(SHOTS, "cluster-selector-probe.png"), fullPage: true });
      clusterRec.screenshot = ".reviews/customer-eval/findings/ui-shots/cluster-selector-probe.png";
    } catch (e) { clusterRec.notes.push(String(e).slice(0, 200)); }
    await page.close();
  }
  results.push(clusterRec);
  console.log("[done] ClusterSelector probe: switched=" + clusterRec.interactions.clusterSelector?.switched);

  await browser.close();

  const outPath = path.join(SHOTS, "results.json");
  writeFileSync(outPath, JSON.stringify(results, null, 2));
  console.log("\n==== RESULTS written to " + outPath + " ====");
}

main().catch((e) => { console.error("FATAL:", e); process.exit(1); });
