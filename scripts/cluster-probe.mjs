import { chromium } from "playwright";
import { readFileSync } from "node:fs";
import path from "node:path";

const ENV = JSON.parse(readFileSync(path.resolve(".reviews/customer-eval/env.json"), "utf8"));
const BASE = ENV.urls.ui_a;
const ADMIN_TOKEN = ENV.tokens.admin;
const SHOTS = path.resolve(".reviews/customer-eval/findings/ui-shots");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const browser = await chromium.launch({
    headless: true,
    args: ["--no-proxy-server", "--proxy-bypass-list=*", "--disable-extensions"],
  });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  const apiCalls = [];
  page.on("response", (r) => {
    const s = r.status();
    const u = r.url();
    if (u.includes("/api/")) apiCalls.push({ url: u, status: s });
  });

  // Navigate + inject token
  await page.goto(BASE + "/", { waitUntil: "domcontentloaded", timeout: 25000 });
  await page.evaluate((t) => localStorage.setItem("nrvq_token", t), ADMIN_TOKEN);
  await page.reload({ waitUntil: "domcontentloaded", timeout: 25000 });
  await sleep(3000);

  // Screenshot before interaction
  await page.screenshot({ path: path.join(SHOTS, "cluster-before.png"), fullPage: false });

  // Find the cluster selector button (shows "production-aks / default")
  console.log("Looking for cluster selector...");
  const topbar = await page.locator("header, nav, [class*='topbar'], [class*='top-bar'], [class*='header']").first().innerHTML().catch(() => "");
  console.log("Topbar HTML:", topbar.slice(0, 600));

  // The selector shows "production-aks / default" — try clicking it
  const clusterBtn = page.getByText(/production-aks/i).first();
  const clusterBtnExists = await clusterBtn.count();
  console.log("Cluster btn found:", clusterBtnExists);

  if (clusterBtnExists) {
    const boundingBox = await clusterBtn.boundingBox();
    console.log("Cluster btn boundingBox:", boundingBox);
    await clusterBtn.click({ timeout: 5000 });
    await sleep(1500);
    await page.screenshot({ path: path.join(SHOTS, "cluster-dropdown-open.png"), fullPage: false });
    console.log("Took cluster dropdown screenshot");

    // Look at what's visible after click
    const body = (await page.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
    console.log("Body after click:", body.slice(0, 500));

    // Look for dropdown options
    const options = await page.locator("[role='option'], [role='menuitem'], [role='listitem'], li").allInnerTexts().catch(() => []);
    console.log("Options found:", options.slice(0, 20));

    // Look for lumina-b or cluster options
    const lumina = await page.getByText(/lumina-b|cluster-b|lumina.b/i).count();
    console.log("lumina-b mentions:", lumina);

    // Look for namespace options like payments, default
    const ns = await page.getByText(/payments|kube-system/i).count();
    console.log("namespace mentions:", ns);

    // Get all clickable elements in dropdown area
    const allText = await page.evaluate(() => {
      const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      const texts = [];
      let node;
      while (node = walker.nextNode()) {
        const t = node.textContent.trim();
        if (t.length > 0 && t.length < 60) texts.push(t);
      }
      return texts;
    });
    console.log("All text nodes:", allText.slice(0, 50));
  }

  // Also probe the "default" part of the selector
  const defaultBtn = page.getByText(/^default$/).first();
  if (await defaultBtn.count()) {
    await defaultBtn.click({ timeout: 3000 });
    await sleep(1500);
    await page.screenshot({ path: path.join(SHOTS, "namespace-dropdown-open.png"), fullPage: false });
    console.log("Namespace dropdown screenshot taken");
    const options2 = await page.locator("[role='option'], [role='menuitem'], li").allInnerTexts().catch(() => []);
    console.log("Namespace options:", options2.slice(0, 20));
  }

  // Also check if there's a combined cluster/namespace picker
  const chevronBtn = page.locator("button").filter({ hasText: /production-aks.*default|default.*production-aks/ }).first();
  if (await chevronBtn.count()) {
    console.log("Found combined cluster/ns button");
    await chevronBtn.click({ timeout: 3000 });
    await sleep(1500);
    await page.screenshot({ path: path.join(SHOTS, "combined-selector-open.png"), fullPage: false });
    const opts = await page.locator("[role='option'], [role='menuitem'], li").allInnerTexts().catch(() => []);
    console.log("Combined selector options:", opts.slice(0, 20));
  }

  // Check the actual HTML of the selector area
  const selectorHtml = await page.locator("button, [role='combobox']").filter({ hasText: /production-aks|default/ }).first().evaluate(el => el.outerHTML).catch(() => "not found");
  console.log("Selector HTML:", selectorHtml.slice(0, 500));

  console.log("\nAPI calls made:", apiCalls.length);
  apiCalls.forEach(c => console.log(" ", c.status, c.url.replace(BASE, "")));

  await browser.close();
}
main().catch(e => { console.error("FATAL:", e); process.exit(1); });
