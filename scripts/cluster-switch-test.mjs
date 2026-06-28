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
    const u = r.url();
    if (u.includes("/api/")) apiCalls.push({ url: u.replace(BASE, ""), status: r.status() });
  });

  await page.goto(BASE + "/", { waitUntil: "domcontentloaded", timeout: 25000 });
  await page.evaluate((t) => localStorage.setItem("nrvq_token", t), ADMIN_TOKEN);
  await page.reload({ waitUntil: "domcontentloaded", timeout: 25000 });
  await sleep(3000);

  const before = apiCalls.length;
  console.log("API calls before switch:", before);
  apiCalls.forEach(c => console.log(" ", c.status, c.url));

  // Open cluster selector
  await page.getByText(/production-aks/i).first().click({ timeout: 5000 });
  await sleep(1000);

  // Click staging-aks
  await page.getByText(/staging-aks/i).first().click({ timeout: 5000 });
  await sleep(3000);
  await page.screenshot({ path: path.join(SHOTS, "after-cluster-switch.png"), fullPage: false });

  const after = apiCalls.slice(before);
  console.log("\nAPI calls AFTER switching to staging-aks:", after.length);
  after.forEach(c => console.log(" ", c.status, c.url));

  // Check what cluster is shown now
  const topbarText = await page.locator("header, [class*='topbar']").first().innerText().catch(() => "");
  console.log("\nTopbar after switch:", topbarText.slice(0, 200));

  // Check if staging-aks appears in API urls
  const stagingCalls = after.filter(c => /staging|cluster/i.test(c.url));
  console.log("Staging-related API calls:", stagingCalls);

  // Check if it's same endpoint with different cluster param
  const clusterParamCalls = after.filter(c => /cluster=/.test(c.url));
  console.log("cluster= param calls:", clusterParamCalls);

  // Now try switching namespace to payments
  await page.getByText(/staging-aks/i).first().click({ timeout: 5000 }).catch(() => {
    // maybe re-open the dropdown
    return page.getByText(/production-aks|staging-aks/i).first().click({ timeout: 3000 });
  });
  await sleep(1000);
  const beforeNS = apiCalls.length;
  await page.getByText(/payments/i).first().click({ timeout: 5000 });
  await sleep(3000);
  await page.screenshot({ path: path.join(SHOTS, "after-namespace-switch.png"), fullPage: false });

  const afterNS = apiCalls.slice(beforeNS);
  console.log("\nAPI calls AFTER switching namespace to payments:", afterNS.length);
  afterNS.forEach(c => console.log(" ", c.status, c.url));

  // Check if namespace=payments appears
  const nsCalls = afterNS.filter(c => /namespace=payments/.test(c.url));
  console.log("namespace=payments calls:", nsCalls);

  await browser.close();
}
main().catch(e => { console.error("FATAL:", e); process.exit(1); });
