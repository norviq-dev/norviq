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

  // Test 1: Namespace switch to payments
  await page.goto(BASE + "/", { waitUntil: "domcontentloaded", timeout: 25000 });
  await page.evaluate((t) => localStorage.setItem("nrvq_token", t), ADMIN_TOKEN);
  await page.reload({ waitUntil: "domcontentloaded", timeout: 25000 });
  await sleep(3000);

  const before = apiCalls.length;
  // Open selector
  await page.getByText(/production-aks/i).first().click({ timeout: 5000 });
  await sleep(800);
  // Click "payments" namespace
  await page.getByText(/^payments$/i).click({ timeout: 5000 });
  await sleep(3000);
  await page.screenshot({ path: path.join(SHOTS, "after-payments-namespace.png"), fullPage: false });

  const after = apiCalls.slice(before);
  console.log("API calls after namespace=payments switch:", after.length);
  after.forEach(c => console.log(" ", c.status, c.url));

  const topbar = await page.getByText(/production-aks/).first().innerText().catch(() => "");
  console.log("Topbar cluster label:", topbar);
  const showingLabel = await page.getByText(/Showing:/i).first().innerText().catch(() => "");
  console.log("Showing label:", showingLabel);

  // Test 2: Red Team page
  const page2 = await context.newPage();
  const apiCalls2 = [];
  page2.on("response", (r) => {
    const u = r.url();
    if (u.includes("/api/")) apiCalls2.push({ url: u.replace(BASE, ""), status: r.status() });
  });
  const consoleErrors2 = [];
  page2.on("console", m => { if (m.type() === "error") consoleErrors2.push(m.text().slice(0,200)); });

  await page2.goto(BASE + "/redteam", { waitUntil: "domcontentloaded", timeout: 25000 });
  await page2.evaluate((t) => localStorage.setItem("nrvq_token", t), ADMIN_TOKEN);
  await page2.reload({ waitUntil: "domcontentloaded", timeout: 25000 });
  await sleep(3000);
  const body2 = (await page2.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
  console.log("\nRed Team page body:", body2.slice(0, 400));
  console.log("Red Team console errors:", consoleErrors2);
  await page2.screenshot({ path: path.join(SHOTS, "red-team.png"), fullPage: true });

  // Test 3: Check if /redteam vs /test - what route is Red Team on?
  // The sidebar shows "Red Team" link
  const rtLink = await page.locator("a").filter({ hasText: /red.?team/i }).first().getAttribute("href").catch(() => "");
  console.log("\nRed Team href:", rtLink);

  // Test 4: Check Agents with payments namespace
  const page3 = await context.newPage();
  const apiCalls3 = [];
  page3.on("response", (r) => {
    const u = r.url();
    if (u.includes("/api/")) apiCalls3.push({ url: u.replace(BASE, ""), status: r.status() });
  });
  await page3.goto(BASE + "/agents", { waitUntil: "domcontentloaded", timeout: 25000 });
  await page3.evaluate((t) => localStorage.setItem("nrvq_token", t), ADMIN_TOKEN);
  await page3.reload({ waitUntil: "domcontentloaded", timeout: 25000 });
  await sleep(3000);
  const agentBody = (await page3.locator("body").innerText().catch(() => "")).replace(/\s+/g, " ");
  console.log("\nAgents body sample:", agentBody.slice(0, 500));
  console.log("Agents API calls:");
  apiCalls3.forEach(c => console.log(" ", c.status, c.url));

  await browser.close();
}
main().catch(e => { console.error("FATAL:", e); process.exit(1); });
