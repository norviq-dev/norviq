import { chromium } from "playwright";
import { readFileSync } from "node:fs";

const ENV = JSON.parse(readFileSync("/Users/san/Documents/Development/norviq/norviq-migration/repo/.reviews/customer-eval/env.json", "utf8"));
const BASE = ENV.urls.ui_a;
const ADMIN_TOKEN = ENV.tokens.admin;

async function main() {
  const browser = await chromium.launch({ headless: true, args: ["--no-proxy-server", "--proxy-bypass-list=*", "--disable-extensions"] });
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await context.newPage();

  page.on("console", (m) => console.log("CONSOLE [" + m.type() + "]:", m.text().slice(0, 200)));
  page.on("pageerror", (e) => console.log("PAGEERROR:", String(e).slice(0, 200)));
  page.on("response", (r) => console.log("RESP:", r.status(), r.url().slice(0, 100)));

  console.log("Navigating to:", BASE + "/");
  await page.goto(BASE + "/", { waitUntil: "domcontentloaded", timeout: 30000 });
  console.log("Page title:", await page.title());
  console.log("URL after nav:", page.url());
  
  // Check HTML content
  const html = await page.content();
  console.log("HTML length:", html.length);
  console.log("HTML first 500:", html.slice(0, 500));
  
  // Try to set localStorage
  try {
    await page.evaluate((t) => { localStorage.setItem("nrvq_token", t); return "ok"; }, ADMIN_TOKEN);
    console.log("localStorage set ok");
  } catch(e) { console.log("localStorage err:", e.message); }
  
  await page.reload({ waitUntil: "domcontentloaded", timeout: 30000 });
  const html2 = await page.content();
  console.log("\nAfter reload HTML length:", html2.length);
  console.log("After reload HTML first 500:", html2.slice(0, 500));
  
  // Wait longer for SPA
  await new Promise(r => setTimeout(r, 5000));
  const bodyText = await page.locator("body").innerText().catch(e => "ERR: " + e.message);
  console.log("Body text length:", bodyText.length);
  console.log("Body text sample:", bodyText.replace(/\s+/g, " ").slice(0, 300));

  await page.screenshot({ path: "/private/tmp/claude-501/-Users-san-Documents-Development-norviq-norviq-migration/61d892f3-dfc9-4ba4-ab78-22c6b4ebabaa/scratchpad/debug-shot.png" });
  await browser.close();
}
main().catch(e => { console.error("FATAL:", e); process.exit(1); });
