---
name: visual-qa-testing
description: Visually QA a Norviq web page by launching it in Cursor's built-in browser, taking screenshots, checking console errors, and auditing network requests. Use after making UI changes or during Day 9 UI walkthrough.
---

# Visual QA for Norviq UI

Use this skill after UI changes to verify the result, catch console errors, and audit network requests.

## How It Works

Cursor's built-in browser (`cursor-ide-browser` MCP) can navigate, screenshot, read console, inspect network. This skill orchestrates those tools.

## Steps

1. Ensure UI dev server is running:
   ```
   cd ui && npm run dev
   ```
   Watch for "ready" or localhost URL.

2. Navigate to the Norviq UI page:
   ```
   Tool: browser_navigate
   Arguments: { "url": "http://localhost:5173/test", "take_screenshot_afterwards": true }
   ```

3. Take a full-page screenshot:
   ```
   Tool: browser_take_screenshot
   Arguments: { "fullPage": true }
   ```
   Review for: layout breaks, missing content, wrong colors, misaligned elements.

4. Check console for errors:
   ```
   Tool: browser_console_messages
   ```
   Report: TypeError, ReferenceError, failed imports, React hydration mismatches, Monaco loading errors.

5. Audit network requests:
   ```
   Tool: browser_network_requests
   ```
   Look for: 4xx/5xx responses, CORS errors, missing /api/v1/* calls, WebSocket disconnects.

6. Interact if needed:
   - browser_snapshot to get element refs
   - browser_click, browser_fill, browser_hover for interaction
   - Take another screenshot after interaction

7. Report findings to docs/ui-qa-day9.md:
   - Page name
   - Screenshot path
   - Console state (clean / errors listed)
   - Network state (healthy / failures listed)
   - Bugs found -> apply the doable in-scope fix now (per AGENTS.md), then attach the before/after
     screenshots as the T4 EFFECT evidence for Claude's review. Do NOT route to a backlog.

## Norviq Pages to Test (Day 9 walkthrough)

Run this skill against each:
- / (Overview / KPI dashboard)
- /policies (Policy Catalog)
- /test (Policy Tester)
- /audit (Audit Log - verify WebSocket connects)
- /agents (Agents list)
- /asset-graph (Asset Graph visualization)
- /threats/graph (Attack Graph)
- /threats/mitre (MITRE Coverage heatmap)
- /redteam (Red Team placeholder)
- /settings (Settings page)

## Notes

- Always use `browser_snapshot` before clicking to get correct element refs.
- For responsive testing, use `browser_resize` to check viewport sizes.
- Save screenshots to docs/screenshots/day9/<page>.png.
- Use `browser_navigate` with `position: "side"` to view browser beside code.
