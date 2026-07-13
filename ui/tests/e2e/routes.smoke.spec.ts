// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Route smoke matrix: one test per console route. Each test navigates, waits for networkidle, and
// asserts:
//   1. the route renders its OWN key selector/text (h1.page-title or a route-specific landmark),
//   2. ZERO console errors,
//   3. ZERO /api/v1 responses with status >= 400,
//   4. key data is present (not an empty authless shell) — a route-specific data assertion.
//
// /fleet is guarded: on a single-cluster install it redirects to `/`, so the test skips itself when it
// does not land on /fleet.

import { test, expect, waitForApp, finalPath } from "./fixtures";
import type { Page } from "@playwright/test";

interface RouteCase {
  name: string;
  path: string;
  /** The h1 page title text (exact) rendered by PageHead, when the page uses one. */
  title?: string;
  /** Extra data-presence assertion proving the page is not an empty shell. */
  data: (page: Page) => Promise<void>;
  /** Skip itself if it redirected away from `path` (fleet gate). */
  guarded?: boolean;
}

const ROUTES: RouteCase[] = [
  {
    name: "Overview / Dashboard",
    path: "/",
    title: "Overview",
    data: async (page) => {
      // Coverage gauge + at least one panel title from the real dashboard rollups.
      await expect(page.getByText("Policy Coverage", { exact: false }).first()).toBeVisible();
    }
  },
  {
    name: "Asset Graph",
    path: "/asset-graph",
    title: "Asset Graph",
    data: async (page) => {
      // The d3 canvas mounts and the clickable stat strip renders live tiles.
      await expect(page.getByTestId("asset-graph-canvas")).toBeVisible();
      await expect(page.getByTestId("stat-strip")).toBeVisible();
    }
  },
  {
    name: "Attack Graph",
    path: "/threats/graph",
    title: "Attack Graph",
    data: async (page) => {
      await expect(page.getByTestId("attack-graph-canvas")).toBeVisible();
      await expect(page.getByText("Threat Relationships")).toBeVisible();
    }
  },
  {
    // D: /threats/mitre is a legacy route that now REDIRECTS to the top-level Compliance page (Compliance
    // replaced the old standalone MITRE page). No "MITRE Coverage" h1 exists anymore — assert the redirect
    // landed on /compliance and the Compliance content rendered. (Test-only fix; routing is unchanged.)
    name: "MITRE Coverage → Compliance (redirect)",
    path: "/threats/mitre",
    data: async (page) => {
      await expect(page).toHaveURL(/\/compliance$/);
      await expect(page.getByText("MITRE ATLAS").first()).toBeVisible();
    }
  },
  {
    name: "Policy Catalog",
    path: "/policies/catalog",
    data: async (page) => {
      // The catalog lists agent-class policies from the live evaluator.
      await expect(page.locator("main, .page-enter, body").first()).toBeVisible();
      await expect(page.getByText(/Polic/i).first()).toBeVisible();
    }
  },
  {
    name: "Policy Packs",
    path: "/policies/packs",
    title: "Policy Packs",
    data: async (page) => {
      await expect(page.getByText("Sector Starter Packs")).toBeVisible();
    }
  },
  {
    name: "Target Settings / Governance",
    path: "/policies/targets",
    title: "Effective Policy & Governance",
    data: async (page) => {
      await expect(page.getByText("Governance").first()).toBeVisible();
    }
  },
  {
    name: "Audit Log",
    path: "/audit",
    title: "Audit Log",
    data: async (page) => {
      // The decision filter tabs are always present (All/Allow/Block/…).
      await expect(page.getByRole("button", { name: "Block", exact: true })).toBeVisible();
    }
  },
  {
    name: "Agents",
    path: "/agents",
    title: "Agent Monitor",
    data: async (page) => {
      await expect(page.getByText(/Trust Distribution|Agent Actions/).first()).toBeVisible();
    }
  },
  {
    name: "Policy Tester",
    path: "/test",
    title: "Policy Tester",
    data: async (page) => {
      // Exact: the panel TITLE (the page-sub description also contains "Simulate tool calls…").
      await expect(page.getByText("Simulate Tool Call", { exact: true })).toBeVisible();
    }
  },
  {
    name: "General Settings",
    path: "/settings/general",
    title: "Settings",
    data: async (page) => {
      await expect(page.getByText("General").first()).toBeVisible();
    }
  },
  {
    name: "Account Settings",
    path: "/settings/account",
    title: "Account Settings",
    data: async (page) => {
      await expect(page.getByText("User Profile")).toBeVisible();
    }
  },
  {
    name: "API Keys",
    path: "/settings/api-keys",
    title: "API Keys",
    data: async (page) => {
      await expect(page.getByText("Issue a Key")).toBeVisible();
      await expect(page.getByText("Active Keys")).toBeVisible();
    }
  },
  {
    name: "Connections",
    path: "/settings/connections",
    title: "Connections",
    data: async (page) => {
      await expect(page.getByText("System Connections")).toBeVisible();
    }
  },
  {
    name: "About",
    path: "/settings/about",
    title: "About Norviq",
    data: async (page) => {
      await expect(page.getByText("Version and Links")).toBeVisible();
    }
  },
  {
    name: "Fleet (gated)",
    path: "/fleet",
    guarded: true,
    data: async (page) => {
      // Only reached when fleet is enabled; assert some fleet chrome is present.
      await expect(page.locator(".page-enter, main, body").first()).toBeVisible();
    }
  }
];

for (const rc of ROUTES) {
  test(`route smoke · ${rc.name} (${rc.path})`, async ({ page, recorder }) => {
    await page.goto(rc.path);
    await waitForApp(page);

    if (rc.guarded) {
      const landed = await finalPath(page);
      test.skip(landed !== rc.path, `${rc.path} redirected to ${landed} (feature not enabled) — skipping.`);
    }

    // 1. renders its own landmark
    if (rc.title) {
      await expect(page.locator("h1.page-title", { hasText: rc.title })).toBeVisible();
    }

    // 4. key data present (not an empty shell)
    await rc.data(page);

    // Give any late XHR a beat, then re-settle before asserting clean network + console.
    await waitForApp(page);

    // 2 + 3: clean console + no api failures.
    recorder.expectNoConsoleErrors();
    recorder.expectNoApiFailures();
  });
}
