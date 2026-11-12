// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// A policy card's mode pill and health dot are claims about the card's OWN namespace. In a Monitor
// namespace the section header already said "Monitor · would-block", while each card under it still
// showed a red BLOCK pill and a green dot titled "enforcing on matching workloads".

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { PolicyCatalog } from "./PolicyCatalog";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";

vi.mock("@monaco-editor/react", () => ({
  default: ({ value }: { value?: string }) => <div data-testid="monaco-editor">{value}</div>
}));

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
// Signed in, so AppContext reads the scope's posture itself (it skips the read without a token).
beforeEach(() => sessionStorage.setItem("nrvq_token", "test-token"));
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
  sessionStorage.removeItem("nrvq_token");
  localStorage.removeItem("nrvq_namespace");
  localStorage.removeItem("nrvq_namespace_sub");
});
afterAll(() => server.close());

const MODES: Record<string, "block" | "audit"> = { analytics: "audit", payments: "block" };

function seed(namespaces: string[], policyMode: "block" | "audit" = "block") {
  server.use(
    http.get("/api/v1/settings", ({ request }) => {
      const ns = new URL(request.url).searchParams.get("namespace") ?? "default";
      return HttpResponse.json({
        namespace: ns,
        enforcement_mode: MODES[ns] ?? "block",
        enforcement_mode_source: ns in MODES ? "namespace" : "cluster_default",
        trust_threshold: 0.7,
        rate_limit: 60,
        apply_mode: "enforce"
      });
    }),
    http.get("/api/v1/policies", () =>
      HttpResponse.json(
        namespaces.map((ns) => ({
          namespace: ns, agent_class: "data-analyst", target_type: "class",
          current_version: 1, rego_length: 120, priority: 700, enforcement_mode: policyMode, matches: 3
        }))
      )
    ),
    http.get("/api/v1/deployments", () => HttpResponse.json([])),
    ...namespaces.flatMap((ns) => [
      http.get(`/api/v1/policies/${ns}/data-analyst`, () =>
        HttpResponse.json({ namespace: ns, agent_class: "data-analyst", rego_source: "package x\n", version: 1 })
      ),
      http.get(`/api/v1/policies/${ns}/data-analyst/versions`, () => HttpResponse.json([]))
    ])
  );
}

function renderAt(ns: string) {
  render(
    <MemoryRouter initialEntries={[`/policies/catalog?ns=${ns}`]}>
      <AppProvider>
        <PolicyCatalog />
      </AppProvider>
    </MemoryRouter>
  );
  fireEvent.click(screen.getByRole("button", { name: /^catalog$/i }));
}

describe("policy cards follow their namespace's posture", () => {
  it("Monitor namespace: the card says block -> would-block, and the dot does not say enforcing", async () => {
    seed(["analytics"]);
    renderAt("analytics");
    const pill = await screen.findByTestId("policy-mode-monitor-analytics-data-analyst");
    expect(pill).toHaveTextContent("block → would-block");
    expect(screen.getByTestId("policy-health-monitor")).toHaveAttribute("aria-label", "Loaded & evaluated — Monitor mode, not blocking");
    expect(screen.queryByTestId("policy-health-enforcing")).toBeNull();
    expect(screen.getByTestId("active-policies-mode")).toHaveTextContent("Monitor · would-block");
  });

  it("CONTROL: enforcing namespace keeps the BLOCK pill and the enforcing dot", async () => {
    seed(["payments"]);
    renderAt("payments");
    expect(await screen.findByTestId("policy-health-enforcing")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("active-policies-mode")).toHaveTextContent("Enforcing"));
    expect(screen.queryByTestId("policy-mode-monitor-payments-data-analyst")).toBeNull();
  });

  it("all namespaces: each card answers for its own namespace", async () => {
    seed(["analytics", "payments"]);
    renderAt("all");
    expect(await screen.findByTestId("policy-mode-monitor-analytics-data-analyst")).toBeInTheDocument();
    expect(screen.queryByTestId("policy-mode-monitor-payments-data-analyst")).toBeNull();
    expect(screen.getByTestId("policy-health-monitor")).toBeInTheDocument();
    expect(screen.getByTestId("policy-health-enforcing")).toBeInTheDocument();
    expect(screen.getByTestId("active-policies-mode")).toHaveTextContent("Loaded · posture per namespace");
  });
});

// The namespace is half the answer. The evaluator also softens the block of a policy SAVED in audit mode
// (`_apply_policy_mode`), so in an enforcing namespace such a card showed a green "Loaded & enforcing" dot
// over a policy that blocks nothing, and the delete dialog called it "currently enforcing".
describe("policy cards account for the policy's own mode", () => {
  it("audit-mode policy in an enforcing namespace: no enforcing dot", async () => {
    seed(["payments"], "audit");
    renderAt("payments");
    const dot = await screen.findByTestId("policy-health-audit");
    expect(dot).toHaveAttribute("aria-label", "Loaded & evaluated — audit-mode policy, not blocking");
    expect(dot.getAttribute("title")).toMatch(/saved in audit mode/);
    await waitFor(() => expect(screen.getByTestId("active-policies-mode")).toHaveTextContent("Enforcing"));
    expect(screen.queryByTestId("policy-health-enforcing")).toBeNull();
  });

  it("the delete dialog does not call an audit-mode policy enforcing", async () => {
    seed(["payments"], "audit");
    renderAt("payments");
    fireEvent.click(await screen.findByTestId("catalog-delete-data-analyst-payments"));
    const warning = await screen.findByTestId("delete-policy-warning");
    await waitFor(() => expect(warning).toHaveTextContent(/loaded in audit mode, so its matches are logged, not blocked/));
    expect(warning).not.toHaveTextContent(/currently enforcing/);
    // The shipped no-policy default is allow, not fail-closed.
    expect(warning).toHaveTextContent(/no-policy default \(shipped as allow\)/);
    expect(warning).not.toHaveTextContent(/fail-closed/i);
  });

  it("CONTROL: a block-mode policy in an enforcing namespace is still enforcing, also in the delete dialog", async () => {
    seed(["payments"], "block");
    renderAt("payments");
    expect(await screen.findByTestId("policy-health-enforcing")).toBeInTheDocument();
    fireEvent.click(screen.getByTestId("catalog-delete-data-analyst-payments"));
    const warning = await screen.findByTestId("delete-policy-warning");
    await waitFor(() => expect(warning).toHaveTextContent(/currently enforcing/));
  });
});

// "Review the Rego below, then click Create to apply it as an enforcing policy … Nothing enforces until you
// Create" was printed for every draft, in a Monitor namespace too, where Create makes a policy that logs.
describe("the draft-loaded banner says what Create does in the target namespace", () => {
  function seedDraft() {
    server.use(
      http.get("/api/v1/deployments", () => HttpResponse.json([])),
      http.get("/api/v1/threats/intent-drafts", () =>
        HttpResponse.json({
          drafts: [{ draft_id: "d1", ns: "analytics", cls: "report-gen", enabled: ["deny_x"], covered_count: 1, total: 1, created_at: "2026-07-10T12:00:00Z" }],
          total: 1, returned: 1, offset: 0, limit: 15
        })
      ),
      http.get("/api/v1/threats/intent-drafts/d1", () =>
        HttpResponse.json({ draft_id: "d1", ns: "analytics", cls: "report-gen", rego: "package norviq.intent.x\n", enabled: ["deny_x"], covered_count: 1, total: 1, enforcement: "draft" })
      )
    );
  }

  async function loadDraft() {
    render(
      <MemoryRouter initialEntries={["/policies/catalog?ns=analytics&intent_draft=d1"]}>
        <AppProvider>
          <PolicyCatalog />
        </AppProvider>
      </MemoryRouter>
    );
    fireEvent.click(await screen.findByRole("button", { name: /review & apply/i }));
    return screen.findByTestId("draft-loaded-banner");
  }

  it("Monitor namespace: Create makes a policy whose matches are logged", async () => {
    seed([]);
    seedDraft();
    const banner = await loadDraft();
    expect(banner).not.toHaveTextContent(/as an enforcing policy/);
    await waitFor(() => expect(banner).toHaveTextContent(/analytics is in Monitor mode/));
    expect(banner).not.toHaveTextContent(/Nothing enforces/);
  });

  it("CONTROL: an enforcing namespace says a match acts on the call", async () => {
    MODES.analytics = "block";
    try {
      seed([]);
      seedDraft();
      await loadDraft();
      await waitFor(() => expect(screen.getByTestId("draft-loaded-consequence")).toHaveTextContent(/analytics enforces/));
    } finally {
      MODES.analytics = "audit";
    }
  });
});
