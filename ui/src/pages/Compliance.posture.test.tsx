// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The framework pill and the detail hero describe what the namespace does with a match, and how many
// enforced techniques have block evidence. They used to be literals: an "ENFORCED" pill on every card and
// hero, and "Every enforced technique is backed by a live policy and block evidence", including in a
// Monitor namespace whose coverage reported 0 of 8 techniques with any block at all.

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Compliance } from "./Compliance";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";
import { ToastProvider } from "../components/common/Toast";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
beforeEach(() => sessionStorage.setItem("nrvq_token", "test-token"));
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
  sessionStorage.removeItem("nrvq_token");
  localStorage.removeItem("nrvq_namespace");
  localStorage.removeItem("nrvq_namespace_sub");
});
afterAll(() => server.close());

const TECHNIQUES = [
  {
    technique_id: "AML.T0051",
    name: "LLM Prompt Injection",
    scope: "enforceable",
    status: "enforced",
    also: "OWASP LLM · LLM01:2025",
    policies: ["llm01_prompt_injection"],
    covered_policies: ["llm01_prompt_injection"],
    covered: true,
    proven: false,
    observed: 20,
    blocked: 0,
    blocked_by_rule: { llm01_prompt_injection: 0 },
    affected_classes: []
  },
  {
    technique_id: "AML.T0053",
    name: "Plugin Compromise",
    scope: "enforceable",
    status: "enforced",
    policies: ["deny_plugin"],
    covered_policies: ["deny_plugin"],
    covered: true,
    proven: true,
    observed: 9,
    blocked: 9,
    blocked_by_rule: { deny_plugin: 9 },
    affected_classes: []
  },
  {
    technique_id: "AML.T0099",
    name: "Data Exfiltration via Tool",
    scope: "enforceable",
    status: "gap",
    generatable: true,
    priority: "high",
    policies: ["deny_exfil"],
    covered_policies: [],
    covered: false,
    observed: 0,
    blocked: 0,
    affected_classes: [{ class: "support", blocked: 0 }]
  }
];

function coverage(namespace: string, proven: number, techniques: unknown[] = []) {
  return {
    namespace,
    range: "24h",
    framework: "atlas",
    enforceable_total: 10,
    enforced: 8,
    gap: 2,
    oos: 1,
    coverage_pct: 80,
    covered: 8,
    total: 11,
    observed: 30,
    blocked: proven ? 12 : 0,
    agent_classes: 1,
    basis: "rules_present",
    proven,
    degraded: false,
    techniques
  };
}

function seed(
  ns: string,
  settings: { enforcement_mode: "block" | "audit"; enforcement_mode_source: string },
  proven: number,
  techniques: unknown[] = []
) {
  server.use(
    http.get("/api/v1/cluster-info", () => HttpResponse.json({ cluster_id: "local", cluster_name: "local", namespaces: [ns] })),
    http.get("/api/v1/settings", () =>
      HttpResponse.json({ namespace: ns, trust_threshold: 0.7, rate_limit: 60, apply_mode: "enforce", ...settings })
    ),
    http.get("/api/v1/compliance/:framework/coverage", () => HttpResponse.json(coverage(ns, proven, techniques))),
    http.get("/api/v1/compliance/:framework/trend", () => HttpResponse.json({ namespace: ns, range: "30d", points: [] })),
    http.get("/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
  );
}

function renderAt(ns: string) {
  return render(
    <MemoryRouter initialEntries={[`/compliance?ns=${ns}`]}>
      <AppProvider>
        <ToastProvider>
          <Compliance />
        </ToastProvider>
      </AppProvider>
    </MemoryRouter>
  );
}

async function pills(verdict: string) {
  // Both framework cards, once the posture read has settled on `verdict`.
  const found = await screen.findAllByTestId("compliance-posture-pill");
  await screen.findAllByText((_, el) => el?.getAttribute("data-verdict") === verdict);
  return found;
}

describe("Compliance pill and hero follow the namespace posture and the proven count", () => {
  it("a Monitor namespace with no block evidence is never labelled ENFORCED", async () => {
    seed("analytics", { enforcement_mode: "audit", enforcement_mode_source: "namespace" }, 0);
    renderAt("analytics");
    const cards = await pills("monitor");
    expect(cards).toHaveLength(2);
    for (const p of cards) {
      expect(p).toHaveAttribute("data-verdict", "monitor");
      expect(p.textContent).toBe("Monitor · not blocking · 0/8 proven");
    }
    expect(screen.queryByText(/^ENFORCED$/)).not.toBeInTheDocument();

    fireEvent.click((await screen.findAllByText("Open coverage detail →"))[0]);
    const sentence = await screen.findByTestId("compliance-evidence-sentence");
    expect(sentence.textContent).toContain("0 of 8 have block or escalate evidence");
    expect(sentence.textContent).toContain("analytics is in Monitor mode");
    expect(document.body.textContent).not.toContain("Every enforced technique is backed by a live policy and block evidence");
    expect(screen.getByTestId("compliance-posture-pill")).toHaveAttribute("data-verdict", "monitor");
  });

  it("an enforcing namespace states how many enforced techniques are proven, not that all are", async () => {
    seed("payments", { enforcement_mode: "block", enforcement_mode_source: "namespace" }, 4);
    renderAt("payments");
    for (const p of await pills("enforcing")) expect(p.textContent).toBe("Enforcing · 4/8 proven");
  });

  it("audit inherited from the cluster default still enforces this namespace's policies", async () => {
    // The engine relaxes policy blocks only on the namespace's own audit; the merged settings value
    // alone would have labelled this namespace Monitor.
    seed("billing", { enforcement_mode: "audit", enforcement_mode_source: "cluster_default" }, 8);
    renderAt("billing");
    for (const p of await pills("enforcing")) expect(p.textContent).toBe("Enforcing · 8/8 proven");
  });
});

// The per-technique chip, the card's bar legend, the detail legend, the tree group and the filter all said
// "ENFORCED"/"enforced" in a Monitor namespace, two inches from a pill that had stopped saying it. They read
// the same posture as the pill now, and "proven" appears only on a technique with block evidence.
describe("Compliance technique status follows the namespace posture", () => {
  async function openDetail() {
    fireEvent.click((await screen.findAllByText("Open coverage detail →"))[0]);
    return screen.findByTestId("technique-status-chip");
  }

  it("Monitor: rules present, never ENFORCED, on the card, the legend, the tree and the chip", async () => {
    seed("analytics", { enforcement_mode: "audit", enforcement_mode_source: "namespace" }, 1, TECHNIQUES);
    renderAt("analytics");
    await pills("monitor");
    for (const el of await screen.findAllByTestId("compliance-card-present")) {
      expect(el.textContent).toBe("8 rules present · monitor");
    }

    const chip = await openDetail();
    await waitFor(() => expect(chip.textContent).toBe("RULES PRESENT · MONITOR"));
    expect(screen.getByTestId("compliance-detail-present").textContent).toContain("Rules present · monitor · 8");
    expect(screen.getByText("Rules present · monitor 8")).toBeInTheDocument(); // the filter segment

    // The proven technique says so; the unproven one does not.
    fireEvent.click(screen.getByText("Plugin Compromise"));
    await waitFor(() => expect(screen.getByTestId("technique-status-chip").textContent).toBe("RULES PRESENT · MONITOR · PROVEN"));

    expect(document.body.textContent).not.toMatch(/\bENFORCED\b/);
    expect(document.body.textContent).not.toMatch(/\b8 enforced\b/);
    expect(screen.queryByText("Enforced")).not.toBeInTheDocument();
  });

  it("enforcing: ENFORCED, and PROVEN only with block evidence", async () => {
    seed("payments", { enforcement_mode: "block", enforcement_mode_source: "namespace" }, 1, TECHNIQUES);
    renderAt("payments");
    await pills("enforcing");
    for (const el of await screen.findAllByTestId("compliance-card-present")) expect(el.textContent).toBe("8 enforced");

    const chip = await openDetail();
    await waitFor(() => expect(chip.textContent).toBe("ENFORCED"));
    expect(screen.getByTestId("compliance-detail-present").textContent).toContain("Enforced · 8");
    fireEvent.click(screen.getByText("Plugin Compromise"));
    await waitFor(() => expect(screen.getByTestId("technique-status-chip").textContent).toBe("ENFORCED · PROVEN"));
  });

  it("an unread posture claims neither", async () => {
    seed("orders", { enforcement_mode: "block", enforcement_mode_source: "namespace" }, 0, TECHNIQUES);
    server.use(http.get("/api/v1/settings", () => HttpResponse.json({ detail: "db down" }, { status: 503 })));
    renderAt("orders");
    await pills("unknown");
    const chip = await openDetail();
    await waitFor(() => expect(chip.textContent).toBe("RULES PRESENT"));
    expect(document.body.textContent).not.toMatch(/\bENFORCED\b/);
  });

  it("the gap and the cross-framework note make no enforcement claim", async () => {
    seed("analytics", { enforcement_mode: "audit", enforcement_mode_source: "namespace" }, 0, TECHNIQUES);
    renderAt("analytics");
    await pills("monitor");
    await openDetail();
    expect(await screen.findByText(/Same rule also satisfies/)).toBeInTheDocument();
    expect(screen.queryByText(/Same enforcing rule/)).not.toBeInTheDocument();

    fireEvent.click(screen.getByText("Data Exfiltration via Tool"));
    expect(await screen.findByText("Generate policy draft")).toBeInTheDocument();
    expect(screen.queryByText("Generate enforcing policy")).not.toBeInTheDocument();
    expect(screen.getByText(/No loaded policy rule maps to this control yet/)).toBeInTheDocument();
    expect(screen.queryByText(/No enforcing policy maps/)).not.toBeInTheDocument();
  });
});
