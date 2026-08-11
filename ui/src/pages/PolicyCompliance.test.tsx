/**
 * Policy Compliance — the per-policy compliance percentage, its remediation list and its evidence.
 *
 * The assertions are about the ways the PERCENTAGE could be wrong, because a compliance number that
 * is confidently incorrect is worse than no number: counting synthetic identities in the denominator,
 * attributing a rule to the wrong policy, showing 100% when nothing has run, or — the one this
 * console cares about most — rendering an unreadable surface as a clean bill of health.
 */

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as client from "../api/client";
import { clearApiCache } from "../hooks/useApi";
import { PolicyCompliance, ruleIdsIn } from "./PolicyCompliance";

vi.mock("../store/AppContext", async () => {
  const actual = await vi.importActual<typeof import("../store/AppContext")>("../store/AppContext");
  return { ...actual, useApp: () => ({ namespace: "chatbot-prod", activeSection: "security" }) };
});

const EGRESS_REGO = `package norviq.custom.egress
blocks["customer_data_to_untrusted_recipient"] { untrusted_domains[_] }
audits["__never__"] { false }
`;
const SQL_REGO = `package norviq.custom.sql
blocks["demo_destructive_sql"] { contains(lower(input.tool_params.query), "drop ") }
`;

function mockAll(opts: {
  controls?: unknown[];
  scanned?: number;
  principals?: unknown[];
  policies?: unknown[];
  sources?: Record<string, string>;
  complianceError?: boolean;
  sourceError?: string;
  controlsCatalog?: unknown[];
}) {
  const {
    controls = [],
    scanned = 1000,
    principals = [
      { agent_class: "r2-support", synthetic: false },
      { agent_class: "billing", synthetic: false },
      { agent_class: "probe-scanner", synthetic: true }
    ],
    policies = [
      { agent_class: "r2-support", enforcement_mode: "block", current_version: 2 },
      { agent_class: "billing", enforcement_mode: "audit", current_version: 1 }
    ],
    sources = { "r2-support": EGRESS_REGO, billing: SQL_REGO }
  } = opts;

  if (opts.complianceError) {
    vi.spyOn(client, "fetchPolicyCompliance").mockRejectedValue(new Error("503 upstream"));
  } else {
    vi.spyOn(client, "fetchPolicyCompliance").mockResolvedValue({
      namespace: "chatbot-prod",
      range: "7d",
      scanned,
      excluded_synthetic: 0,
      controls
    } as never);
  }
  vi.spyOn(client, "fetchCompliancePrincipals").mockResolvedValue(principals as never);
  vi.spyOn(client, "fetchPolicyList").mockResolvedValue(policies as never);
  vi.spyOn(client, "fetchPolicySource").mockImplementation(async (_ns: string, cls: string) => {
    if (opts.sourceError && cls === opts.sourceError) throw new Error("500");
    return { rego_source: sources[cls] ?? "" } as never;
  });
  vi.spyOn(client, "fetchVolume").mockResolvedValue([] as never);
  vi.spyOn(client, "fetchBaselineControls").mockResolvedValue({
    namespace: "chatbot-prod", preset: "strict", default_effect: "monitor",
    effects: ["off", "monitor", "deny"], counts: { off: 0, monitor: 13, deny: 1 },
    controls: opts.controlsCatalog ?? [
      { id: "pii_detection", title: "PII egress", description: "", effect: "deny" },
      { id: "deny_sql_injection", title: "SQL injection", description: "", effect: "monitor" }
    ]
  } as never);
}

function control(id: string, classes: string[], count = classes.length) {
  return {
    control_id: id,
    count,
    agent_classes: classes.map((n) => ({ name: n, count: 1 })),
    tools: [{ name: "send_email", count }],
    namespaces: ["chatbot-prod"],
    first_seen: null,
    last_seen: null,
    samples: []
  };
}

const renderPage = () => render(<MemoryRouter><PolicyCompliance /></MemoryRouter>);

beforeEach(() => {
  clearApiCache();
  vi.restoreAllMocks();
});

// --- the rule -> policy join -------------------------------------------------------------------

describe("ruleIdsIn", () => {
  it("extracts every partial-set head a policy defines", () => {
    expect(ruleIdsIn(EGRESS_REGO)).toEqual(["customer_data_to_untrusted_recipient"]);
  });

  it("ignores the never-firing sentinel the baseline compiler emits", () => {
    // An all-monitor module registers `audits[id] { false; id := "__never__" }` purely so the partial
    // set is defined and the module compiles. Counting it would invent a rule no operator wrote.
    expect(ruleIdsIn('audits["__never__"] { false }\nblocks["real"] { x }')).toEqual(["real"]);
  });

  it("reads blocks, escalates and audits alike", () => {
    const ids = ruleIdsIn('blocks["a"] { x }\nescalates["b"] { y }\naudits["c"] { z }');
    expect(ids.sort()).toEqual(["a", "b", "c"]);
  });
});

// --- the percentage ----------------------------------------------------------------------------

describe("policy compliance percentage", () => {
  it("scores each policy over agent classes, Azure-style", async () => {
    mockAll({ controls: [control("customer_data_to_untrusted_recipient", ["r2-support"])] });
    renderPage();
    // 2 real classes, 1 of them non-compliant for this policy -> 50%
    const pct = await screen.findByTestId("pc-pct-r2-support");
    expect(pct).toHaveAttribute("data-pct", "50");
    expect(pct.textContent).toContain("1 out of 2");
    // the other policy flagged nobody
    expect(screen.getByTestId("pc-pct-billing")).toHaveAttribute("data-pct", "100");
    expect(screen.getByTestId("pc-state-billing").textContent).toBe("Compliant");
  });

  it("does not count synthetic identities in the denominator", async () => {
    // probe-scanner is a real row and a real principal, but it is a red-team probe, not a customer
    // workload. Counting it would move a number no operator can act on.
    mockAll({ controls: [control("customer_data_to_untrusted_recipient", ["r2-support", "probe-scanner"])] });
    renderPage();
    const pct = await screen.findByTestId("pc-pct-r2-support");
    expect(pct.textContent).toContain("out of 2"); // not 3
    expect(pct).toHaveAttribute("data-pct", "50"); // probe-scanner not in the numerator either
  });

  it("attributes a rule only to the policy that DEFINES it", async () => {
    // Both policies exist; only billing declares demo_destructive_sql. If the join were by namespace
    // rather than by rego head, r2-support would be blamed for a rule it does not contain.
    mockAll({ controls: [control("demo_destructive_sql", ["billing"])] });
    renderPage();
    await screen.findByTestId("pc-pct-billing");
    expect(screen.getByTestId("pc-state-billing").textContent).toBe("Non-compliant");
    expect(screen.getByTestId("pc-state-r2-support").textContent).toBe("Compliant");
  });

  it("rolls the overall figure up over principals, not over policies", async () => {
    // One class offends two different policies. Azure counts RESOURCES, so that is one non-compliant
    // resource out of two — not two.
    mockAll({
      controls: [
        control("customer_data_to_untrusted_recipient", ["r2-support"]),
        control("demo_destructive_sql", ["r2-support"])
      ]
    });
    renderPage();
    // Wait on the ATTRIBUTE, not the element: `pc-overall` exists in the loading branch too (carrying
    // data-pct="unknown"), so findByTestId resolves before the data lands.
    await waitFor(() => expect(screen.getByTestId("pc-overall")).toHaveAttribute("data-pct", "50"));
    const overall = screen.getByTestId("pc-overall");
    // The number itself is rendered by ScoreGauge into a canvas, so `data-pct` is the contract —
    // which is exactly why this page puts raw values on data attributes rather than in text.
    expect(overall.textContent).toContain("1 out of 2");
  });
});

// --- the ways it must refuse to answer ----------------------------------------------------------

describe("refusing to overclaim", () => {
  it("renders an unreadable compliance feed as unknown, never as compliant", async () => {
    mockAll({ complianceError: true });
    renderPage();
    expect(await screen.findByTestId("pc-unreadable")).toHaveTextContent("unknown");
    expect(screen.getByTestId("pc-overall")).not.toHaveAttribute("data-pct", "100");
  });

  it("shows a policy whose rego will not load as Unknown, not as compliant", async () => {
    // We do not know which rules it defines, so we cannot know whether anything violated them.
    // Showing 100% here would be a fabricated pass on a security control.
    mockAll({ sourceError: "r2-support" });
    renderPage();
    await screen.findByTestId("pc-state-r2-support");
    expect(screen.getByTestId("pc-state-r2-support").textContent).toBe("Unknown");
    expect(screen.getByTestId("pc-pct-r2-support")).toHaveAttribute("data-pct", "unknown");
  });

  it("distinguishes 'nothing has run' from 'fully compliant'", async () => {
    // Zero non-compliant out of ZERO agent classes is idle. Rendering that as 100% is the exact lie
    // the `scanned` field exists to prevent, and it is the reading an auditor would act on.
    mockAll({ principals: [], scanned: 0 });
    renderPage();
    const overall = await screen.findByTestId("pc-overall");
    expect(overall).toHaveAttribute("data-pct", "unknown");
    expect(overall.textContent).toContain("—");
    expect(screen.getByTestId("pc-state-r2-support").textContent).toBe("Not evaluated");
  });
});

// --- remediation + evidence ---------------------------------------------------------------------

describe("remediation", () => {
  it("lists only non-compliant policies, and says whether traffic was actually stopped", async () => {
    mockAll({
      controls: [
        control("customer_data_to_untrusted_recipient", ["r2-support"], 4),
        control("demo_destructive_sql", ["billing"], 9)
      ]
    });
    renderPage();
    await waitFor(() => expect(screen.getByTestId("pc-remediate-r2-support")).toBeInTheDocument());
    expect(screen.getByTestId("pc-remediate-billing")).toBeInTheDocument();
    // The consequence is stated once under the table rather than repeated per row, and it leads with
    // the DANGEROUS case: if any listed policy is in audit, those calls proceeded, and that is the
    // sentence an operator must not miss while scanning a table of red counts.
    expect(screen.getByText(/RECORDED these calls and let them through/)).toBeInTheDocument();

    // Azure's four columns, each with a real referent here. Scoped to the remediation table — the
    // compliance table above also has a Scope column, and an unscoped query matches both.
    const remediationTable = screen.getByTestId("pc-remediate-r2-support").closest("table") as HTMLElement;
    for (const heading of ["Policy definition", "Assignment", "Resources to remediate", "Scope"]) {
      expect(within(remediationTable).getByRole("columnheader", { name: heading })).toBeInTheDocument();
    }
    // and the actions deep-link to the row's OWN namespace and class
    expect(screen.getByTestId("pc-open-policy-r2-support").getAttribute("href")).toContain("agent_class=r2-support");
    expect(screen.getByTestId("pc-open-audit-r2-support").getAttribute("href")).toContain("agent=r2-support");
  });

  it("says nothing to remediate only when policies exist and all are clean", async () => {
    mockAll({ controls: [] });
    renderPage();
    const empty = await screen.findByTestId("pc-remediation-empty");
    expect(empty.textContent).toContain("every policy is compliant");
  });

  it("never issues an all-clear while any policy's state is unknown", async () => {
    // Caught in the browser, not here: mid-load every row read Unknown while this line already said
    // "every policy is compliant". An all-clear over data that has not arrived is the reading an
    // operator stops at.
    mockAll({ sourceError: "r2-support" });
    renderPage();
    const empty = await screen.findByTestId("pc-remediation-empty");
    expect(empty.textContent).toContain("not fully known");
    expect(empty.textContent).not.toContain("every policy is compliant");
  });

  it("does not claim 'all compliant' when nothing has been evaluated", async () => {
    mockAll({ principals: [], scanned: 0 });
    renderPage();
    const empty = await screen.findByTestId("pc-remediation-empty");
    expect(empty.textContent).toContain("nothing has been evaluated");
    expect(empty.textContent).not.toContain("every policy is compliant");
  });
});

// --- the three defects the live browser found, not the suite --------------------------------------

describe("cross-namespace rows", () => {
  it("labels each policy with ITS OWN namespace, not the selected one", async () => {
    // Under "All namespaces" the list spans namespaces. Stamping the selection onto every row made a
    // policy claim a namespace it does not live in — and the detail fetch then 404'd, turning the
    // whole page Unknown for a reason that was our bug.
    mockAll({
      policies: [{ namespace: "billing-prod", agent_class: "invoices", enforcement_mode: "block", current_version: 3 }],
      sources: { invoices: SQL_REGO }
    });
    renderPage();
    await screen.findByTestId("pc-row-invoices");
    expect(screen.getByText("billing-prod / invoices")).toBeInTheDocument();
  });

  it("fetches a policy's rego from the namespace that policy lives in", async () => {
    mockAll({
      policies: [{ namespace: "billing-prod", agent_class: "invoices", enforcement_mode: "block", current_version: 3 }],
      sources: { invoices: SQL_REGO }
    });
    renderPage();
    await screen.findByTestId("pc-row-invoices");
    expect(client.fetchPolicySource).toHaveBeenCalledWith("billing-prod", "invoices");
  });
});

describe("the summary tile never outruns its own number", () => {
  it("does not assert a count under an unknown percentage", async () => {
    // It read "53 out of 53" beneath a "—" while the evidence feed was down: a stronger claim than
    // the headline it sits under, and the more readable of the two.
    mockAll({ complianceError: true });
    renderPage();
    const tile = await screen.findByTestId("pc-overall");
    expect(tile).toHaveAttribute("data-pct", "unknown");
    const card = tile.parentElement as HTMLElement;
    expect(card.textContent).toContain("compliance evidence unavailable");
    expect(card.textContent).not.toMatch(/\d+ out of \d+/);
  });
});

describe("scope and evidence", () => {
  it("hides reserved scopes — this page is about policies the CUSTOMER wrote", async () => {
    mockAll({
      policies: [
        { agent_class: "r2-support", enforcement_mode: "block", current_version: 1 },
        { agent_class: "__controls__", enforcement_mode: "block", current_version: 5 },
        { agent_class: "__baseline__", enforcement_mode: "audit", current_version: 1 },
        { agent_class: "support__remediation__", enforcement_mode: "block", current_version: 1 }
      ]
    });
    renderPage();
    await screen.findByTestId("pc-row-r2-support");
    expect(screen.queryByTestId("pc-row-__controls__")).toBeNull();
    expect(screen.queryByTestId("pc-row-__baseline__")).toBeNull();
    expect(screen.queryByTestId("pc-row-support__remediation__")).toBeNull();
  });


});

describe("evidence is a redirect, not a second Audit Log", () => {
  it("deep-links into the Audit Log for the namespace, and per class/rule once a policy is picked", async () => {
    // A 25-row table here was a worse copy of a page that already filters, tails, exports and
    // separates redteam traffic. Land the operator ON the evidence instead of on a search box.
    mockAll({ controls: [control("customer_data_to_untrusted_recipient", ["r2-support"])] });
    renderPage();
    const all = await screen.findByTestId("pc-evidence-all");
    expect(all.getAttribute("href")).toContain("/audit?ns=chatbot-prod");
    expect(screen.queryByTestId("pc-evidence-class")).toBeNull();

    await userEvent.click(screen.getByTestId("pc-row-r2-support"));
    const cls = await screen.findByTestId("pc-evidence-class");
    expect(cls.getAttribute("href")).toContain("agent=r2-support");
    const rule = screen.getByTestId("pc-evidence-rule-customer_data_to_untrusted_recipient");
    expect(rule.getAttribute("href")).toContain("rule=customer_data_to_untrusted_recipient");
  });
});

describe("baseline controls are a floor, so nothing supersedes them", () => {
  it("does not warn that a class policy switches the shipped controls off", async () => {
    // It used to, and the warning was true: the controls tier was a base tier at priority 2, so a
    // class policy at 100 outranked it and the shipped detectors stopped running for that class.
    // The engine now collects the tier as a tighten-only floor (see
    // tests/engine/test_pack_precedence.py), so the condition no longer exists — and a banner that
    // outlives the defect it described is just a false alarm on a security page.
    mockAll({ policies: [{ agent_class: "r2-support", enforcement_mode: "block", current_version: 2, priority: 100 }] });
    renderPage();
    await screen.findByTestId("pc-row-r2-support");
    expect(screen.queryByTestId("pc-baseline-masked")).toBeNull();
    expect(screen.queryByTestId("pc-masks-r2-support")).toBeNull();
  });
});
