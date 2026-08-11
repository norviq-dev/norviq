// SPDX-License-Identifier: Apache-2.0
// Smoke test: the Dashboard (default landing route) must mount without throwing React #130.
// echarts core is stubbed so the chart components render without a canvas; the interop-shape guard
// lives in components/common/EChart.test.tsx.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("echarts-for-react/lib/core", () => ({
  default: () => null
}));

import { Dashboard } from "./Dashboard";
import { AppProvider, useApp } from "../store/AppContext";
import { clearApiCache, peekApiCache } from "../hooks/useApi";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
  // AppContext.setNamespace persists the selection, so a test that switches namespace would otherwise
  // start the NEXT test in that namespace instead of the "all" default.
  localStorage.removeItem("nrvq_namespace");
  localStorage.removeItem("nrvq_namespace_sub");
});
afterAll(() => server.close());

describe("Dashboard mounts", () => {
  it("renders the Overview page without a React #130 crash", async () => {
    const errors: string[] = [];
    const spy = vi.spyOn(console, "error").mockImplementation((m) => errors.push(String(m)));
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("Overview")).toBeInTheDocument());
    expect(errors.join("\n")).not.toMatch(/#130|element type is invalid/i);
    spy.mockRestore();
  });

  it("surfaces an engine_errors signal (distinct from policy blocks) when stats report faults", async () => {
    server.use(
      http.get("/api/v1/audit/stats", () =>
        HttpResponse.json({ total: 1000, blocked: 900, allowed: 100, block_rate_pct: 90, engine_errors: 174 })
      )
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    // The engine-fault banner appears with the count and is explicitly framed as a fail-closed OPA fault,
    // distinct from a policy block.
    expect(await screen.findByText(/engine error/i)).toBeInTheDocument();
    expect(screen.getByText(/fail-closed OPA-evaluation faults/i)).toBeInTheDocument();
  });

  it("KPI cards bind the /audit/stats numbers (total/blocked/block-rate) + real avg_latency_ms", async () => {
    server.use(
      http.get("/api/v1/audit/stats", () =>
        HttpResponse.json({ total: 1666, blocked: 1500, allowed: 166, block_rate_pct: 90.04, avg_latency_ms: 337 })
      )
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    // the cards bind the resolved stats (data-value is the raw bound number, independent of the count-up anim).
    const total = await screen.findByTestId("kpi-total-value");
    await waitFor(() => expect(total).toHaveAttribute("data-value", "1666"));
    expect(screen.getByTestId("kpi-blocked-value")).toHaveAttribute("data-value", "1500");
    expect(screen.getByTestId("kpi-blockrate-value")).toHaveAttribute("data-value", "90"); // Math.round(90.04)
    // Avg latency is the real avg_latency_ms from the same call (not the old records-derived 0).
    expect(screen.getByTestId("kpi-latency-value")).toHaveAttribute("data-value", "337");
  });

  it("exactly one export control (Report ▾) — no duplicate standalone Export button", async () => {
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByText("Overview")).toBeInTheDocument());
    // The Report ▾ menu remains (houses Export CSV + future PDF/Schedule); the standalone "Export" button is gone.
    expect(screen.getByText(/Report ▼/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Export$/ })).not.toBeInTheDocument();
  });
});

// A healthy /coverage-by-category. These two tests are about the GAUGE CAPTION, and the gauge only
// renders when the coverage read succeeded — an errored coverage now draws an explicit "could not be
// measured" panel instead of a fabricated 0% ring. Previously the fixture left /coverage-by-category
// unhandled, so both tests ran with coverage.error set and asserted the caption of a gauge that was only
// on screen because the page treated a failed read as "0% coverage".
//
// It ECHOES the scope it was asked for, because the real endpoint does (coverage.py returns
// `read_namespace(user, namespace)` — the scope it actually computed, `null` for the "all" aggregate).
// Hardcoding "default" made this fixture unable to produce the state its name claims for any test that
// selects a namespace: the page compares the echo before labelling a number with a namespace, so a
// "healthy coverage for payments" that answers about `default` is exactly the off-scope payload the page
// must refuse. `namespace_mode` defaults to "block" — the mode coverage.py reports for a namespace with no
// enforcement_mode row of its own, which is also the mode the ENGINE enforces for it.
// Every OTHER fetch the page-level "API unavailable. Showing partial data." notice is bound to, answering
// normally — so a test can attribute that notice (or its absence) to the one endpoint it is about.
function healthyRestOfPage() {
  return [
    http.get("*/api/v1/audit/stats", () =>
      HttpResponse.json({ total: 900, blocked: 34, allowed: 866, block_rate_pct: 4, avg_latency_ms: 12 })
    ),
    http.get("*/api/v1/audit/records", () => HttpResponse.json([])),
    http.get("*/api/v1/audit/top-blocked", () => HttpResponse.json([])),
    http.get("*/api/v1/audit/volume", () => HttpResponse.json([])),
    http.get("*/api/v1/agents", () => HttpResponse.json([]))
  ];
}

function healthyCoverage(extra: Record<string, unknown> = {}) {
  return http.get("*/api/v1/coverage-by-category", ({ request }) =>
    HttpResponse.json({
      namespace: new URL(request.url).searchParams.get("namespace"),
      coverage_pct: 64,
      basis: "rules_present",
      available: 0,
      categories: [{ category: "Prompt Injection", covered: 2, total: 2, score: 100, observed: 10, blocked: 3, effective: true, in_scope: true }],
      namespace_mode: "block",
      agent_class_policies: [],
      ...extra
    })
  );
}

describe("Overview coverage caption reflects Red Team efficacy", () => {
  it("upgrades 'not efficacy-tested' to 'X% proven-blocking (last run)' when a run exists", async () => {
    server.use(
      healthyCoverage(),
      http.get("*/api/v1/redteam/results/latest", () =>
        HttpResponse.json({ has_run: true, efficacy: { overall: { total: 20, caught: 17, got_through: 3, proven_blocking_pct: 85 } } })
      )
    );
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    // The gauge caption carries the % (teal-emphasized in its own node) and is the NEUTRAL --text-muted
    // token, not block-red. " (last run)" follows the bold %.
    const gaugeCaption = await screen.findByTestId("score-gauge-caption");
    expect(gaugeCaption).toHaveTextContent(/rules present · 85% proven-blocking \(last run\)/i);
    expect(gaugeCaption.style.color).toBe("var(--text-muted)");
    // The proven-blocking % lives on the GAUGE caption; the coverage card is now color-first (the caption
    // that duplicated this number was removed for a cleaner card — the gauge is the single source).
  });

  it("keeps the honest 'not efficacy-tested' caption before any run", async () => {
    server.use(healthyCoverage(), http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false })));
    render(
      <MemoryRouter>
        <AppProvider>
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    expect(await screen.findByText(/not efficacy-tested/i)).toBeInTheDocument();
  });
});

// ==================================================================================================
// REGRESSION — the Overview's headline numbers must belong to the scope the page says it is showing,
// and a failed read must never be drawn as a measured value.
// ==================================================================================================

/** Renders the current location so a deep-link assertion tests the real navigation, not a spy. */
function LocationProbe() {
  const loc = useLocation();
  return <span data-testid="test-location">{`${loc.pathname}${loc.search}`}</span>;
}

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AppProvider>
        <Dashboard />
      </AppProvider>
    </MemoryRouter>
  );
}

// A namespace SWITCH, driven exactly as the Header drives it (AppContext.setNamespace). This is the only
// way to reach the state the scope checks exist for: `useApi` keeps the last good `data` when a later load
// fails, so mid-switch the page is labelled ns-B while still holding ns-A's payload.
function NsSwitcher({ to }: { to: string }) {
  const { setNamespace } = useApp();
  return <button onClick={() => setNamespace(to)}>switch-ns</button>;
}
function renderWithSwitcher(to: string) {
  return render(
    <MemoryRouter initialEntries={["/"]}>
      <AppProvider>
        <NsSwitcher to={to} />
        <Dashboard />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("Overview efficacy is scoped to the selected namespace", () => {
  it("requests /redteam/results/latest WITH ?namespace=, and shows that namespace's answer — not the newest cluster-wide run", async () => {
    const latestUrls: string[] = [];
    server.use(
      healthyCoverage(),
      http.get("*/api/v1/redteam/results/latest", ({ request }) => {
        const url = new URL(request.url);
        latestUrls.push(url.pathname + url.search);
        // The real endpoint (redteam.py:320-324): a concrete namespace filters the query. `payments` has
        // never been red-teamed; some OTHER namespace has a 92%-proven run that is the newest overall.
        if (url.searchParams.get("namespace") === "payments") return HttpResponse.json({ has_run: false });
        return HttpResponse.json({
          has_run: true,
          efficacy: { overall: { total: 25, caught: 23, got_through: 2, proven_blocking_pct: 92 } }
        });
      })
    );
    renderAt("/?ns=payments");

    // The page header says it is showing `payments`…
    expect(await screen.findByText(/Showing: payments/)).toBeInTheDocument();
    const caption = await screen.findByTestId("score-gauge-caption");
    // …so the caption must carry payments' OWN answer ("never tested"), never another namespace's 92%.
    await waitFor(() => expect(caption).toHaveTextContent(/not efficacy-tested/i));
    expect(caption).not.toHaveTextContent(/92/);
    // And the request itself must be scoped.
    expect(latestUrls).toContain("/api/v1/redteam/results/latest?namespace=payments");
    expect(latestUrls).not.toContain("/api/v1/redteam/results/latest");
  });

  it("uses Compliance's exact cache key so the two surfaces share ONE entry and cannot diverge", async () => {
    server.use(
      healthyCoverage(),
      http.get("*/api/v1/redteam/results/latest", () =>
        HttpResponse.json({ has_run: true, efficacy: { overall: { total: 10, caught: 4, got_through: 6, proven_blocking_pct: 40 } } })
      )
    );
    renderAt("/?ns=payments");
    await screen.findByTestId("score-gauge-caption");
    // Compliance.tsx keys this exact fetch `compliance-redteam-latest:${namespace}`. Sharing the key is what
    // makes "the Overview and Compliance can show different %s for one namespace" structurally impossible.
    await waitFor(() =>
      expect(peekApiCache("compliance-redteam-latest:payments")).toMatchObject({ has_run: true })
    );
    // The old namespace-free key must be gone — it is what made the value both unscoped and un-refetchable.
    expect(peekApiCache("dashboard-redteam-latest")).toBeUndefined();
  });
});

describe("Overview never renders an unreadable value as a measured one", () => {
  it("a failed /coverage-by-category shows an explicit 'could not be measured' panel — not 'Policy Coverage 0%'", async () => {
    server.use(
      http.get("*/api/v1/coverage-by-category", () => HttpResponse.json({ detail: "boom" }, { status: 500 })),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false })),
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 4210, blocked: 12, allowed: 4198, block_rate_pct: 0.3 }))
    );
    renderAt("/");

    // The unmeasured state is explicit…
    expect(await screen.findByTestId("coverage-unavailable")).toBeInTheDocument();
    expect(screen.getByText(/could not be measured/i)).toBeInTheDocument();
    // …the confident 0% ring is NOT drawn…
    expect(screen.queryByTestId("score-gauge-value")).toBeNull();
    // …the category bars say unavailable rather than rendering an empty chart as "no coverage"…
    expect(screen.getByTestId("coverage-categories-unavailable")).toBeInTheDocument();
    // …and the page-level partial-data notice fires (coverage.error was the only fetch excluded from it).
    expect(screen.getByText(/API unavailable\. Showing partial data\./i)).toBeInTheDocument();
  });

  it("CONTROL: a genuine 0% coverage still renders the real 0% gauge (the fix must not hide real zeros)", async () => {
    server.use(
      healthyCoverage({ coverage_pct: 0, categories: [] }),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    );
    renderAt("/");
    expect(await screen.findByTestId("score-gauge-value")).toHaveTextContent("0%");
    expect(screen.queryByTestId("coverage-unavailable")).toBeNull();
  });

  it("a 403 from the admin-only efficacy endpoint reads 'unknown' — never the fact 'not efficacy-tested'", async () => {
    server.use(
      ...healthyRestOfPage(),
      healthyCoverage(),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ detail: "Admin role required" }, { status: 403 }))
    );
    renderAt("/");
    const caption = await screen.findByTestId("score-gauge-caption");
    await waitFor(() => expect(screen.getByTestId("dash-efficacy-unknown")).toBeInTheDocument());
    expect(caption).toHaveTextContent(/efficacy unknown/i);
    // The server's own reason is surfaced, so a non-admin can see WHY rather than mis-report the posture.
    expect(caption).toHaveTextContent(/Admin role required/);
    expect(caption).not.toHaveTextContent(/not efficacy-tested/i);
    // …and it does NOT raise the page-level outage notice. /redteam/results/latest is admin-only, so this
    // 403 is the PERMANENT, correct response for every non-admin operator: folding it into the generic
    // union pinned "API unavailable. Showing partial data." to their screen on every load, about an API
    // that answered correctly. The one signal the console has for a real outage has to stay meaningful.
    expect(screen.queryByText(/API unavailable\. Showing partial data\./i)).toBeNull();
  });

  it("a coverage read that fails AFTER a namespace switch does not republish the previous namespace's number", async () => {
    server.use(
      http.get("*/api/v1/coverage-by-category", ({ request }) => {
        const ns = new URL(request.url).searchParams.get("namespace");
        // `payments` faults; the aggregate answered 64% a moment ago. useApi still holds that 64%.
        if (ns === "payments") return HttpResponse.json({ detail: "statement timeout" }, { status: 500 });
        return HttpResponse.json({
          namespace: ns, coverage_pct: 64, basis: "rules_present", available: 0,
          categories: [{ category: "Prompt Injection", covered: 2, total: 2, score: 100, observed: 10, blocked: 3, effective: true, in_scope: true }],
          namespace_mode: "block", agent_class_policies: []
        });
      }),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    );
    renderWithSwitcher("payments");
    expect(await screen.findByTestId("score-gauge-value")).toHaveTextContent("64%");

    fireEvent.click(screen.getByText("switch-ns"));
    expect(await screen.findByText(/Showing: payments/)).toBeInTheDocument();

    // The page now says "payments" — so it must NOT still be showing the aggregate's 64% as payments'
    // measured coverage, nor the aggregate's categories, nor its agent classes.
    await waitFor(() => expect(screen.getByTestId("coverage-unavailable")).toBeInTheDocument());
    expect(screen.queryByTestId("score-gauge-value")).toBeNull();
    expect(screen.queryByText("64%")).toBeNull();
    expect(screen.getByTestId("coverage-categories-unavailable")).toBeInTheDocument();
  });

  it("an efficacy read that fails AFTER a namespace switch does not republish the previous namespace's %", async () => {
    server.use(
      healthyCoverage(),
      http.get("*/api/v1/redteam/results/latest", ({ request }) => {
        const ns = new URL(request.url).searchParams.get("namespace");
        if (ns === "payments") return HttpResponse.json({ detail: "Admin role required" }, { status: 403 });
        return HttpResponse.json({
          has_run: true,
          efficacy: { overall: { total: 25, caught: 23, got_through: 2, proven_blocking_pct: 92 } }
        });
      })
    );
    renderWithSwitcher("payments");
    const caption = await screen.findByTestId("score-gauge-caption");
    await waitFor(() => expect(caption).toHaveTextContent(/92% proven-blocking/));

    fireEvent.click(screen.getByText("switch-ns"));
    expect(await screen.findByText(/Showing: payments/)).toBeInTheDocument();
    // 92% belongs to the aggregate. payments' own read failed, so payments' efficacy is UNKNOWN — the one
    // thing it must never be is another scope's number wearing this scope's label.
    await waitFor(() => expect(screen.getByTestId("dash-efficacy-unknown")).toBeInTheDocument());
    expect(screen.getByTestId("score-gauge-caption")).not.toHaveTextContent(/92/);
  });
});

describe("Overview agent-class section honours the backend's degraded flag", () => {
  it("degraded + EMPTY list renders the section with an unavailable note instead of hiding it", async () => {
    server.use(
      healthyCoverage({ agent_class_policies: [], agent_class_policies_degraded: true }),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    );
    renderAt("/");
    // The section is present (hiding it read as "no agent-class policies are applied here")…
    expect(await screen.findByText(/By agent class/i)).toBeInTheDocument();
    // …and says the read failed.
    expect(screen.getByTestId("agent-class-degraded")).toHaveTextContent(/unavailable, not zero/i);
  });

  it("degraded + policies present withholds the proven/unproven bars (their efficacy is forced to 0)", async () => {
    server.use(
      healthyCoverage({
        agent_class_policies: [
          { cls: "report-gen", kind: "intent", allow_tools: ["read_report"], refinements: ["readonly"], learned_verbs: [],
            priority: 100, enforcement_mode: "block", enforcing: true, observed: 0, blocked: 0, would_block: 0, effective: false }
        ],
        agent_class_policies_degraded: true
      }),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    );
    renderAt("/");
    expect(await screen.findByTestId("agent-class-degraded")).toBeInTheDocument();
    // The class is still named (we DO know a policy is applied) but no bar states a verdict on it.
    expect(screen.getByText(/report-gen/)).toBeInTheDocument();
    await waitFor(() => expect(screen.queryAllByTestId("agent-class-cov-row")).toHaveLength(0));
  });

  it("CONTROL: not degraded → the real bars render (the degraded path must not swallow healthy data)", async () => {
    server.use(
      healthyCoverage({
        agent_class_policies: [
          { cls: "report-gen", kind: "intent", allow_tools: ["read_report"], refinements: [], learned_verbs: [],
            priority: 100, enforcement_mode: "block", enforcing: true, observed: 40, blocked: 4, would_block: 0, effective: true }
        ]
      }),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    );
    renderAt("/");
    await waitFor(() => expect(screen.getAllByTestId("agent-class-cov-row").length).toBe(1));
    expect(screen.queryByTestId("agent-class-degraded")).toBeNull();
  });
});

describe("Overview Monitor-mode signals are scoped and true of the code beneath them", () => {
  beforeEach(() => sessionStorage.setItem("nrvq_token", "test-token"));
  afterEach(() => sessionStorage.removeItem("nrvq_token"));

  // settings_router.py serves the `default` namespace row when no ?namespace= is sent, so under "all"
  // `posture.mode` is ONE namespace's posture, not the aggregate's.
  function monitorSettings() {
    return http.get("*/api/v1/settings", ({ request }) => {
      const ns = new URL(request.url).searchParams.get("namespace") ?? "default";
      return HttpResponse.json({ namespace: ns, enforcement_mode: ns === "block-ns" ? "block" : "audit", trust_threshold: 50, rate_limit: 100 });
    });
  }

  it("under 'all' the coverage legend shows NO monitor chip (it would assert 'does NOT enforce' over every namespace)", async () => {
    server.use(
      // Deliberately hostile fixture: the real endpoint returns namespace_mode "block" for the aggregate
      // (coverage.py `_namespace_mode(None)` — "don't imply monitor across the fleet"), so this pins the
      // CLIENT-side "all" guard on its own. Even handed a payload that claims Monitor, the aggregate scope
      // must refuse to draw the chip.
      healthyCoverage({ namespace_mode: "audit" }),
      monitorSettings(),
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 900, blocked: 34, allowed: 866, block_rate_pct: 4 })),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    );
    renderAt("/");
    expect(await screen.findByText(/Showing: all/)).toBeInTheDocument();
    // The same page's KPI tile already refuses to relabel itself under "all" — it still reads
    // "Blocked (24h)" over 34 real enforced blocks. The chip must not contradict it two inches below.
    const kpi = await screen.findByTestId("kpi-blocked");
    expect(kpi).toHaveTextContent(/^Blocked \(24h\)/);
    await waitFor(() => expect(screen.getByText(/By risk category/i)).toBeInTheDocument());
    expect(screen.queryByText(/^monitor$/)).toBeNull();
    expect(screen.queryByTestId("category-monitor-note")).toBeNull();
  });

  it("CONTROL: a concrete Monitor namespace still shows the chip, plus a note explaining why category bars cannot turn green", async () => {
    server.use(
      // A REAL Monitor namespace: it has its own enforcement_mode='audit' row, so /settings AND
      // coverage.py's namespace_mode both say audit — and only then is the engine actually softening.
      healthyCoverage({ namespace_mode: "audit" }),
      monitorSettings(),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    );
    renderAt("/?ns=payments");
    expect(await screen.findByText(/Showing: payments/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText(/^monitor$/)).toBeInTheDocument());
    // The legend used to claim grey meant "no traffic has exercised these rules; run the Red Team suite to
    // prove them" — false here: the engine rewrites would-blocks to a `monitor_would_block:` rule id that the
    // category roll-up never attributes to a category, so `effective` is unreachable for every category.
    const note = screen.getByTestId("category-monitor-note");
    expect(note).toHaveTextContent(/monitor_would_block:/);
    expect(note).toHaveTextContent(/no category bar can turn/i);
    expect(screen.queryByTitle(/no traffic has exercised these rules/i)).toBeNull();
    expect(screen.queryByTitle(/stopped \(or would-block\) traffic/i)).toBeNull();
  });

  // THE CONFIGURATION THE MONITOR SIGNALS WERE KEYED ON THE WRONG SOURCE FOR.
  // /settings merges the namespace row with the CLUSTER-WIDE default (`_effective`), so on a cluster
  // deployed with global enforcement_mode=audit it answers "audit" for a namespace that has no row of its
  // own. The ENGINE does not: `_resolve_posture` softens only on an explicit per-namespace override ("a
  // null/global mode does NO softening"), which is precisely the rule coverage.py's `namespace_mode`
  // reports. Keyed on /settings, the Overview relabelled the tile "Would-block" over `would_blocked`, which
  // is structurally 0 there because nothing is ever softened — HIDING 41 real enforced blocks behind a 0 —
  // and told the operator matched rules "do NOT enforce" while they were enforcing.
  it("a namespace that reads Monitor only from the CLUSTER default is not rendered as Monitor (the engine blocks it)", async () => {
    server.use(
      healthyCoverage({ namespace_mode: "block" }), // no per-namespace row → engine blocks → coverage says block
      monitorSettings(), // …while /settings answers "audit" for it, from the global default
      http.get("*/api/v1/audit/stats", () =>
        HttpResponse.json({ total: 900, blocked: 41, allowed: 859, block_rate_pct: 5, would_blocked: 0, would_block_rate_pct: 0 })
      ),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    );
    renderAt("/?ns=payments");
    expect(await screen.findByText(/Showing: payments/)).toBeInTheDocument();
    // The tile must count the REAL enforced blocks under their real name, not a would-block counter of 0.
    const kpi = await screen.findByTestId("kpi-blocked");
    await waitFor(() => expect(kpi).toHaveTextContent(/^Blocked \(24h\)/));
    // `data-value` is the raw bound number (the visible text count-up animates), as the KPI tests above use.
    await waitFor(() => expect(screen.getByTestId("kpi-blocked-value")).toHaveAttribute("data-value", "41"));
    expect(kpi).not.toHaveTextContent(/Monitor mode/);
    // …and neither Monitor claim is made about a namespace the engine is really enforcing.
    await waitFor(() => expect(screen.getByText(/By risk category/i)).toBeInTheDocument());
    expect(screen.queryByText(/^monitor$/)).toBeNull();
    expect(screen.queryByTestId("category-monitor-note")).toBeNull();
  });

  it("the shared proven/loaded legend names BOTH backends' definitions of green (escalate, and Monitor would-blocks)", async () => {
    server.use(healthyCoverage({ namespace_mode: "audit" }), monitorSettings(), http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false })));
    renderAt("/?ns=payments");
    await waitFor(() => expect(screen.getByText(/By risk category/i)).toBeInTheDocument());
    // One legend, two backends: a CATEGORY turns green off block-OR-ESCALATE (mitre.py folds escalate into
    // `blocked` — "the ONE place the product's two blocked-counts differ"), an AGENT CLASS also off a
    // would_block, where the call was expressly NOT stopped. A legend that says green means "stopped" is
    // false for both halves, so it has to name them.
    const proven = screen.getByTitle(/^Proven —/);
    expect(proven).toHaveTextContent(/^proven$/);
    expect(proven.getAttribute("title")).toMatch(/escalation/i);
    expect(proven.getAttribute("title")).toMatch(/would-block/i);
    expect(proven.getAttribute("title")).toMatch(/NOT stopped/i);
    // The green swatch must not be described as a "stop" full stop — it is exactly what an escalation and a
    // Monitor would-block are not.
    expect(screen.queryByTitle(/counted as stopped by these rules/i)).toBeNull();
  });
});

// ---------------------------------------------------------------------------------------------------
// MONITOR MODE: the two block feeds counted enforced blocks and reported their structural emptiness as a
// measured fact about the namespace's traffic.
//
// `_apply_posture` rewrites EVERY would-block/would-escalate to `decision="audit"` with a
// `monitor_would_block:<rule>` rule id (only the five non-policy `_POSTURE_EXEMPT_RULES` stay hard), so
// `AuditLogEntry.decision == "block"` — what `/audit/top-blocked` filters on, and what this page asks
// `/audit/records` for — can never match. Both panels therefore printed "No blocked tool calls in the
// selected range" directly beneath the page's own "Would-block (24h) 812" tile, and "See All →" navigated
// to `/audit?decision=block`, a filter structurally incapable of returning a row here. The KPI tile was
// fixed for exactly this reason (audit.py:222); these two panels were not.
// ---------------------------------------------------------------------------------------------------
describe("Overview block feeds are Monitor-aware", () => {
  function monitorNamespace(wouldBlocked = 812) {
    return [
      http.get("*/api/v1/settings", ({ request }) => {
        const ns = new URL(request.url).searchParams.get("namespace") ?? "default";
        return HttpResponse.json({ namespace: ns, enforcement_mode: "audit", apply_mode: "enforce" });
      }),
      healthyCoverage({ namespace_mode: "audit" }), // the ENGINE confirms it: a real per-ns override
      http.get("*/api/v1/audit/stats", () =>
        HttpResponse.json({
          total: 2000, blocked: 0, allowed: 2000, block_rate_pct: 0,
          would_blocked: wouldBlocked, would_block_rate_pct: 40.6
        })
      ),
      // Structurally empty — this is what the server really returns for a monitored namespace.
      http.get("*/api/v1/audit/records", () => HttpResponse.json([])),
      http.get("*/api/v1/audit/top-blocked", () => HttpResponse.json([])),
      http.get("*/api/v1/audit/volume", () => HttpResponse.json([])),
      http.get("*/api/v1/agents", () => HttpResponse.json([])),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    ];
  }

  it("neither feed states 'No blocked tool calls' as a fact about the traffic", async () => {
    server.use(...monitorNamespace());
    renderAt("/?ns=payments");
    expect(await screen.findByText(/Showing: payments/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("kpi-blocked")).toHaveTextContent(/Would-block \(24h\)/));

    // FAIL-ON-BUG: pre-fix both panels rendered the traffic claim and neither said "would-block".
    const recentEmpty = await screen.findByTestId("recent-blocked-monitor-empty");
    const topEmpty = screen.getByTestId("top-blocked-monitor-empty");
    for (const el of [recentEmpty, topEmpty]) {
      // REWRITTEN (was: /structurally empty, not a measured zero/ and "nothing is blocked live"). Those
      // sentences over-claimed: `_apply_posture` leaves `_POSTURE_EXEMPT_RULES` — trust_frozen,
      // policy_load_pending, evaluator_error, evaluator_invalid_payload, rate_limit_exceeded — HARD in
      // Monitor, and those land in this very feed as `decision="block"`. The panel now scopes the claim to
      // POLICY blocks and names what still enforces, so the assertions follow it.
      expect(el).toHaveTextContent(/no policy block can appear here/i);
      expect(el).toHaveTextContent(/monitor_would_block:/);
      expect(el).toHaveTextContent(/trust freeze/i);
      expect(el).toHaveTextContent(/812 would-blocks were logged in this range/i);
      expect(el).not.toHaveTextContent(/nothing is blocked live/i);
    }
    // The kill switch is not described away either: nothing on the page says a monitored namespace
    // enforces nothing.
    expect(screen.queryByText(/this namespace enforces none/i)).toBeNull();
    expect(screen.queryByText(/No blocked tool calls in the selected range/i)).toBeNull();
  });

  it("'See All →' lands on a filter that CAN match a row (decision=block cannot, here)", async () => {
    server.use(...monitorNamespace());
    render(
      <MemoryRouter initialEntries={["/?ns=payments"]}>
        <AppProvider>
          <LocationProbe />
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    await waitFor(() => expect(screen.getByTestId("kpi-blocked")).toHaveTextContent(/Would-block \(24h\)/));

    const recent = screen.getByTestId("recent-blocked");
    fireEvent.click(within(recent).getByRole("button", { name: /See All/ }));
    // FAIL-ON-BUG: pre-fix this navigated to `?decision=block`, which `_apply_posture` guarantees matches
    // nothing here. `/audit/records` filters `rule_id` by EXACT match, so the `monitor_would_block:` PREFIX
    // is not a server-side filter the console can send — `decision=audit` is the narrowest one that can
    // return these rows, and the Audit Log renders that prefix specially.
    await waitFor(() => expect(screen.getByTestId("test-location")).toHaveTextContent("/audit?decision=audit"));

    // The in-panel escape hatch goes to the same place.
    fireEvent.click(within(recent).getByRole("button", { name: /Show would-blocks in the Audit Log/ }));
    expect(screen.getByTestId("test-location")).toHaveTextContent("/audit?decision=audit");
  });

  // The empty state must not invent a number when the stats read failed — "we could not measure this" is
  // not "812", and it is not "0" either.
  it("does not state a would-block count when /audit/stats could not be read", async () => {
    server.use(...monitorNamespace());
    // A later `server.use` takes precedence over the earlier registration, so this really is the stats read
    // failing while everything else answers normally.
    server.use(http.get("*/api/v1/audit/stats", () => new HttpResponse("boom", { status: 500 })));
    renderAt("/?ns=payments");
    const topEmpty = await screen.findByTestId("top-blocked-monitor-empty");
    expect(topEmpty).toHaveTextContent(/no policy block can appear here/i); // (was: /structurally empty…/)
    expect(topEmpty).not.toHaveTextContent(/would-blocks were logged/i);
  });

  it("CONTROL: an ENFORCING namespace keeps the plain empty state and the decision=block deep-link", async () => {
    server.use(
      http.get("*/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "block", apply_mode: "enforce" })),
      healthyCoverage({ namespace_mode: "block" }),
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 900, blocked: 0, allowed: 900, block_rate_pct: 0 })),
      http.get("*/api/v1/audit/records", () => HttpResponse.json([])),
      http.get("*/api/v1/audit/top-blocked", () => HttpResponse.json([])),
      http.get("*/api/v1/audit/volume", () => HttpResponse.json([])),
      http.get("*/api/v1/agents", () => HttpResponse.json([])),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    );
    renderAt("/?ns=payments");
    expect(await screen.findByText(/Showing: payments/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("kpi-blocked")).toHaveTextContent(/^Blocked \(24h\)/));
    // Here a zero really IS a measurement, and the plain sentence is true.
    await waitFor(() => expect(screen.getAllByText(/No blocked tool calls in the selected range/i).length).toBe(2));
    expect(screen.queryByTestId("recent-blocked-monitor-empty")).toBeNull();
    expect(screen.queryByTestId("top-blocked-monitor-empty")).toBeNull();
  });

  // -------------------------------------------------------------------------------------------------
  // The case the Monitor-aware empty state was first shipped without: /settings says Monitor and the
  // ENGINE's own field could not be read.
  //
  // `monitorScope` deliberately falls back to `posture.mode` while coverage is loading or after it fails
  // ("Prefer the engine-accurate signal; fall back to the settings posture only until coverage answers"),
  // and that posture MERGES the cluster-wide default — so on a global-audit cluster (helm values-dev.yaml
  // `enforcementMode: audit`) it reads "audit" for every namespace the engine really blocks. Keying the
  // MECHANISM sentence off that fallback made an unread posture render as "nothing here is enforced", over
  // a feed whose zero was a genuine measurement, and printed "0 would-blocks were logged in this range" in
  // the same breath as "this feed is structurally empty, not a measured zero".
  // -------------------------------------------------------------------------------------------------
  it("does NOT assert the Monitor mechanism when the engine's own posture could not be read", async () => {
    server.use(
      http.get("*/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "audit", apply_mode: "enforce" })),
      // The engine's field is unreadable. This namespace may well be enforcing.
      http.get("*/api/v1/coverage-by-category", () => new HttpResponse("boom", { status: 500 })),
      http.get("*/api/v1/audit/stats", () =>
        HttpResponse.json({ total: 2000, blocked: 0, allowed: 2000, block_rate_pct: 0, would_blocked: 0 })
      ),
      http.get("*/api/v1/audit/records", () => HttpResponse.json([])),
      http.get("*/api/v1/audit/top-blocked", () => HttpResponse.json([])),
      http.get("*/api/v1/audit/volume", () => HttpResponse.json([])),
      http.get("*/api/v1/agents", () => HttpResponse.json([])),
      http.get("*/api/v1/redteam/results/latest", () => HttpResponse.json({ has_run: false }))
    );
    render(
      <MemoryRouter initialEntries={["/?ns=payments"]}>
        <AppProvider>
          <LocationProbe />
          <Dashboard />
        </AppProvider>
      </MemoryRouter>
    );
    expect(await screen.findByText(/Showing: payments/)).toBeInTheDocument();
    await waitFor(() => expect(screen.getByTestId("coverage-categories-unavailable")).toBeInTheDocument());

    // FAIL-ON-BUG: both feeds rendered the confirmed-Monitor sentence off the settings fallback.
    //
    // Both are awaited (the second used to be a synchronous getByTestId assuming two independent
    // queries settle in the same tick — they do not), and both get explicit headroom past the 15s
    // `asyncUtilTimeout` in src/test/setup.ts.
    //
    // WHY THE HEADROOM, and what is NOT known. This timed out at exactly 15s on a 2-core CI runner
    // while passing 6/6 locally on 10 cores. The decisive detail is that testing-library's failure
    // DUMP CONTAINED the element it said it could not find — so the render landed either side of the
    // deadline, rather than never happening. It is a slow render, not a wrong one.
    //
    // Ruled out, so nobody re-walks them: (1) a sync/async race between the two feeds — fixed, still
    // failed; (2) state leaking between tests — `timeRange` is not persisted at all, and the file
    // already clears `nrvq_namespace` and the api cache; (3) worker starvation from parallel files —
    // the workflow already passes `--no-file-parallelism`, and its comment records that raising the
    // async budget "moved the symptom rather than removing it"; (4) the bounded empty-retry in
    // useApi — the only feed configured for it is `/audit/stats` (emptyRetries 4 x 1200ms), which
    // this test mocks as `total: 2000`, so it is not empty and never retries.
    //
    // What remains is the runner being slow in a way no single timeout bounds, which is the same
    // conclusion .github/workflows/test.yml already reached. The timeout is therefore an honest
    // statement of the observed cost, not a mask: the assertions below are untouched, and if the
    // element genuinely never renders this still fails — just after 30s instead of 15s.
    const wait = { timeout: 30_000 };
    const recent = await screen.findByTestId("recent-blocked-monitor-empty-unconfirmed", {}, wait);
    const top = await screen.findByTestId("top-blocked-monitor-empty-unconfirmed", {}, wait);
    expect(screen.queryByTestId("recent-blocked-monitor-empty")).toBeNull();
    expect(screen.queryByTestId("top-blocked-monitor-empty")).toBeNull();
    for (const el of [recent, top]) {
      expect(el).not.toHaveTextContent(/no policy block can appear here/i);
      expect(el).not.toHaveTextContent(/not blocked live/i);
      expect(el).toHaveTextContent(/has not been confirmed/i);
      expect(el).toHaveTextContent(/unknown/i);
    }
    // …and the subtitle must not state the Monitor population either.
    expect(within(screen.getByTestId("recent-blocked")).queryByText(/only non-policy ones/i)).toBeNull();

    // The deep-link premised on `monitor_would_block:` rows existing is also withheld: `decision=audit`
    // is only the right destination where the engine confirmed it softens.
    fireEvent.click(within(screen.getByTestId("recent-blocked")).getByRole("button", { name: /See All/ }));
    await waitFor(() => expect(screen.getByTestId("test-location")).toHaveTextContent("/audit?decision=block"));
  });
});
