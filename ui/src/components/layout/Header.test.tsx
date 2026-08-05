// SPDX-License-Identifier: Apache-2.0
// The header time-range selector renders ONLY on time-scoped routes, and the selected chip
// carries a visible ACTIVE state (teal --accent + aria-pressed + `active` class), distinct from the
// muted inactive chips. Header's mount fetches are left unhandled (bypassed) — they fail gracefully;
// the chips render synchronously from the route, which is what we assert.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

// A fleet hub must be configured BEFORE api/fleet.ts is imported — `fleetEnabled` is a module-level
// const. vi.hoisted runs ahead of the import graph, which is the only place this can be set. With no
// cluster selected (`nrvq_cluster` unset) `isRemote` stays false, so the non-fleet tests are unaffected.
vi.hoisted(() => {
  (window as unknown as { __NRVQ_CONFIG__?: { fleetApiUrl: string } }).__NRVQ_CONFIG__ = {
    fleetApiUrl: "http://hub.test"
  };
});

import { Header } from "./Header";
import { AppProvider } from "../../store/AppContext";
import { clearApiCache } from "../../hooks/useApi";

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
beforeEach(() => { localStorage.clear(); sessionStorage.clear(); });
afterEach(() => { server.resetHandlers(); clearApiCache(); localStorage.clear(); sessionStorage.clear(); });
afterAll(() => server.close());

// A syntactically-valid dev JWT (header.payload.signature) so getToken()/tokenSubject() behave.
const TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig";
const signIn = () => localStorage.setItem("nrvq_token", TOKEN);
const openInbox = () => fireEvent.click(screen.getByRole("button", { name: /Inbox/i }));

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AppProvider>
        <Header isTablet={false} onMenuToggle={() => {}} tabletMenuOpen={false} />
      </AppProvider>
    </MemoryRouter>
  );
}

describe("Header time-range selector — scope + active state", () => {
  it("renders the range selector on time-scoped routes (/audit, /compliance)", () => {
    renderAt("/audit");
    expect(screen.getByTestId("time-range")).toBeInTheDocument();
    expect(screen.getByTestId("range-chip-24h")).toBeInTheDocument();
  });

  it("renders the range selector on Compliance (it IS range-scoped)", () => {
    renderAt("/compliance");
    expect(screen.getByTestId("time-range")).toBeInTheDocument();
  });

  it("does NOT render the range selector on Policy Catalog (current-state, not time-scoped)", () => {
    renderAt("/policies/catalog");
    expect(screen.queryByTestId("time-range")).not.toBeInTheDocument();
    expect(screen.queryByTestId("range-chip-24h")).not.toBeInTheDocument();
  });

  it("hidden on Policy Packs, Target Settings, and pages with their own range picker (Attack/Asset Graph)", () => {
    for (const p of ["/policies/packs", "/policies/targets", "/threats/graph", "/asset-graph"]) {
      const { unmount } = renderAt(p);
      expect(screen.queryByTestId("time-range")).not.toBeInTheDocument();
      unmount();
    }
  });

  it("the selected chip (default 24h) is ACTIVE (aria-pressed + `active` class + --accent fill); others are not", () => {
    renderAt("/audit");
    const active = screen.getByTestId("range-chip-24h");
    expect(active).toHaveAttribute("aria-pressed", "true");
    expect(active.className).toContain("active");
    // teal --accent fill (jsdom resolves the inline var literally to the CSS custom property).
    expect(active).toHaveStyle({ background: "var(--accent)" });

    for (const r of ["1h", "6h", "7d", "30d"]) {
      const chip = screen.getByTestId(`range-chip-${r}`);
      expect(chip).toHaveAttribute("aria-pressed", "false");
      expect(chip.className).not.toContain("active");
    }
  });
});

describe("Inbox alert copy agrees with its own count", () => {
  // A single blocked call read as "1 tool calls blocked". An alert that contradicts the number
  // sitting next to it undercuts the one thing the alert exists to state.
  async function openInboxWith(blocked: number) {
    server.use(
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 100, blocked, allowed: 100 - blocked })),
      http.get("*/api/v1/agents", () => HttpResponse.json([]))
    );
    renderAt("/audit");
    screen.getByRole("button", { name: /Inbox/i }).click();
  }

  it("says 'call' for exactly one blocked call", async () => {
    await openInboxWith(1);
    await waitFor(() => expect(screen.getByText(/1 tool call blocked in last 24h/)).toBeInTheDocument());
    expect(screen.queryByText(/1 tool calls blocked/)).not.toBeInTheDocument();
  });

  it("keeps the plural for more than one", async () => {
    await openInboxWith(4);
    await waitFor(() => expect(screen.getByText(/4 tool calls blocked in last 24h/)).toBeInTheDocument());
  });
});

describe("Inbox: a check that never completed is never an all-clear", () => {
  // The dropdown used to catch every failure into {blocked:0, lowTrust:0}, which lands in the
  // zero/zero branch — a green, timestamped "All systems healthy" produced by a request that 500'd.
  it("says the check FAILED (and not 'All systems healthy') when the alert lookup errors", async () => {
    server.use(
      http.get("*/api/v1/audit/stats", () => new HttpResponse("boom", { status: 500 })),
      http.get("*/api/v1/agents", () => new HttpResponse("boom", { status: 500 }))
    );
    renderAt("/audit");
    openInbox();

    const panel = await screen.findByTestId("inbox-error");
    expect(panel).toHaveTextContent(/not the same as no alerts/i);
    expect(screen.queryByText(/All systems healthy/i)).not.toBeInTheDocument();
    // A "Last checked" stamp asserts a check completed. It did not.
    expect(screen.queryByText(/Last checked:/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Last attempted:/i)).toBeInTheDocument();
    // Silence on the bell after a failed check is the same inversion — the badge says "unknown".
    expect(screen.getByTestId("bell-badge-incomplete")).toHaveTextContent("!");

    // Retry actually re-runs (a failed check is never cached), and a check that DID complete with two
    // zeros is still allowed to say so.
    server.use(
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 100, blocked: 0, allowed: 100 })),
      http.get("*/api/v1/agents", () => HttpResponse.json([]))
    );
    fireEvent.click(within(panel).getByRole("button", { name: /Retry/i }));
    expect(await screen.findByText(/All systems healthy/i)).toBeInTheDocument();
    expect(screen.getByText(/Last checked:/i)).toBeInTheDocument();
    expect(screen.queryByTestId("inbox-error")).not.toBeInTheDocument();
  });

  it("a 429 (the rate limiter, reachable in normal use) is reported, not rendered as zero alerts", async () => {
    server.use(
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ detail: "rate limited" }, { status: 429 })),
      http.get("*/api/v1/agents", () => HttpResponse.json({ detail: "rate limited" }, { status: 429 }))
    );
    renderAt("/audit");
    openInbox();

    expect(await screen.findByTestId("inbox-error")).toHaveTextContent(/rate limited/i);
    expect(screen.queryByText(/All systems healthy/i)).not.toBeInTheDocument();
  });

  it("keeps a REAL blocked count when only the OTHER lookup fails (they settle independently)", async () => {
    server.use(
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 100, blocked: 9, allowed: 91 })),
      http.get("*/api/v1/agents", () => new HttpResponse("boom", { status: 500 }))
    );
    renderAt("/audit");
    openInbox();

    // Nine real blocked calls survive a failure of the unrelated /agents call...
    expect(await screen.findByText(/9 tool calls blocked in last 24h/)).toBeInTheDocument();
    // ...and the dropdown still admits the half it could not measure.
    expect(screen.getByTestId("inbox-error")).toHaveTextContent(/Low-trust agents:/i);
    expect(screen.queryByText(/All systems healthy/i)).not.toBeInTheDocument();
    expect(screen.getByTestId("bell-badge-incomplete")).toHaveTextContent("9");
  });

  it("a stats response with no `blocked` field is unknown, not zero", async () => {
    server.use(
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 100 })),
      http.get("*/api/v1/agents", () => HttpResponse.json([]))
    );
    renderAt("/audit");
    openInbox();

    expect(await screen.findByTestId("inbox-error")).toHaveTextContent(/Blocked calls: the server returned no count/i);
    expect(screen.queryByText(/All systems healthy/i)).not.toBeInTheDocument();
  });
});

describe("Bell badge describes the scope currently on screen", () => {
  it("drops the previous namespace's count when the scope switches", async () => {
    signIn();
    server.use(
      http.get("*/api/v1/cluster-info", () =>
        HttpResponse.json({ cluster_id: "local-1", cluster_name: "local", namespaces: ["default", "payments"] })
      ),
      http.get("http://hub.test/api/v1/fleet/clusters", () =>
        HttpResponse.json([{ id: "local-1", name: "local", region: "r", endpoint: "", last_heartbeat: null, status: "ok" }])
      ),
      http.get("*/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "block", apply_mode: "enforce" })),
      http.get("*/api/v1/audit/stats", ({ request }) => {
        const ns = new URL(request.url).searchParams.get("namespace");
        return HttpResponse.json({ total: 100, blocked: ns === "payments" ? 7 : 0, allowed: 93 });
      }),
      http.get("*/api/v1/agents", () => HttpResponse.json([]))
    );
    renderAt("/audit?ns=payments");

    openInbox();
    await waitFor(() => expect(screen.getByTestId("bell-badge")).toHaveTextContent("7"));
    fireEvent.click(screen.getByRole("button", { name: /Close/i }));

    // Switch scope through the real selector: `default` has zero blocked calls.
    fireEvent.click(screen.getByRole("button", { name: /All namespaces|payments/ }));
    fireEvent.click(await screen.findByRole("button", { name: "default" }));

    await waitFor(() => expect(screen.getByText("default")).toBeInTheDocument());
    // The badge must not keep describing `payments` while the pill reads `default`.
    await waitFor(() => expect(screen.queryByTestId("bell-badge")).not.toBeInTheDocument());
    expect(screen.queryByTestId("bell-badge-incomplete")).not.toBeInTheDocument();

    // Re-checking the new scope reports the new scope honestly.
    openInbox();
    expect(await screen.findByText(/All systems healthy/i)).toBeInTheDocument();
  });
});

describe("A REMOTE cluster's label never sits over LOCAL numbers", () => {
  const remoteHandlers = (hits: { stats: number; agents: number }) => [
    http.get("*/api/v1/cluster-info", () =>
      HttpResponse.json({ cluster_id: "local-1", cluster_name: "local", namespaces: ["payments"] })
    ),
    http.get("http://hub.test/api/v1/fleet/clusters", () =>
      HttpResponse.json([
        { id: "local-1", name: "local", region: "r", endpoint: "", last_heartbeat: null, status: "ok" },
        { id: "fleet-b", name: "b", region: "r", endpoint: "", last_heartbeat: null, status: "ok" }
      ])
    ),
    // The LOCAL cluster is in Monitor mode with 9 blocked calls. Under a fleet-b label, neither fact
    // describes fleet-b — and the silent direction (local `block` ⇒ no chip at all) is the dangerous one.
    http.get("*/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "audit", apply_mode: "enforce" })),
    http.get("*/api/v1/audit/stats", () => {
      hits.stats += 1;
      return HttpResponse.json({ total: 100, blocked: 9, allowed: 91 });
    }),
    http.get("*/api/v1/agents", () => {
      hits.agents += 1;
      return HttpResponse.json([]);
    })
  ];

  it("shows no local posture chip and no local alert counts while fleet-b is selected", async () => {
    signIn();
    localStorage.setItem("nrvq_cluster", "fleet-b");
    const hits = { stats: 0, agents: 0 };
    server.use(...remoteHandlers(hits));
    renderAt("/audit?ns=payments");

    // The scope is remote: the posture chip states that, instead of showing local-1's Monitor mode.
    const chip = await screen.findByTestId("posture-chip-remote");
    expect(chip).toHaveTextContent(/Posture unknown/i);
    expect(chip).toHaveTextContent(/fleet-b/);
    expect(screen.queryByTestId("posture-chip-monitor")).not.toBeInTheDocument();

    openInbox();
    expect(await screen.findByTestId("inbox-remote")).toHaveTextContent(/aren’t readable from this console/i);
    expect(screen.queryByText(/9 tool calls blocked/)).not.toBeInTheDocument();
    expect(screen.queryByText(/All systems healthy/i)).not.toBeInTheDocument();
    expect(screen.queryByTestId("bell-badge")).not.toBeInTheDocument();
    // Nothing local was even asked for under the remote label.
    expect(hits).toEqual({ stats: 0, agents: 0 });
  });

  it("still shows the LOCAL posture and counts when the LOCAL cluster is selected", async () => {
    signIn();
    localStorage.setItem("nrvq_cluster", "local-1");
    const hits = { stats: 0, agents: 0 };
    server.use(...remoteHandlers(hits));
    renderAt("/audit?ns=payments");

    expect(await screen.findByTestId("posture-chip-monitor")).toBeInTheDocument();
    expect(screen.queryByTestId("posture-chip-remote")).not.toBeInTheDocument();
    openInbox();
    expect(await screen.findByText(/9 tool calls blocked in last 24h/)).toBeInTheDocument();
  });
});

describe("Posture chip: unknown is not drawn like enforcing", () => {
  const settings = (status: number, body: Record<string, string>) =>
    http.get("*/api/v1/settings", () => HttpResponse.json(body, { status }));

  it("says 'Posture unknown' when /settings fails — the same DOM as a confirmed `block` before", async () => {
    signIn();
    server.use(
      http.get("*/api/v1/cluster-info", () =>
        HttpResponse.json({ cluster_id: "local-1", cluster_name: "local", namespaces: ["payments"] })
      ),
      http.get("http://hub.test/api/v1/fleet/clusters", () => HttpResponse.json([])),
      settings(429, { detail: "rate limited" })
    );
    renderAt("/audit?ns=payments");

    const chip = await screen.findByTestId("posture-chip-unknown");
    expect(chip).toHaveTextContent("Posture unknown");
    expect(chip.getAttribute("title")).toMatch(/NOT a confirmation/i);
    expect(screen.queryByTestId("posture-chip-monitor")).not.toBeInTheDocument();
  });

  it("renders NO posture chip for a confirmed `block` (the chip's absence keeps meaning 'enforcing')", async () => {
    signIn();
    server.use(
      http.get("*/api/v1/cluster-info", () =>
        HttpResponse.json({ cluster_id: "local-1", cluster_name: "local", namespaces: ["payments"] })
      ),
      http.get("http://hub.test/api/v1/fleet/clusters", () => HttpResponse.json([])),
      // apply_mode "dry_run_only" gives a positive marker that the settings response was applied, so the
      // absence assertions below cannot pass merely because the fetch is still in flight.
      settings(200, { enforcement_mode: "block", apply_mode: "dry_run_only" })
    );
    renderAt("/audit?ns=payments");

    expect(await screen.findByTestId("posture-chip-frozen")).toBeInTheDocument();
    expect(screen.queryByTestId("posture-chip-unknown")).not.toBeInTheDocument();
    expect(screen.queryByTestId("posture-chip-monitor")).not.toBeInTheDocument();
  });
});

describe("⌘K palette states what it knows", () => {
  function typeQuery(text: string) {
    const input = screen.getByLabelText("Search");
    fireEvent.focus(input);
    fireEvent.change(input, { target: { value: text } });
  }

  it("a FAILED search says so instead of 'No results'", async () => {
    server.use(http.get("*/api/v1/search", () => new HttpResponse("upstream down", { status: 500 })));
    renderAt("/audit");
    typeQuery("report");

    const panel = await screen.findByTestId("search-error");
    expect(panel).toHaveTextContent(/Search unavailable/i);
    expect(panel).toHaveTextContent(/not “no matches”/i);
    expect(screen.queryByText(/No results for/)).not.toBeInTheDocument();

    server.use(
      http.get("*/api/v1/search", () =>
        HttpResponse.json({ tools: [], agents: [], policies: [{ namespace: "payments", agent_class: "report-gen" }] })
      )
    );
    fireEvent.click(within(panel).getByRole("button", { name: /Retry/i }));
    expect(await screen.findByText(/payments\/report-gen/)).toBeInTheDocument();
    expect(screen.queryByTestId("search-error")).not.toBeInTheDocument();
  });

  it("an expired session in the palette is named, not reported as 'No results'", async () => {
    server.use(http.get("*/api/v1/search", () => new HttpResponse("", { status: 401 })));
    renderAt("/audit");
    typeQuery("report");

    expect(await screen.findByTestId("search-error")).toHaveTextContent(/session has expired/i);
    expect(screen.queryByText(/No results for/)).not.toBeInTheDocument();
  });

  it("a policy hit with no mode reads 'mode unknown' — never a concrete posture (CONTRACT B)", async () => {
    server.use(
      http.get("*/api/v1/search", () =>
        // Exactly what routers/search.py emits: namespace + agent_class, no mode.
        HttpResponse.json({ tools: [], agents: [], policies: [{ namespace: "payments", agent_class: "report-gen" }] })
      )
    );
    renderAt("/audit");
    typeQuery("report");

    const hit = await screen.findByText(/payments\/report-gen/);
    expect(hit).toHaveTextContent("mode unknown");
    // `— audit` labelled every policy hit Monitor/not-enforcing, including block-mode namespaces.
    expect(hit).not.toHaveTextContent(/—\s*audit/);
  });

  it("an unscored agent and a decision-less tool read 'unknown', not 0.00 / audit", async () => {
    server.use(
      http.get("*/api/v1/search", () =>
        HttpResponse.json({
          tools: [{ tool_name: "report_gen", timestamp: new Date().toISOString() }],
          agents: [{ spiffe_id: "spiffe://x/ns/payments/sa/rg", agent_class: "report-gen" }],
          policies: []
        })
      )
    );
    renderAt("/audit");
    typeQuery("report");

    expect(await screen.findByText(/decision unknown/)).toBeInTheDocument();
    expect(screen.getByText(/trust unknown/)).toBeInTheDocument();
    expect(screen.queryByText(/trust 0\.00/)).not.toBeInTheDocument();
  });
});

// The three cases below are the ones the header's honesty rules break under WITHOUT an error being
// involved at all — a slow response is enough. Each was reproduced on the fixed file before being fixed.
describe("An answer is only ever shown under the scope it was measured for", () => {
  const localFleet = [
    http.get("*/api/v1/cluster-info", () =>
      HttpResponse.json({ cluster_id: "local-1", cluster_name: "local", namespaces: ["default", "payments"] })
    ),
    http.get("http://hub.test/api/v1/fleet/clusters", () =>
      HttpResponse.json([{ id: "local-1", name: "local", region: "r", endpoint: "", last_heartbeat: null, status: "ok" }])
    )
  ];
  /** A promise the test releases by hand, to hold ONE response open across a scope switch. */
  function gate() {
    let release: () => void = () => {};
    const promise = new Promise<void>((r) => { release = r; });
    return { promise, release: () => release() };
  }
  /** Switch scope through the REAL selector; `label` is what the menu entry reads. */
  const switchNamespaceTo = async (label: string) => {
    fireEvent.click(screen.getByRole("button", { name: /All namespaces|payments|default/ }));
    fireEvent.click(await screen.findByRole("button", { name: label }));
    await waitFor(() => expect(screen.getByText(label)).toBeInTheDocument());
  };

  it("an alert lookup that lands AFTER the scope switched is discarded, not shown under the new scope", async () => {
    signIn();
    const slow = gate();
    server.use(
      ...localFleet,
      http.get("*/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "block", apply_mode: "enforce" })),
      http.get("*/api/v1/audit/stats", async ({ request }) => {
        const ns = new URL(request.url).searchParams.get("namespace");
        if (ns === "payments") await slow.promise; // still in flight when the operator switches away
        return HttpResponse.json({ total: 100, blocked: ns === "payments" ? 7 : 0, allowed: 93 });
      }),
      http.get("*/api/v1/agents", () => HttpResponse.json([]))
    );
    renderAt("/audit?ns=payments");

    openInbox();                                   // starts the slow `payments` lookup
    fireEvent.click(screen.getByRole("button", { name: /Close/i }));
    await switchNamespaceTo("default");
    slow.release();                                // `payments`' answer arrives under the `default` label
    await new Promise((r) => setTimeout(r, 50));

    // Dropping the state on the switch is not enough: the in-flight answer must not re-populate it.
    expect(screen.queryByTestId("bell-badge")).not.toBeInTheDocument();
    expect(screen.queryByTestId("bell-badge-incomplete")).not.toBeInTheDocument();
    openInbox();
    expect(screen.queryByText(/7 tool calls blocked/)).not.toBeInTheDocument();
    // ...and the new scope's own check still reports the new scope honestly.
    expect(await screen.findByText(/All systems healthy/i)).toBeInTheDocument();
  });

  it("never leaves the chip area empty while the on-screen namespace's posture is still being read", async () => {
    // `default` (via "all") is `block` — no chip. `payments` is `audit` — Monitor. While the switch is in
    // flight the header holds the PREVIOUS scope's `block`, so it drew the empty chip area that this
    // component uses to mean "confirmed block" over a namespace that is wide open in Monitor mode.
    signIn();
    const slow = gate();
    server.use(
      ...localFleet,
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 0, blocked: 0, allowed: 0 })),
      http.get("*/api/v1/agents", () => HttpResponse.json([])),
      http.get("*/api/v1/settings", async ({ request }) => {
        const ns = new URL(request.url).searchParams.get("namespace");
        if (ns === "payments") await slow.promise;
        return HttpResponse.json({ enforcement_mode: ns === "payments" ? "audit" : "block", apply_mode: "enforce" });
      })
    );
    renderAt("/audit");

    // Settled on the cluster default: a confirmed `block`, so no chip at all.
    await waitFor(() => expect(screen.queryByTestId("posture-chip-checking")).not.toBeInTheDocument());
    expect(screen.queryByTestId("posture-chip-unknown")).not.toBeInTheDocument();
    expect(screen.queryByTestId("posture-chip-monitor")).not.toBeInTheDocument();

    await switchNamespaceTo("payments");
    // Mid-switch: we hold `default`'s posture, not `payments`'. Say so — do not let the empty chip area
    // state that payments is enforcing.
    const checking = await screen.findByTestId("posture-chip-checking");
    expect(checking).toHaveTextContent(/Checking posture/i);
    expect(checking.getAttribute("title")).toMatch(/namespace payments .*not been read/i);
    expect(checking.getAttribute("title")).toMatch(/NOT a confirmation/i);

    slow.release();
    expect(await screen.findByTestId("posture-chip-monitor")).toBeInTheDocument();
    expect(screen.queryByTestId("posture-chip-checking")).not.toBeInTheDocument();
  });

  it("does not keep the previous namespace's Monitor chip over the new one", async () => {
    // The reverse direction: `payments` is `audit`, the cluster default is `block`. The stale chip claimed
    // "live traffic is NOT blocked" — and named the wrong namespace in its own tooltip.
    signIn();
    const slow = gate();
    server.use(
      ...localFleet,
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 0, blocked: 0, allowed: 0 })),
      http.get("*/api/v1/agents", () => HttpResponse.json([])),
      http.get("*/api/v1/settings", async ({ request }) => {
        const ns = new URL(request.url).searchParams.get("namespace");
        if (!ns) await slow.promise; // the cluster-default read is the slow one this time
        return HttpResponse.json({ enforcement_mode: ns === "payments" ? "audit" : "block", apply_mode: "enforce" });
      })
    );
    renderAt("/audit?ns=payments");

    expect(await screen.findByTestId("posture-chip-monitor")).toBeInTheDocument();
    await switchNamespaceTo("All namespaces");

    await waitFor(() => expect(screen.getByTestId("posture-chip-checking")).toBeInTheDocument());
    expect(screen.queryByTestId("posture-chip-monitor")).not.toBeInTheDocument();
    slow.release();
    await waitFor(() => expect(screen.queryByTestId("posture-chip-checking")).not.toBeInTheDocument());
    expect(screen.queryByTestId("posture-chip-monitor")).not.toBeInTheDocument();
  });
});

describe("Inbox: a lookup that cannot be READ is a failed lookup", () => {
  it("a 200 that is not an agent list is named, and does not erase the blocked count", async () => {
    // Independent settling is not enough on its own: parsing a fulfilled-but-unusable body used to throw
    // out of the whole handler (there is no catch), taking the ALREADY-measured blocked count with it and
    // leaving "Alerts haven't been checked for this scope yet" — with a Retry that fails the same way.
    signIn();
    server.use(
      http.get("*/api/v1/cluster-info", () =>
        HttpResponse.json({ cluster_id: "local-1", cluster_name: "local", namespaces: ["default"] })
      ),
      http.get("http://hub.test/api/v1/fleet/clusters", () => HttpResponse.json([])),
      http.get("*/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "block", apply_mode: "enforce" })),
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 100, blocked: 3, allowed: 97 })),
      http.get("*/api/v1/agents", () => HttpResponse.json({ detail: "gateway rewrote the body" }))
    );
    renderAt("/audit");
    openInbox();

    // The half we DID measure survives...
    expect(await screen.findByText(/3 tool calls blocked in last 24h/)).toBeInTheDocument();
    // ...the half we could not read is named, not silently dropped...
    expect(screen.getByTestId("inbox-error")).toHaveTextContent(/Low-trust agents: the server returned no agent list/i);
    expect(screen.getByTestId("inbox-error")).toHaveTextContent(/Partial check/i);
    // ...and it is never an all-clear, nor a check that "hasn't run".
    expect(screen.queryByText(/All systems healthy/i)).not.toBeInTheDocument();
    expect(screen.queryByTestId("inbox-unchecked")).not.toBeInTheDocument();
    expect(screen.getByText(/Last attempted:/i)).toBeInTheDocument();
  });
});

describe("Inbox: a completed check is not thrown away by the console learning its own name", () => {
  it("keeps the counts when /cluster-info fills the cluster label in after the check ran", async () => {
    // `selectedCluster` starts "" and becomes the served cluster id when /cluster-info answers. Treating
    // that as a scope switch wiped a check that had just completed: the operator saw real counts appear
    // during page load and revert to "Alerts haven't been checked for this scope yet".
    signIn();
    let release: () => void = () => {};
    const clusterInfo = new Promise<void>((r) => { release = r; });
    server.use(
      http.get("*/api/v1/cluster-info", async () => {
        await clusterInfo; // resolves AFTER the inbox check has landed
        return HttpResponse.json({ cluster_id: "local-1", cluster_name: "local", namespaces: ["default"] });
      }),
      http.get("http://hub.test/api/v1/fleet/clusters", () => HttpResponse.json([])),
      http.get("*/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "block", apply_mode: "enforce" })),
      http.get("*/api/v1/audit/stats", () => HttpResponse.json({ total: 100, blocked: 5, allowed: 95 })),
      http.get("*/api/v1/agents", () => HttpResponse.json([]))
    );
    renderAt("/audit");
    openInbox();

    expect(await screen.findByText(/5 tool calls blocked in last 24h/)).toBeInTheDocument();
    release();
    await waitFor(() => expect(screen.getByText(/local-1/)).toBeInTheDocument());

    expect(screen.getByText(/5 tool calls blocked in last 24h/)).toBeInTheDocument();
    expect(screen.queryByTestId("inbox-unchecked")).not.toBeInTheDocument();
    expect(screen.getByTestId("bell-badge")).toHaveTextContent("5");
  });

  it("a superseded check does not put 'not checked yet' on screen while the current one is running", async () => {
    signIn();
    let releaseA: () => void = () => {};
    let releaseB: () => void = () => {};
    const a = new Promise<void>((r) => { releaseA = r; });
    const b = new Promise<void>((r) => { releaseB = r; });
    server.use(
      http.get("*/api/v1/cluster-info", () =>
        HttpResponse.json({ cluster_id: "local-1", cluster_name: "local", namespaces: ["default", "payments"] })
      ),
      http.get("http://hub.test/api/v1/fleet/clusters", () => HttpResponse.json([])),
      http.get("*/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "block", apply_mode: "enforce" })),
      http.get("*/api/v1/audit/stats", async ({ request }) => {
        const ns = new URL(request.url).searchParams.get("namespace");
        await (ns === "payments" ? a : b);
        return HttpResponse.json({ total: 100, blocked: ns === "payments" ? 7 : 1, allowed: 93 });
      }),
      http.get("*/api/v1/agents", () => HttpResponse.json([]))
    );
    renderAt("/audit?ns=payments");
    openInbox();                                            // check A (payments) starts, and hangs
    fireEvent.click(screen.getByRole("button", { name: /All namespaces|payments/ }));
    fireEvent.click(await screen.findByRole("button", { name: "default" }));
    await waitFor(() => expect(screen.getByText("default")).toBeInTheDocument());
    openInbox();                                            // check B (default) starts, and hangs
    await waitFor(() => expect(screen.getByText(/Checking alerts/i)).toBeInTheDocument());

    releaseA();                                             // the SUPERSEDED check finishes first
    await new Promise((r) => setTimeout(r, 50));
    // B is still running: the dropdown must not claim nothing has been checked (nor show A's 7).
    expect(screen.getByText(/Checking alerts/i)).toBeInTheDocument();
    expect(screen.queryByTestId("inbox-unchecked")).not.toBeInTheDocument();
    expect(screen.queryByText(/7 tool calls blocked/)).not.toBeInTheDocument();

    releaseB();
    expect(await screen.findByText(/1 tool call blocked in last 24h/)).toBeInTheDocument();
  });
});

describe("A failure reason is a sentence, not the proxy's error page", () => {
  it("reports the status when the body is markup instead of pasting the page into the dropdown", async () => {
    // client.ts's `detailOf` falls back to the RAW body for anything that is not a FastAPI error
    // envelope, so an ingress 502 arrives as a page of HTML.
    signIn();
    const page = `<html><head><title>502 Bad Gateway</title></head><body bgcolor="white">${"<hr/>".repeat(40)}</body></html>`;
    server.use(
      http.get("*/api/v1/cluster-info", () =>
        HttpResponse.json({ cluster_id: "local-1", cluster_name: "local", namespaces: ["default"] })
      ),
      http.get("http://hub.test/api/v1/fleet/clusters", () => HttpResponse.json([])),
      http.get("*/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "block", apply_mode: "enforce" })),
      http.get("*/api/v1/audit/stats", () => new HttpResponse(page, { status: 502 })),
      http.get("*/api/v1/agents", () => HttpResponse.json([]))
    );
    renderAt("/audit");
    openInbox();

    const panel = await screen.findByTestId("inbox-error");
    expect(panel).toHaveTextContent(/Blocked calls: the request failed \(HTTP 502\)/i);
    expect(panel.textContent ?? "").not.toContain("<html");
    expect(panel.textContent ?? "").not.toContain("Bad Gateway");
    // Still not an all-clear, and still not a measured zero.
    expect(screen.queryByText(/All systems healthy/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/0 tool calls blocked/)).not.toBeInTheDocument();
  });
});

describe("Inbox: a known answer is never hidden behind another scope's spinner", () => {
  it("shows the cached counts for the scope you switched back to while another check is still running", async () => {
    signIn();
    let release: () => void = () => {};
    const slow = new Promise<void>((r) => { release = r; });
    server.use(
      http.get("*/api/v1/cluster-info", () =>
        HttpResponse.json({ cluster_id: "local-1", cluster_name: "local", namespaces: ["payments"] })
      ),
      http.get("http://hub.test/api/v1/fleet/clusters", () => HttpResponse.json([])),
      http.get("*/api/v1/settings", () => HttpResponse.json({ enforcement_mode: "block", apply_mode: "enforce" })),
      http.get("*/api/v1/audit/stats", async ({ request }) => {
        const ns = new URL(request.url).searchParams.get("namespace");
        if (ns === "payments") await slow;              // this one never comes back during the test
        return HttpResponse.json({ total: 100, blocked: 1, allowed: 99 });
      }),
      http.get("*/api/v1/agents", () => HttpResponse.json([]))
    );
    renderAt("/audit");

    openInbox();                                        // all-namespaces: completes and is cached
    expect(await screen.findByText(/1 tool call blocked in last 24h/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Close/i }));

    fireEvent.click(screen.getByRole("button", { name: /All namespaces/ }));
    fireEvent.click(await screen.findByRole("button", { name: "payments" }));
    await waitFor(() => expect(screen.getByText("payments")).toBeInTheDocument());
    openInbox();                                        // payments: hangs
    expect(await screen.findByText(/Checking alerts/i)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Close/i }));

    fireEvent.click(screen.getByRole("button", { name: /payments/ }));
    fireEvent.click(await screen.findByRole("button", { name: "All namespaces" }));
    await waitFor(() => expect(screen.getByText("All namespaces")).toBeInTheDocument());
    openInbox();                                        // cache hit — a COMPLETE answer for this scope

    expect(await screen.findByText(/1 tool call blocked in last 24h/)).toBeInTheDocument();
    expect(screen.queryByText(/Checking alerts/i)).not.toBeInTheDocument();
    release();
  });
});
