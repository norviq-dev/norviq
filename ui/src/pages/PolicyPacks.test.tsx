// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import PolicyPacks from "./PolicyPacks";
import { clearApiCache } from "../hooks/useApi";

// The mutation guard reads the selected scope from useApp() — mock it so each test controls the namespace
// (the real AppProvider defaults to the aggregate "all", under which every mutation is correctly disabled).
const mockApp = { namespace: "default", selectedCluster: "local", isRemote: false, namespaces: ["default", "payments"] };
vi.mock("../store/AppContext", () => ({
  useApp: () => mockApp,
  AppProvider: ({ children }: { children: ReactNode }) => <>{children}</>
}));

const server = setupServer();
beforeAll(() => server.listen());
beforeEach(() => {
  mockApp.namespace = "default";
  mockApp.selectedCluster = "local";
  mockApp.isRemote = false;
});
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

function pack(id: string, sector: string, title: string, enabled: boolean) {
  return {
    id,
    sector,
    title,
    enforces: `${title} enforcement`,
    rule_ids: ["rule_a", "rule_b"],
    composes: sector === "Finance" ? ["pci_card_numbers"] : [],
    categories: [`${sector} Cat`],
    compliance: ["REG-1"],
    tunables: ["verbs"],
    enabled,
    namespace: "default"
  };
}

function handlers(
  role: string,
  enabled: Set<string>,
  opts: {
    applyMode?: string;
    onEnable?: (ns: string) => void;
    // The GET /policy-packs/override body this namespace reports. Default = no overlay loaded, which is
    // what packs.py emits for an untouched namespace.
    override?: { rego_source?: string; active?: boolean; mode?: string };
    // Simulate the override read failing outright (503) — "we could not tell", not "nothing is overlaid".
    overrideFails?: boolean;
  } = {}
) {
  return [
    http.get("/api/v1/me", () => HttpResponse.json({ sub: "u", role, namespace: "default" })),
    http.get("/api/v1/settings", () => HttpResponse.json({ namespace: "default", sector: "Energy", apply_mode: opts.applyMode ?? "enforce" })),
    http.get("/api/v1/policy-packs/override", () => {
      if (opts.overrideFails) return HttpResponse.json({ detail: "policy loader unreachable" }, { status: 503 });
      const o = opts.override;
      const body: Record<string, unknown> = {
        namespace: "default",
        rego_source: o?.rego_source ?? "",
        active: o?.active ?? false
      };
      // An explicit `mode: undefined` means "this server reported no mode at all" — omit the key entirely.
      if (!o || !("mode" in o)) body.mode = "tighten-only";
      else if (o.mode !== undefined) body.mode = o.mode;
      return HttpResponse.json(body);
    }),
    http.get("/api/v1/policy-packs", () =>
      HttpResponse.json([
        pack("energy-ot", "Energy", "Energy OT/IT Segmentation", enabled.has("energy-ot")),
        pack("finance-money-movement", "Finance", "Finance Money-Movement", enabled.has("finance-money-movement"))
      ])
    ),
    http.post("/api/v1/policy-packs/:id/enable", async ({ params, request }) => {
      const body = (await request.json().catch(() => ({}))) as { namespace?: string };
      opts.onEnable?.(String(body?.namespace ?? ""));
      enabled.add(String(params.id));
      return HttpResponse.json({ namespace: body?.namespace ?? "default", pack_id: params.id, enabled: true, enabled_packs: [...enabled] });
    }),
    http.post("/api/v1/policy-packs/:id/disable", ({ params }) => {
      enabled.delete(String(params.id));
      return HttpResponse.json({ namespace: "default", pack_id: params.id, enabled: false, enabled_packs: [...enabled] });
    })
  ];
}

function renderPage() {
  return render(
    <MemoryRouter>
      <PolicyPacks />
    </MemoryRouter>
  );
}

describe("PolicyPacks page", () => {
  it("renders packs grouped by sector with enabled state and suggested-sector highlight", async () => {
    server.use(...handlers("admin", new Set(["finance-money-movement"])));
    renderPage();
    expect(await screen.findByText("Energy OT/IT Segmentation")).toBeInTheDocument();
    expect(screen.getByText("Finance Money-Movement")).toBeInTheDocument();
    expect(screen.getByText("Suggested")).toBeInTheDocument();
    expect(screen.getByText("Energy")).toBeInTheDocument();
    expect(screen.getByText("Off")).toBeInTheDocument();
    expect(screen.getByText("Enabled")).toBeInTheDocument();
  });

  it("admin can enable a pack under a concrete namespace — POSTs {namespace:default} and flips to Enabled", async () => {
    const sentNs: string[] = [];
    server.use(...handlers("admin", new Set(), { onEnable: (ns) => sentNs.push(ns) }));
    renderPage();
    const enableBtn = await screen.findAllByRole("button", { name: "Enable" });
    expect(enableBtn.length).toBe(2);
    fireEvent.click(enableBtn[0]);
    // Enabling now confirms first (names the namespace); the POST only fires on confirm.
    const confirm = await screen.findByTestId("pack-confirm-apply");
    fireEvent.click(confirm);
    await waitFor(() => expect(screen.getByText("Enabled")).toBeInTheDocument());
    // The write targeted the concrete namespace, never the phantom "all".
    expect(sentNs).toContain("default");
    expect(sentNs).not.toContain("all");
  });

  it("the apply-result badge never shows APPLIED while its own outcome text still says Verifying, " +
    "and converges to a matching APPLIED + 'Confirmed via a live read' once the toggle's poll resolves", async () => {
    server.use(...handlers("admin", new Set()));
    renderPage();
    const enableBtn = await screen.findAllByRole("button", { name: "Enable" });
    fireEvent.click(enableBtn[0]);
    const confirm = await screen.findByTestId("pack-confirm-apply");
    fireEvent.click(confirm);
    // Eventually the toggle's own poll converges (msw's enable handler adds the id synchronously, so the
    // first poll try already matches) and the panel shows a badge consistent with its own outcome text —
    // never an APPLIED badge sitting above lingering "Verifying…" body text.
    await waitFor(() => expect(screen.getByText(/Confirmed via a live read/i)).toBeInTheDocument());
    expect(screen.getByText("APPLIED")).toBeInTheDocument();
  });

  it("cancelling the confirm dialog fires no network POST", async () => {
    const sentNs: string[] = [];
    server.use(...handlers("admin", new Set(), { onEnable: (ns) => sentNs.push(ns) }));
    renderPage();
    const enableBtn = await screen.findAllByRole("button", { name: "Enable" });
    fireEvent.click(enableBtn[0]);
    fireEvent.click(await screen.findByRole("button", { name: /cancel/i }));
    // no confirm → no write, pack stays Off.
    expect(sentNs).toHaveLength(0);
  });

  it("under All-namespaces (aggregate) every pack mutation is DISABLED and prompts for a concrete namespace", async () => {
    mockApp.namespace = "all";
    server.use(...handlers("admin", new Set()));
    renderPage();
    await screen.findByText("Energy OT/IT Segmentation");
    expect(screen.getByTestId("pack-scope-prompt")).toHaveTextContent(/Select a namespace/i);
    // both toggle buttons are disabled — no write can target "all"
    expect(screen.getByTestId("pack-toggle-energy-ot")).toBeDisabled();
    expect(screen.getByTestId("pack-toggle-finance-money-movement")).toBeDisabled();
    // override actions are disabled too
    expect(screen.getByTestId("override-apply")).toBeDisabled();
    expect(screen.getByTestId("override-dryrun")).toBeDisabled();
  });

  it("a disabled aggregate mutation never fires a network POST", async () => {
    mockApp.namespace = "all";
    const sentNs: string[] = [];
    server.use(...handlers("admin", new Set(), { onEnable: (ns) => sentNs.push(ns) }));
    renderPage();
    const btn = await screen.findByTestId("pack-toggle-energy-ot");
    fireEvent.click(btn); // disabled → no-op
    await new Promise((r) => setTimeout(r, 200));
    expect(sentNs).toEqual([]); // nothing sent; certainly no ?namespace=all write
  });

  it("a dry-run-only namespace shows the reason and disables pack enable up-front", async () => {
    server.use(...handlers("admin", new Set(), { applyMode: "dry_run_only" }));
    renderPage();
    await screen.findByText("Energy OT/IT Segmentation");
    expect(screen.getByTestId("pack-dryrun-banner")).toHaveTextContent(/dry-run-only/i);
    expect(screen.getByTestId("pack-toggle-energy-ot")).toBeDisabled();
  });

  it("viewer sees read-only catalog (no enable/disable buttons)", async () => {
    server.use(...handlers("viewer", new Set()));
    renderPage();
    expect(await screen.findByText("Energy OT/IT Segmentation")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Enable" })).not.toBeInTheDocument();
    expect(screen.getAllByText("Admin only").length).toBeGreaterThan(0);
  });

  // ---------------------------------------------------------------------------------------------
  // The override Dry-Run must actually replay the namespace.
  //
  // The server's `_replay_recent` (norviq/api/routers/policies.py) narrows the replayed audit rows with
  // `where(AuditLogEntry.agent_class == agent_class)` ONLY when the field is truthy — a class-less policy
  // replays the whole namespace. `__pack_override__` is the LOADER key the overlay is STORED under; it is
  // never a calling agent's class on an audit record, so sending it filtered every namespace to zero rows
  // and the server answered "No recent real traffic for this scope" — blaming the namespace's traffic for a
  // malformed request, in the only impact preview shown before Apply / Apply (weaken).
  // ---------------------------------------------------------------------------------------------
  function dryRunRoute(capture: { body?: { namespace?: string; agent_class?: string; rego_source?: string } }) {
    return http.post("/api/v1/policies/dry-run", async ({ request }) => {
      const body = (await request.json()) as { namespace?: string; agent_class?: string; rego_source?: string };
      capture.body = body;
      // Transcribes the real route: a truthy agent_class filters the replay, and no audit record carries
      // "__pack_override__", so the scope comes back empty.
      if (body.agent_class) {
        return HttpResponse.json({
          valid: true,
          total_records_checked: 0,
          would_block: 0,
          would_allow: 0,
          would_escalate: 0,
          newly_blocked: 0,
          block_rate_pct: 0,
          scope: { namespace: body.namespace, agent_class: body.agent_class },
          recommendation: "No recent real traffic for this scope — cannot simulate impact; deploy with care."
        });
      }
      // Class-less: the whole namespace's recent real traffic is replayed.
      return HttpResponse.json({
        valid: true,
        total_records_checked: 412,
        would_block: 37,
        would_allow: 375,
        would_escalate: 0,
        newly_blocked: 9,
        block_rate_pct: 8.98,
        scope: { namespace: body.namespace, agent_class: null },
        recommendation: "Would NEWLY block 9 of 412 recent calls (2.2%) — review the flips before deploying."
      });
    });
  }

  it("the override Dry-Run replays the whole namespace — it sends a class-less agent_class, never the " +
    "__pack_override__ loader key that no audit record can carry", async () => {
    const capture: { body?: { agent_class?: string } } = {};
    server.use(...handlers("admin", new Set()), dryRunRoute(capture));
    renderPage();
    fireEvent.click(await screen.findByTestId("override-dryrun"));
    await waitFor(() => expect(capture.body).toBeDefined());
    expect(capture.body?.agent_class).toBe("");
    expect(capture.body?.agent_class).not.toBe("__pack_override__");
    // …and because it is class-less, the readout reports a real replay instead of the zero-traffic verdict.
    const out = await screen.findByTestId("override-dryrun-result");
    expect(out).toHaveTextContent(/replayed 412 recent calls/i);
    expect(out).toHaveTextContent(/would block 37/i);
    expect(out).not.toHaveTextContent(/No recent real traffic for this scope/i);
  });

  it("a replay that checked ZERO records is rendered as 'nothing was simulated', never as a zero-impact " +
    "result — the record count is always shown next to the would-block/allow numbers", async () => {
    server.use(
      ...handlers("admin", new Set()),
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({
          valid: true,
          total_records_checked: 0,
          would_block: 0,
          would_allow: 0,
          block_rate_pct: 0,
          recommendation: "No recent real traffic for this scope — cannot simulate impact; deploy with care."
        })
      )
    );
    renderPage();
    fireEvent.click(await screen.findByTestId("override-dryrun"));
    const out = await screen.findByTestId("override-dryrun-result");
    expect(out).toHaveTextContent(/replayed 0 recent calls/i);
    expect(out).toHaveTextContent(/nothing was simulated/i);
    expect(out).toHaveTextContent(/not.{0,3}a zero-impact result/i);
    // The old readout said only "would block 0 (0%), allow 0" — indistinguishable from a real 0-of-500.
    expect(out).not.toHaveTextContent(/^Dry-Run:\s*would block 0/i);
  });

  it("a server that reports no record count is called out as unmeasured, not printed as zeros", async () => {
    server.use(
      ...handlers("admin", new Set()),
      http.post("/api/v1/policies/dry-run", () => HttpResponse.json({ valid: true, would_block: 0, would_allow: 0 }))
    );
    renderPage();
    fireEvent.click(await screen.findByTestId("override-dryrun"));
    const out = await screen.findByTestId("override-dryrun-result");
    expect(out).toHaveTextContent(/did not report how many recent calls were replayed/i);
    expect(out).not.toHaveTextContent(/would block 0/i);
  });

  it("a FAILED dry-run leaves no stale numbers on screen under the failure notice", async () => {
    let calls = 0;
    server.use(
      ...handlers("admin", new Set()),
      http.post("/api/v1/policies/dry-run", () => {
        calls += 1;
        return calls === 1
          ? HttpResponse.json({ valid: true, total_records_checked: 412, would_block: 37, would_allow: 375, block_rate_pct: 8.98 })
          : HttpResponse.json({ detail: "opa unreachable" }, { status: 503 });
      })
    );
    renderPage();
    const btn = await screen.findByTestId("override-dryrun");
    fireEvent.click(btn);
    expect(await screen.findByTestId("override-dryrun-result")).toHaveTextContent(/replayed 412 recent calls/i);
    fireEvent.click(btn);
    await waitFor(() => expect(screen.getByText(/Dry-run failed/i)).toBeInTheDocument());
    // The previous run's measurement must not sit next to "Dry-run failed" as if it described this rego.
    expect(screen.queryByTestId("override-dryrun-result")).not.toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------------------------
  // A live WEAKEN overlay must never be described as tighten-only.
  //
  // The weaken overlay is a deliberate, admin-only, audited capability (packs.py `_WEAKEN_KEY`,
  // evaluator.py's `__pack_weaken__` candidate) bounded by the comprehensive floor — so the BEHAVIOUR is
  // right and the blanket copy "it never weakens or removes a pack's block" was the false half.
  // ---------------------------------------------------------------------------------------------
  it("a live WEAKEN overlay is NOT described as tighten-only and does not get the tighten-only green pill", async () => {
    server.use(...handlers("admin", new Set(), { override: { active: true, rego_source: "package norviq.packoverride\n", mode: "weaken" } }));
    renderPage();
    const pill = await screen.findByTestId("override-status-pill");
    await waitFor(() => expect(pill).toHaveTextContent(/WEAKEN overlay active/i));
    // Not the byte-identical "Override active" a tighten-only overlay used to get.
    expect(pill).not.toHaveTextContent(/^Override active$/);
    expect(pill).not.toHaveTextContent(/tighten-only/i);
    // The relaxation is stated in visible prose, above the 240px editor.
    expect(screen.getByTestId("override-weaken-live")).toHaveTextContent(/not tighten-only/i);
    expect(screen.getByTestId("override-weaken-live")).toHaveTextContent(/RELAX a block/i);
    // The panel no longer asserts the blanket denial anywhere on the page — the old sub was an
    // unqualified absolute ("A per-namespace override that can ONLY add stricter blocks — it never
    // weakens or removes a pack's block"), and the old title carried "(tighten-only)".
    expect(screen.queryByText(/never weakens or removes a pack's block/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/override that can ONLY add stricter blocks/i)).not.toBeInTheDocument();
    expect(screen.queryByText("Customize pack enforcement (tighten-only)")).not.toBeInTheDocument();
    // What replaces it names both modes, so the tighten-only clause is scoped to the mode it is true of.
    expect(screen.getByText(/By default it is tighten-only/i)).toBeInTheDocument();
    expect(screen.getByText(/can relax a block the pack adds/i)).toBeInTheDocument();
  });

  it("a live TIGHTEN-ONLY overlay says so — the two opposite modes never render identically", async () => {
    server.use(...handlers("admin", new Set(), { override: { active: true, rego_source: "package norviq.packoverride\n", mode: "tighten-only" } }));
    renderPage();
    const pill = await screen.findByTestId("override-status-pill");
    await waitFor(() => expect(pill).toHaveTextContent(/Tighten-only override active/i));
    expect(pill).not.toHaveTextContent(/WEAKEN/i);
    expect(screen.queryByTestId("override-weaken-live")).not.toBeInTheDocument();
  });

  it("ticking the Advanced weaken opt-in does NOT claim a weaken overlay is live — the pill reports the " +
    "enforced mode, not the pending one", async () => {
    server.use(...handlers("admin", new Set(), { override: { active: true, rego_source: "package norviq.packoverride\n", mode: "tighten-only" } }));
    renderPage();
    const pill = await screen.findByTestId("override-status-pill");
    await waitFor(() => expect(pill).toHaveTextContent(/Tighten-only override active/i));
    fireEvent.click(screen.getByRole("checkbox"));
    // Button label follows the pending intent…
    expect(await screen.findByTestId("override-apply")).toHaveTextContent(/Apply \(weaken\)/i);
    // …but nothing was applied, so the live posture readout must not move.
    expect(pill).toHaveTextContent(/Tighten-only override active/i);
    expect(screen.queryByTestId("override-weaken-live")).not.toBeInTheDocument();
  });

  it("an active overlay whose mode the server does not report is flagged unverified, not assumed tighten-only", async () => {
    server.use(...handlers("admin", new Set(), { override: { active: true, rego_source: "package norviq.packoverride\n", mode: undefined } }));
    renderPage();
    const pill = await screen.findByTestId("override-status-pill");
    await waitFor(() => expect(pill).toHaveTextContent(/mode unreported/i));
    expect(screen.getByTestId("override-mode-unknown")).toHaveTextContent(/may relax a pack's block/i);
    expect(pill).not.toHaveTextContent(/Tighten-only override active/i);
  });

  it("a FAILED override read reports the state as unknown — never the confident 'No override'", async () => {
    server.use(...handlers("admin", new Set(), { overrideFails: true }));
    renderPage();
    const pill = await screen.findByTestId("override-status-pill");
    await waitFor(() => expect(pill).toHaveTextContent(/Override state unknown/i));
    expect(pill).not.toHaveTextContent(/No override/i);
    expect(screen.getByTestId("override-load-error")).toHaveTextContent(/may be live and enforced/i);
    // The banner tells the operator an overlay may be live — so it must also say that Revert cannot be used
    // to remove one, because Revert is gated on `overrideActive`, which a failed read leaves false.
    expect(screen.getByTestId("override-load-error")).toHaveTextContent(/Revert is unavailable/i);
    expect(screen.getByTestId("override-revert")).toBeDisabled();
  });

  // ---------------------------------------------------------------------------------------------
  // An UNREAD namespace is exactly as unmeasured as an unreadable one.
  //
  // "No override" and "an overlay is loaded" are both measurement claims. Neither may be rendered from a
  // read that has not landed, nor from the PREVIOUS namespace's answer.
  // ---------------------------------------------------------------------------------------------
  /** msw override route with per-namespace bodies; namespaces listed in `hold` block until released. */
  function overrideRoute(
    bodies: Record<string, { active: boolean; mode?: string; rego_source?: string }>,
    hold: Record<string, Promise<void> | undefined> = {}
  ) {
    return http.get("/api/v1/policy-packs/override", async ({ request }) => {
      const ns = new URL(request.url).searchParams.get("namespace") ?? "default";
      const gate = hold[ns];
      if (gate) await gate;
      const b = bodies[ns] ?? { active: false, mode: "tighten-only" };
      return HttpResponse.json({ namespace: ns, rego_source: b.rego_source ?? "", active: b.active, mode: b.mode });
    });
  }

  it("the override posture is NOT claimed as 'No override' while the read is still in flight — an unread " +
    "namespace is unmeasured, not clean", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => { release = r; });
    server.use(...handlers("admin", new Set()));
    server.use(overrideRoute({ default: { active: true, mode: "weaken", rego_source: "package norviq.packoverride\n" } }, { default: held }));
    renderPage();
    const pill = await screen.findByTestId("override-status-pill");
    // Before the read lands: no verdict either way.
    expect(pill).toHaveTextContent(/Reading override/i);
    expect(pill).not.toHaveTextContent(/No override/i);
    // …and the namespace it was hiding really did have a live WEAKEN overlay.
    release();
    await waitFor(() => expect(pill).toHaveTextContent(/WEAKEN overlay active/i));
  });

  it("switching namespace does not reinterpret the PREVIOUS namespace's override as an unverified overlay " +
    "on the new one", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => { release = r; });
    server.use(...handlers("admin", new Set()));
    server.use(
      overrideRoute(
        {
          default: { active: true, mode: "weaken", rego_source: "package norviq.packoverride\n" },
          payments: { active: false, mode: "tighten-only" }
        },
        { payments: held }
      )
    );
    const { rerender } = renderPage();
    const pill = await screen.findByTestId("override-status-pill");
    await waitFor(() => expect(pill).toHaveTextContent(/WEAKEN overlay active/i));

    mockApp.namespace = "payments";
    rerender(<MemoryRouter><PolicyPacks /></MemoryRouter>);
    await waitFor(() => expect(screen.getByTestId("override-status-pill")).toHaveTextContent(/Reading override/i));
    const after = screen.getByTestId("override-status-pill");
    // "default" was overlaid; "payments" has not been read at all. Neither the old verdict nor a
    // manufactured one may be stated about it.
    expect(after).not.toHaveTextContent(/WEAKEN/i);
    expect(after).not.toHaveTextContent(/mode unreported/i);
    expect(after).not.toHaveTextContent(/No override/i);
    expect(screen.queryByTestId("override-mode-unknown")).not.toBeInTheDocument();
    expect(screen.queryByTestId("override-weaken-live")).not.toBeInTheDocument();
    release();
    await waitFor(() => expect(screen.getByTestId("override-status-pill")).toHaveTextContent(/No override/i));
  });

  it("a slow read of the PREVIOUS namespace that lands after a switch never overwrites the new " +
    "namespace's posture", async () => {
    let release!: () => void;
    const held = new Promise<void>((r) => { release = r; });
    server.use(...handlers("admin", new Set()));
    server.use(
      overrideRoute(
        {
          default: { active: true, mode: "weaken", rego_source: "package norviq.packoverride\n" },
          payments: { active: false, mode: "tighten-only" }
        },
        { default: held }
      )
    );
    const { rerender } = renderPage();
    await screen.findByTestId("override-status-pill");
    mockApp.namespace = "payments";
    rerender(<MemoryRouter><PolicyPacks /></MemoryRouter>);
    await waitFor(() => expect(screen.getByTestId("override-status-pill")).toHaveTextContent(/No override/i));
    // "default"'s WEAKEN overlay now lands — against the wrong namespace.
    release();
    await new Promise((r) => setTimeout(r, 20));
    const pill = screen.getByTestId("override-status-pill");
    expect(pill).toHaveTextContent(/No override/i);
    expect(pill).not.toHaveTextContent(/WEAKEN/i);
    expect(screen.queryByTestId("override-weaken-live")).not.toBeInTheDocument();
  });

  // ---------------------------------------------------------------------------------------------
  // The dry-run readout must reconcile with the total it now prints, and must never present a COMPILE
  // failure as a fact about the namespace's traffic.
  // ---------------------------------------------------------------------------------------------
  it("the dry-run readout never drops the escalate bucket, and names the records the replay counted but " +
    "did not simulate — block + escalate + allow must reconcile with the total on screen", async () => {
    server.use(...handlers("admin", new Set()));
    server.use(
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({
          valid: true,
          // _replay_recent counts every FETCHED row in total_records_checked but `continue`s past synthetic
          // identities and per-record OPA errors, so the three buckets legitimately sum to less than it.
          total_records_checked: 412,
          would_block: 37,
          would_escalate: 45,
          would_allow: 300,
          block_rate_pct: 8.98,
          recommendation: "Would NEWLY block 9 of 412 recent calls (2.2%) — review the flips before deploying."
        })
      )
    );
    renderPage();
    fireEvent.click(await screen.findByTestId("override-dryrun"));
    const out = await screen.findByTestId("override-dryrun-result");
    expect(out).toHaveTextContent(/replayed 412 recent calls/i);
    // The escalate bucket is a decision the operator must see before Apply — it is not "allow".
    expect(out).toHaveTextContent(/escalate 45/i);
    // 37 + 45 + 300 = 382, not 412: the 30-record hole is named rather than left for the operator to find.
    expect(screen.getByTestId("override-dryrun-unsimulated")).toHaveTextContent(/30 of those 412/i);
    expect(screen.getByTestId("override-dryrun-unsimulated")).toHaveTextContent(/none of the three outcomes/i);
  });

  it("outcome counts that EXCEED the record total are called out as not reconciling, not rendered as a " +
    "measurement", async () => {
    server.use(...handlers("admin", new Set()));
    server.use(
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({
          valid: true, total_records_checked: 100, would_block: 60, would_escalate: 30, would_allow: 40,
          block_rate_pct: 60
        })
      )
    );
    renderPage();
    fireEvent.click(await screen.findByTestId("override-dryrun"));
    await screen.findByTestId("override-dryrun-result");
    expect(screen.getByTestId("override-dryrun-unsimulated")).toHaveTextContent(/do not reconcile/i);
    expect(screen.getByTestId("override-dryrun-unsimulated")).toHaveTextContent(/130 against 100/i);
  });

  it("a replay that hit the server's record cap says so — the numbers are lower bounds, not the window", async () => {
    server.use(...handlers("admin", new Set()));
    server.use(
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({
          valid: true, total_records_checked: 500, would_block: 10, would_escalate: 0, would_allow: 490,
          block_rate_pct: 2, truncated: true, recommendation: "Would NEWLY block 3 of 500 recent calls (0.6%)."
        })
      )
    );
    renderPage();
    fireEvent.click(await screen.findByTestId("override-dryrun"));
    await screen.findByTestId("override-dryrun-result");
    expect(screen.getByTestId("override-dryrun-truncated")).toHaveTextContent(/lower bounds/i);
  });

  it("an absent would_block is reported as unreported — never printed as a measured 0 alongside a real " +
    "record count", async () => {
    server.use(...handlers("admin", new Set()));
    server.use(
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({ valid: true, total_records_checked: 412, would_allow: 375 })
      )
    );
    renderPage();
    fireEvent.click(await screen.findByTestId("override-dryrun"));
    const out = await screen.findByTestId("override-dryrun-result");
    expect(out).toHaveTextContent(/replayed 412 recent calls/i);
    expect(out).toHaveTextContent(/would block not reported/i);
    expect(out).toHaveTextContent(/rate not reported/i);
    // The old `?? 0` painted a zero-impact headline out of fields the response never carried.
    expect(out).not.toHaveTextContent(/would block 0/i);
    expect(out).not.toHaveTextContent(/\(0%\)/);
    // …and with a bucket unreported the reconciliation cannot be computed, so it must not be claimed.
    expect(screen.queryByTestId("override-dryrun-unsimulated")).not.toBeInTheDocument();
  });

  it("a rego that did NOT compile is reported as a compile failure with the server's errors — never as " +
    "'nothing was simulated' in this namespace", async () => {
    server.use(...handlers("admin", new Set()));
    server.use(
      // Exactly the body policies.py's dry_run_policy returns when _validate_rego fails: a zeroed replay
      // block plus valid:false + errors. Routed through the traffic branch it read as an idle namespace.
      http.post("/api/v1/policies/dry-run", () =>
        HttpResponse.json({
          valid: false,
          errors: ["rego_parse_error: unexpected eof at line 7"],
          total_records_checked: 0, would_block: 0, would_allow: 0, would_escalate: 0,
          newly_blocked: 0, block_rate_pct: 0,
          recommendation: "Invalid rego — fix errors before deploying"
        })
      )
    );
    renderPage();
    fireEvent.click(await screen.findByTestId("override-dryrun"));
    const out = await screen.findByTestId("override-dryrun-result");
    expect(screen.getByTestId("override-dryrun-invalid")).toHaveTextContent(/did not compile/i);
    expect(out).toHaveTextContent(/rego_parse_error: unexpected eof at line 7/);
    // It must NOT be described as a replay of this namespace's traffic.
    expect(out).not.toHaveTextContent(/replayed 0 recent calls/i);
    expect(out).not.toHaveTextContent(/nothing was simulated/i);
  });

  it("ALL packs lay out in ONE flat side-by-side grid (not one stack per sector)", async () => {
    server.use(...handlers("admin", new Set(["finance-money-movement"])));
    renderPage();
    await screen.findByText("Energy OT/IT Segmentation");
    const rails = screen.getAllByTestId("pack-rail");
    expect(rails.length).toBe(1);
    const rail = rails[0];
    expect(rail).toHaveClass("pack-rail");
    expect(rail.querySelectorAll(".panel").length).toBe(2);
  });
});

describe("a pack is enabled per namespace, so the aggregate scope must not answer for one", () => {
  // fetchPolicyPacks omits ?namespace at "all"; the route declares namespace: str = Query("default").
  // So the API answers for ONE namespace and echoes it on every row, while the header says "all".
  // Rendering that as "Enabled" is a control surface reporting a posture it was never told.
  it("does not report one namespace's enabled state as the estate's", async () => {
    mockApp.namespace = "all";
    server.use(...handlers("admin", new Set(["finance-money-movement"])));
    renderPage();
    const pill = await screen.findByTestId("pack-state-finance-money-movement");
    expect(pill).toHaveTextContent(/per namespace/i);
    expect(screen.queryByText("Enabled")).not.toBeInTheDocument();
    expect(screen.getByText(/pick one to see which are on/i)).toBeInTheDocument();
  });

  it("still reports real enabled state at a concrete namespace", async () => {
    // The guard must not blank a scope where the answer IS knowable — that would be its own defect.
    mockApp.namespace = "default";
    server.use(...handlers("admin", new Set(["finance-money-movement"])));
    renderPage();
    expect(await screen.findByTestId("pack-state-finance-money-movement")).toHaveTextContent("Enabled");
    expect(screen.getByTestId("pack-state-energy-ot")).toHaveTextContent("Off");
  });
});
