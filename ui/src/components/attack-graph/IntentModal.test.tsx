// Tests for the IntentModal allowlist builder — drafting an intent/allowlist policy from an attack path.
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { BuilderGraph } from "../../lib/builderGraph";
import { IntentModal } from "./IntentModal";
import type { ThreatPath } from "./types";

/**
 * The navigation PAYLOAD, captured.
 *
 * The builder handoff carries a whole `BuilderGraph` in router state, and the only thing that makes
 * it a handoff rather than a link is that payload — the Tools screen shipped a broken one for weeks
 * behind a green test that asserted the destination URL and nothing else. So this captures the
 * argument rather than the destination.
 *
 * `importOriginal`, not a bare stub: MemoryRouter and the rest of the router must keep working.
 */
let navigated: { to: string; state: { builderGraph: BuilderGraph } } | null = null;
vi.mock("react-router-dom", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react-router-dom")>()),
  useNavigate: () => (to: string, opts?: { state?: unknown }) => {
    navigated = { to, state: (opts?.state ?? {}) as never };
  }
}));

const server = setupServer();
beforeAll(() => server.listen());
afterEach(() => {
  server.resetHandlers();
  navigated = null;
});
afterAll(() => server.close());

const PATH: ThreatPath = {
  id: "p2", sev: "high", src: "billing-runner", tgt: "postgresql/ledger", ns: "payments", cls: "payments",
  mitre: "T1041", hops: 2, trust: 0.61, blast: 4, status: "exploitable", tool: "issue_refund",
  reach: [{ n: "tax-records", s: 1 }],
  steps: [
    { from: "billing-runner", to: "issue_refund", verb: "calls", dec: "mixed", kind: "tool", deny: 6, allow: 68 },
    { from: "issue_refund", to: "postgresql/ledger", verb: "reaches", dec: "allow", kind: "data", deny: 0, allow: 512 }
  ],
  verdict: "exploitable", fix: "scope issue_refund"
};

const SUGGEST = {
  ns: "payments", cls: "payments",
  tools: [
    { name: "read_ledger", allow: 90, block: 0, tag: "normal" as const, target: null, in_attack_path: false },
    { name: "issue_refund", allow: 68, block: 6, tag: "chokepoint" as const, target: "postgresql/ledger", in_attack_path: true }
  ]
};

function suggestHandler() {
  return http.get("/api/v1/threats/intent-suggest", () => HttpResponse.json(SUGGEST));
}

function renderModal() {
  return render(
    <MemoryRouter>
      <IntentModal ns="payments" cls="payments" tool="issue_refund" paths={[PATH]} onClose={() => {}} />
    </MemoryRouter>
  );
}

describe("IntentModal — allowlist builder", () => {
  it("renders the observed tools as a checklist", async () => {
    server.use(
      suggestHandler(),
      http.post("/api/v1/threats/intent-coverage", () => HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 }))
    );
    renderModal();
    expect(await screen.findByLabelText(/Intended: read_ledger/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Intended: issue_refund/i)).toBeInTheDocument();
  });

  it("flags the attack-abused chokepoint + defaults ALL tools unchecked (deny-all)", async () => {
    server.use(
      suggestHandler(),
      http.post("/api/v1/threats/intent-coverage", () => HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 }))
    );
    renderModal();
    const normal = await screen.findByLabelText(/Intended: read_ledger/i);
    const choke = screen.getByLabelText(/Intended: issue_refund/i);
    expect((normal as HTMLInputElement).checked).toBe(false); // deny-all: everything starts unchecked
    expect((choke as HTMLInputElement).checked).toBe(false); // never pre-allow a chokepoint
    // the chokepoint is visually flagged
    expect(screen.getByText(/reached/i)).toBeInTheDocument();
    expect(screen.getByText(/intended\?/i)).toBeInTheDocument();
  });

  it("toggling a checkbox calls fetchIntentCoverage with the updated allow_tools", async () => {
    const bodies: Array<{ allow_tools: string[] }> = [];
    server.use(
      suggestHandler(),
      http.post("/api/v1/threats/intent-coverage", async ({ request }) => {
        bodies.push((await request.json()) as { allow_tools: string[] });
        return HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 });
      })
    );
    renderModal();
    // deny-all default: the first coverage call runs with an EMPTY allowlist
    await waitFor(() => expect(bodies.length).toBeGreaterThan(0));
    expect(bodies[0].allow_tools).toEqual([]);

    // check a tool → coverage re-runs with it in allow_tools
    fireEvent.click(screen.getByLabelText(/Intended: read_ledger/i));
    await waitFor(() => expect(bodies.some((b) => b.allow_tools.includes("read_ledger"))).toBe(true));
  });

  it("Apply is disabled when no tools are checked and no toggles are on", async () => {
    server.use(
      suggestHandler(),
      http.post("/api/v1/threats/intent-coverage", () => HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 }))
    );
    renderModal();
    await screen.findByLabelText(/Intended: read_ledger/i);
    // clear the default-checked tool → nothing checked, no toggle on
    fireEvent.click(screen.getByRole("button", { name: /^clear$/i }));
    const apply = screen.getByRole("button", { name: /apply intent policy/i });
    await waitFor(() => expect(apply).toBeDisabled());
    // enabling a refinement toggle re-enables Apply
    fireEvent.click(screen.getByRole("button", { name: /Read-only/i }));
    await waitFor(() => expect(apply).not.toBeDisabled());
  });

  it("Apply creates a draft with the checked tools + shows the confirmation", async () => {
    let draftBody: { allow_tools: string[] } | null = null;
    server.use(
      suggestHandler(),
      http.post("/api/v1/threats/intent-coverage", () => HttpResponse.json({ rego: "package x", covered: ["p2"], residual: [], covered_count: 1, total: 1 })),
      http.post("/api/v1/threats/intent-draft", async ({ request }) => {
        draftBody = (await request.json()) as { allow_tools: string[] };
        return HttpResponse.json({ draft_id: "d1", policy: "x", ns: "payments", cls: "payments", deeplink: "/policies?draft=d1", enforcement: "draft", valid: true, errors: [], would_block: 1, would_allow: 5, covered_count: 1, total: 1 });
      })
    );
    renderModal();
    await screen.findByLabelText(/Intended: read_ledger/i);
    // deny-all default → explicitly check the intended tool before applying
    fireEvent.click(screen.getByLabelText(/Intended: read_ledger/i));
    fireEvent.click(screen.getByRole("button", { name: /apply intent policy/i }));
    expect(await screen.findByRole("button", { name: /Draft created/i })).toBeInTheDocument();
    const body = draftBody as { allow_tools: string[] } | null;
    expect(body).not.toBeNull();
    expect(body?.allow_tools).toEqual(["read_ledger"]);
  });

  it("warns when a mutating tool is allowlisted, and 'Make read-only' refines it out", async () => {
    server.use(
      http.get("/api/v1/threats/intent-suggest", () => HttpResponse.json({
        ns: "payments", cls: "payments",
        tools: [
          { name: "warehouse_task", allow: 12, block: 0, tag: "chokepoint" as const, target: null, in_attack_path: false, op: "delete", op_risk: "critical", op_src: "learned" }
        ]
      })),
      http.post("/api/v1/threats/intent-coverage", () => HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 }))
    );
    renderModal();
    const box = await screen.findByLabelText(/Intended: warehouse_task/i);
    // no warning until it's allowlisted (deny-all default leaves it unchecked → it's blocked, not granted)
    expect(screen.queryByTestId("destructive-allowlist-warning")).not.toBeInTheDocument();
    fireEvent.click(box);
    // allowlisting the promoted-delete tool grants a destructive capability → warning appears
    const warn = await screen.findByTestId("destructive-allowlist-warning");
    expect(warn).toHaveTextContent(/warehouse_task/);
    expect(warn).toHaveTextContent(/delete/);
    // one-click Read-only refines it out → warning clears
    fireEvent.click(screen.getByRole("button", { name: /make read-only/i }));
    await waitFor(() => expect(screen.queryByTestId("destructive-allowlist-warning")).not.toBeInTheDocument());
  });

  it("warns about a send+egress conflict when an allowlisted egress tool meets 'No external egress', and not otherwise", async () => {
    server.use(
      http.get("/api/v1/threats/intent-suggest", () => HttpResponse.json({
        ns: "payments", cls: "payments",
        tools: [
          { name: "send_email", allow: 5, block: 0, tag: "egress" as const, target: null, in_attack_path: false, op: "send", op_risk: "high", op_src: "registry" }
        ]
      })),
      http.post("/api/v1/threats/intent-coverage", () => HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 }))
    );
    renderModal();
    const box = await screen.findByLabelText(/Intended: send_email/i);
    // not checked yet → no conflict warning
    expect(screen.queryByTestId("egress-conflict-warning")).not.toBeInTheDocument();
    // check it, but "No external egress" is still off → still no conflict warning
    fireEvent.click(box);
    expect(screen.queryByTestId("egress-conflict-warning")).not.toBeInTheDocument();
    // turn on "No external egress" → the allowlisted egress tool now conflicts with the toggle
    fireEvent.click(screen.getByRole("button", { name: /No external egress/i }));
    const warn = await screen.findByTestId("egress-conflict-warning");
    expect(warn).toHaveTextContent(/send_email/);
    expect(warn).toHaveTextContent(/no effect/i);
    // turning the toggle back off clears the warning
    fireEvent.click(screen.getByRole("button", { name: /No external egress/i }));
    await waitFor(() => expect(screen.queryByTestId("egress-conflict-warning")).not.toBeInTheDocument());
  });

  it("does NOT warn on a registry-classified send tool (not EGRESS_TOOLS-tagged) — the backend's " +
    "is_egress never blocks it, so it resolves to ALLOW and the warning would be a false positive", async () => {
    server.use(
      http.get("/api/v1/threats/intent-suggest", () => HttpResponse.json({
        ns: "payments", cls: "payments",
        tools: [
          { name: "forward_ticket", allow: 5, block: 0, tag: "normal" as const, target: null, in_attack_path: false, op: "send", op_risk: "medium", op_src: "registry" }
        ]
      })),
      http.post("/api/v1/threats/intent-coverage", () => HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 }))
    );
    renderModal();
    const box = await screen.findByLabelText(/Intended: forward_ticket/i);
    fireEvent.click(box);
    fireEvent.click(screen.getByRole("button", { name: /No external egress/i }));
    // give any (incorrect) async warning render a chance, then assert it never appears
    await waitFor(() => expect(screen.getByRole("button", { name: /No external egress/i })).toHaveAttribute("aria-pressed", "true"));
    expect(screen.queryByTestId("egress-conflict-warning")).not.toBeInTheDocument();
  });

  it("still warns on an admin-PROMOTED (learned) send tool that isn't EGRESS_TOOLS-tagged — the backend " +
    "blocks it via is_learned_mutating/learned_egress regardless of name", async () => {
    server.use(
      http.get("/api/v1/threats/intent-suggest", () => HttpResponse.json({
        ns: "payments", cls: "payments",
        tools: [
          { name: "custom_relay", allow: 5, block: 0, tag: "normal" as const, target: null, in_attack_path: false, op: "send", op_risk: "high", op_src: "learned" }
        ]
      })),
      http.post("/api/v1/threats/intent-coverage", () => HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 }))
    );
    renderModal();
    const box = await screen.findByLabelText(/Intended: custom_relay/i);
    fireEvent.click(box);
    fireEvent.click(screen.getByRole("button", { name: /No external egress/i }));
    const warn = await screen.findByTestId("egress-conflict-warning");
    expect(warn).toHaveTextContent(/custom_relay/);
  });

  it("closes on Escape", async () => {
    let closed = false;
    server.use(
      suggestHandler(),
      http.post("/api/v1/threats/intent-coverage", () => HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 }))
    );
    render(
      <MemoryRouter>
        <IntentModal ns="payments" cls="payments" tool="issue_refund" paths={[PATH]} onClose={() => { closed = true; }} />
      </MemoryRouter>
    );
    const dialog = await screen.findByRole("dialog", { name: /define intended behaviour/i });
    fireEvent.keyDown(window, { key: "Escape" });
    expect(closed).toBe(true);
    // sanity: the checklist was inside the dialog
    expect(within(dialog).getByLabelText(/Intended: read_ledger/i)).toBeInTheDocument();
  });
});

/**
 * The scope gap, and the route out of it.
 *
 * This modal produces an allowlist of tool NAMES — which is exactly what the agent framework's own
 * tool binding already produces, the finding the Visual Builder's P1 fix exists to answer. It warned
 * about destructive verbs and about egress, but never said that an "intended" tool is intended WITH
 * ANY ARGUMENTS, so a ticked box read as a finished decision when it was half of one.
 *
 * It deliberately does NOT grow an argument editor of its own: two implementations of one concept is
 * the defect shape this project has paid for repeatedly. It hands over instead, through the same
 * `builderGraph` router-state channel /intents and Tools use and PolicyCatalog consumes.
 */
describe("IntentModal — scope gap and builder handoff", () => {
  function coverageHandler() {
    return http.post("/api/v1/threats/intent-coverage", () =>
      HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 })
    );
  }

  it("says nothing about scope for a tool that is not intended", async () => {
    server.use(suggestHandler(), coverageHandler());
    renderModal();
    await screen.findByLabelText(/Intended: read_ledger/i);
    // Unchecked means "not granted at all" — an unrestricted-grant warning there would be noise.
    expect(screen.queryByTestId("intent-tool-scope-read_ledger")).not.toBeInTheDocument();
  });

  it("states that ticking a tool grants it with ANY arguments", async () => {
    server.use(suggestHandler(), coverageHandler());
    renderModal();
    fireEvent.click(await screen.findByLabelText(/Intended: read_ledger/i));
    // The builder's own words for the same state, deliberately — one concept, one vocabulary.
    expect(await screen.findByTestId("intent-tool-scope-read_ledger")).toHaveTextContent(
      "Any arguments · unrestricted"
    );
  });

  it("refuses the handoff until something is intended, and says why", async () => {
    server.use(suggestHandler(), coverageHandler());
    renderModal();
    await screen.findByLabelText(/Intended: read_ledger/i);
    expect(screen.getByTestId("intent-open-in-builder")).toBeDisabled();
    expect(screen.getByText(/Pick the intended tools first/i)).toBeInTheDocument();
  });

  it("hands the checked tools AND the refinements to the builder, in allowlist mode", async () => {
    server.use(suggestHandler(), coverageHandler());
    renderModal();
    fireEvent.click(await screen.findByLabelText(/Intended: read_ledger/i));
    fireEvent.click(screen.getByLabelText(/Intended: issue_refund/i));
    fireEvent.click(screen.getByRole("button", { name: /Read-only/i }));

    const cta = screen.getByTestId("intent-open-in-builder");
    expect(cta).toBeEnabled();
    // The consequence is stated on the way out, not left for the builder to reveal.
    expect(screen.getByText(/grants each tool with ANY arguments/i)).toBeInTheDocument();

    fireEvent.click(cta);

    // ASSERT THE PAYLOAD, not the navigation. A handoff test that only checks the URL is how the
    // Tools -> builder handoff stayed broken behind a green test named "hands off to the builder".
    expect(navigated).not.toBeNull();
    expect(navigated!.to).toBe("/policies/catalog");
    const graph = navigated!.state.builderGraph;
    expect(graph.mode).toBe("allowlist"); // a grant only exists under deny-by-default
    expect(graph.scope).toEqual({ kind: "class", agentClass: "payments" });
    // Asserted present, not optional-chained away: `allowlist` being undefined IS the failure this
    // test exists to catch — a graph in allowlist mode with no allowlist grants nothing at all.
    expect(graph.allowlist).toBeDefined();
    expect(graph.allowlist!.tools).toEqual(["read_ledger", "issue_refund"]);
    expect(graph.allowlist!.refinements.readonly).toBe(true);
    expect(graph.defaults.decision).toBe("block");
  });
});

/**
 * A tool NAME on this checklist is attacker-controlled.
 *
 * `tool_name` comes from observed traffic, so an agent can register `exеcute_sql` with a Cyrillic е
 * (U+0435). In the console's font that row is pixel-identical to the real `execute_sql`. Ticking it
 * is not a cosmetic mistake: `checkedTools` carries the twin's bytes into
 * createIntentDraft({allow_tools}) and into the builder handoff, so the generated DEFAULT-DENY
 * allowlist permits the impostor. The repo already ships the detector (lookalikeOf) and the
 * consequence sentence (LookalikeNote) for exactly this, and no attack-graph surface called them.
 */
describe("IntentModal — a lookalike tool name is marked before it becomes a grant", () => {
  const TWIN = "exеcute_sql"; // U+0435 CYRILLIC SMALL LETTER IE in place of the third character

  function twinHandlers() {
    return [
      http.get("/api/v1/threats/intent-suggest", () =>
        HttpResponse.json({
          ns: ["payments"], cls: "payments",
          tools: [
            { name: "execute_sql", allow: 90, block: 0, tag: "normal" as const, target: null, in_attack_path: false },
            { name: TWIN, allow: 3, block: 0, tag: "normal" as const, target: null, in_attack_path: false }
          ]
        })
      ),
      http.post("/api/v1/threats/intent-coverage", () =>
        HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 })
      )
    ];
  }

  it("marks ONLY the homoglyph row, showing where the invisible character sits", async () => {
    server.use(...twinHandlers());
    renderModal();
    await screen.findByLabelText(`Intended: ${TWIN}`);
    // the plain-ASCII row stays clean — this must not become noise on every tool
    expect(screen.queryByTestId("intent-tool-lookalike-execute_sql")).not.toBeInTheDocument();
    const note = screen.getByTestId(`intent-tool-lookalike-${TWIN}`);
    expect(note).toHaveTextContent("ex·cute_sql"); // the POSITION, not just "something is wrong"
    expect(note).toHaveTextContent("U+0435");
    // and the consequence the operator is entitled to know before ticking the box
    expect(note).toHaveTextContent(/evasion-normalised/i);
  });

  it("marks it on the row itself, next to the name that will become the grant", async () => {
    server.use(...twinHandlers());
    renderModal();
    await screen.findByLabelText(`Intended: ${TWIN}`);
    const row = screen.getByLabelText(`Intended: ${TWIN}`).closest("label")!;
    // The inline chip beside the name AND the note below it — the warning is on the row an operator
    // is about to tick, not tucked into a summary elsewhere.
    expect(within(row).getAllByText(/lookalike name/i).length).toBeGreaterThan(0);
    const clean = screen.getByLabelText("Intended: execute_sql").closest("label")!;
    expect(within(clean).queryAllByText(/lookalike/i)).toHaveLength(0);
  });

  it("still hands the name over EXACTLY as observed — flagged, never silently rewritten", async () => {
    server.use(...twinHandlers());
    renderModal();
    fireEvent.click(await screen.findByLabelText(`Intended: ${TWIN}`));
    fireEvent.click(screen.getByTestId("intent-open-in-builder"));
    // Normalising the bytes here would be its own bug: the operator's decision must be about the
    // real string. The fix is that they can now SEE which string it is.
    expect(navigated!.state.builderGraph.allowlist!.tools).toEqual([TWIN]);
  });
});

/**
 * WHERE A PROMOTED VERB LANDS.
 *
 * The same fail-open that was fixed in ToolVerbsPanel, reached through this modal instead. A learned
 * verb is a row keyed on (namespace, tool_name) and the evaluator reads it back with the REQUEST's
 * namespace, so a row filed under the wrong namespace is never consulted: `input.derived.verb`
 * resolves to `unknown` where the tool actually runs and `block when derived.verb == "delete"` never
 * fires. ToolVerbsPanel POSTed the literal "all"; this modal did something quieter and worse — it
 * read the server's `ns` list (threats.py returns `sorted(seen)`, the union of every namespace in the
 * snapshots it read) and took `[0]`, the ALPHABETICALLY FIRST one. On an admin console at "All
 * namespaces" a `warehouse_task` seen only in `studioai` was promoted into `hr`, which looks entirely
 * plausible in the audit trail. The reload then re-reads overrides across ALL namespaces, so the row
 * came back with a green "✓ learned" chip: the console asserting a classification that is inert
 * everywhere the tool is actually called.
 */
describe("IntentModal — a promoted verb goes to ONE real namespace or nowhere", () => {
  const OBSERVING = {
    name: "warehouse_task", allow: 42, block: 0, tag: "normal" as const, target: null, in_attack_path: false,
    op: null, op_risk: null, op_src: null,
    observed_calls: 42, inferred_verb: "delete" as const, inferred_count: 30
  };

  /** `nsList` is what the server resolved the scope to. An admin at "all" gets every namespace it read. */
  function scopedHandlers(nsList: string[], posted?: unknown[]) {
    return [
      http.get("/api/v1/me", () => HttpResponse.json({ sub: "admin", role: "admin", namespace: null })),
      http.get("/api/v1/threats/intent-suggest", () =>
        HttpResponse.json({ ns: nsList, cls: "payments", tools: [OBSERVING] })
      ),
      http.post("/api/v1/threats/intent-coverage", () =>
        HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 })
      ),
      http.post("/api/v1/threats/tool-verbs/promote", async ({ request }) => {
        posted?.push(await request.json());
        return HttpResponse.json({ promoted: true, verb: "delete", risk: "critical" });
      })
    ];
  }

  function renderGlobal() {
    return render(
      <MemoryRouter>
        <IntentModal ns="all" cls="payments" tool="" paths={[PATH]} onClose={() => {}} global />
      </MemoryRouter>
    );
  }

  it("never promotes into the alphabetically-first of SEVERAL resolved namespaces", async () => {
    const posted: unknown[] = [];
    server.use(...scopedHandlers(["hr", "payments", "studioai"], posted));
    renderGlobal();
    const promote = await screen.findByRole("button", { name: /promote as delete/i });

    // Pre-fix this POSTed {"ns":"hr","tool_name":"warehouse_task","verb":"delete"} and reported
    // success — a learned verb filed in a namespace the tool is never called from.
    fireEvent.click(promote);
    await waitFor(() => expect(screen.getByText(/warehouse_task/)).toBeInTheDocument());
    expect(posted).toEqual([]);
    expect(promote).toBeDisabled();
  });

  it("says why, in visible text, rather than doing nothing when clicked", async () => {
    server.use(...scopedHandlers(["hr", "payments", "studioai"]));
    renderGlobal();
    await screen.findByRole("button", { name: /promote as delete/i });
    // `.btn:disabled { pointer-events: none }` — a title on a disabled control can never be read, so
    // the blocked reason has to be text on the page.
    const reason = screen.getByTestId("intent-verb-scope-warehouse_task-reason");
    expect(reason).toHaveTextContent(/learned per namespace/i);
    expect(reason).toHaveTextContent(/did not resolve to a single one/i);
  });

  it("does not offer a promotion that would silently do nothing when NO namespace resolved", async () => {
    // The other half of the old behaviour: with an empty `ns` the click fell through a `!promoNs`
    // early return — no POST, no error, no change. The button looked live and the tooltip named
    // "this namespace", so the operator's only evidence that nothing happened was that nothing
    // happened. An action that cannot be performed must say so instead of absorbing the click.
    const posted: unknown[] = [];
    server.use(...scopedHandlers([], posted));
    renderGlobal();
    const promote = await screen.findByRole("button", { name: /promote as delete/i });
    expect(promote).toBeDisabled();
    fireEvent.click(promote);
    await waitFor(() => expect(screen.getByText(/warehouse_task/)).toBeInTheDocument());
    expect(posted).toEqual([]);
    expect(screen.getByTestId("intent-verb-scope-warehouse_task-reason")).toBeInTheDocument();
    // …and it no longer claims a destination. The old title read "in this namespace" — naming a
    // place the click would never have written to. (`?? ""` because an absent title is the fix.)
    expect(promote.getAttribute("title") ?? "").not.toMatch(/this namespace/i);
  });

  it("promotes into the ONE namespace the server resolved the scope to", async () => {
    // A namespace-scoped caller asking for "all" gets exactly its own back. That IS concrete, so
    // promoting into it is honest — the fix must not disable the case it is supposed to allow.
    const posted: unknown[] = [];
    server.use(...scopedHandlers(["studioai"], posted));
    renderGlobal();
    fireEvent.click(await screen.findByRole("button", { name: /promote as delete/i }));
    await waitFor(() =>
      expect(posted).toEqual([{ ns: "studioai", tool_name: "warehouse_task", verb: "delete" }])
    );
  });

  it("names the destination namespace on the control, not 'this namespace'", async () => {
    server.use(...scopedHandlers(["studioai"]));
    renderGlobal();
    const promote = await screen.findByRole("button", { name: /promote as delete/i });
    expect(promote).toBeEnabled();
    // The old copy said "in this namespace" whenever the scope resolved to none — naming a namespace
    // the click would never have written to.
    expect(promote.getAttribute("title")).toContain("in studioai");
    expect(promote.getAttribute("title")).not.toMatch(/this namespace/i);
  });
});

/**
 * "Granted to" must name the class the draft is ACTUALLY created for — one class.
 *
 * `createIntentDraft`, `fetchIntentSuggest` and `fetchIntentCoverage` all take `activeCls`, but the
 * per-path branch used to render every source class that reaches the tool. On a busy namespace that is
 * forty-odd names, including e2e debris, under a heading reading "Intended behaviour · <one class>"
 * and followed by "everything else is denied by default". The only available reading was that applying
 * it would grant, or constrain, all of them.
 *
 * Reported by a product user reading the screen — there was no test of any kind on this line, at any
 * level, which is why it shipped.
 */
describe("IntentModal — the grant target is one class, not everyone who reaches the tool", () => {
  // `alsoReach` compares each path's SOURCE CLASS against the active class, so the fixture has to put
  // the active class on its own path — otherwise the class being granted counts itself as an "other"
  // and the numbers are off by one. (That is exactly what my first draft of this test got wrong: it
  // reused the shared PATH, whose src is `billing-runner` while cls is `payments`.)
  const from = (src: string, id: string): ThreatPath => ({
    ...PATH,
    id,
    src,
    // Same tool — that is precisely what made the old code list them all as the grant target.
    tool: "issue_refund"
  });
  const MINE = from("payments", "p2");

  function renderCrowded() {
    return render(
      <MemoryRouter>
        <IntentModal
          ns="payments"
          cls="payments"
          tool="issue_refund"
          paths={[MINE, from("q2-manual-1786050017202", "p3"), from("bce2e-create", "p4"), from("test", "p5")]}
          onClose={() => {}}
        />
      </MemoryRouter>
    );
  }

  it("names only the active class, never the other classes that reach the same tool", async () => {
    server.use(
      suggestHandler(),
      http.post("/api/v1/threats/intent-coverage", () =>
        HttpResponse.json({ rego: "package x", covered: [], residual: [], covered_count: 0, total: 4 })
      )
    );
    renderCrowded();

    const granted = await screen.findByText(/Granted to/i);
    expect(granted).toHaveTextContent("payments");
    // FAIL-ON-BUG: these are other classes' names. A grant sentence must not contain them.
    expect(granted).not.toHaveTextContent("q2-manual-1786050017202");
    expect(granted).not.toHaveTextContent("bce2e-create");
  });

  it("still surfaces those other classes — as a warning, not as the grant target", async () => {
    server.use(
      suggestHandler(),
      http.post("/api/v1/threats/intent-coverage", () =>
        HttpResponse.json({ rego: "package x", covered: [], residual: [], covered_count: 0, total: 4 })
      )
    );
    renderCrowded();

    // The fact is worth keeping: those classes reach the same tool and each needs its own intent.
    // What changed is that it is stated as what it is instead of as who this policy grants.
    const note = await screen.findByTestId("intent-also-reach");
    expect(note).toHaveTextContent(/3 other classes also reach/i);
    expect(note).toHaveTextContent(/does not constrain them/i);
  });

  it("says nothing about other classes when the active class is the only one reaching the tool", async () => {
    server.use(
      suggestHandler(),
      http.post("/api/v1/threats/intent-coverage", () =>
        HttpResponse.json({ rego: "package x", covered: [], residual: ["p2"], covered_count: 0, total: 1 })
      )
    );
    render(
      <MemoryRouter>
        <IntentModal ns="payments" cls="payments" tool="issue_refund" paths={[MINE]} onClose={() => {}} />
      </MemoryRouter>
    );

    await screen.findByText(/Granted to/i);
    // A warning that fires when there is nothing to warn about is noise, and noise is how a warning
    // gets trained out of existence before the one time it matters.
    expect(screen.queryByTestId("intent-also-reach")).not.toBeInTheDocument();
  });
});
