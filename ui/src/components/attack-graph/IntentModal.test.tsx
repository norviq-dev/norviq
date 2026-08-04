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
