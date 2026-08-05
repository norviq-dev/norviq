// SPDX-License-Identifier: Apache-2.0
// Policy Tester — what DECIDED this call must be true of the engine that decided it.
//
// POST /api/v1/evaluate returns exactly three fields (evaluate.py `EvaluateResponse`:
// decision / rule_id / trust_score). It has never carried `trust_signals`, so the Signals block's
// "no signals" branch is the ONLY one an operator can ever reach — and it used to end the sentence
// with two claims the endpoint cannot support: that "the policy decided on rules alone", and that
// signals "populate once trust telemetry is active for this agent".
//
// Both are false, and the first is dangerous: `_apply_trust_overrides` (evaluator.py:862-885) can
// return block/`trust_frozen` and escalate/`escalate_low_trust` with NO rule involved at all. An
// operator checking "does my new rule block execute_sql for this class?" saw BLOCK, was told a rule
// did it, and could ship a policy whose rule does not exist — the block came from the frozen agent
// and vanishes the moment a healthy one makes the same call.
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { PolicyTester } from "./PolicyTester";
import { AppProvider } from "../store/AppContext";

const server = setupServer(
  http.get("/api/v1/cluster-info", () => HttpResponse.json({ cluster_id: "local", cluster_name: "local", namespaces: ["default"] })),
  http.get("/api/v1/settings", () => HttpResponse.json({ namespace: "default", enforcement_mode: "block", trust_threshold: 0.7, rate_limit: 60, apply_mode: "enforce" }))
);
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter>
      <AppProvider>
        <PolicyTester />
      </AppProvider>
    </MemoryRouter>
  );
}

/** The REAL response shape — the three fields evaluate.py's response model actually has. */
function evaluateReturns(decision: string, rule_id: string, trust_score = 0.5) {
  server.use(http.post("/api/v1/evaluate", () => HttpResponse.json({ decision, rule_id, trust_score })));
}

async function run() {
  renderPage();
  fireEvent.click(await screen.findByRole("button", { name: /^evaluate$/i }));
}

describe("the Signals note cannot claim what /evaluate does not return", () => {
  it("never says 'the policy decided on rules alone'", async () => {
    evaluateReturns("block", "trust_frozen", 0.0);
    await run();
    await waitFor(() => expect(screen.getByTestId("signals-unavailable")).toBeInTheDocument());

    // FAIL-ON-BUG: pre-fix this exact sentence renders on EVERY evaluation, including this one,
    // where no rule fired at all.
    expect(screen.queryByText(/decided on rules alone/i)).not.toBeInTheDocument();
  });

  it("never promises signals will populate once telemetry is active", async () => {
    evaluateReturns("allow", "default_allow", 0.9);
    await run();
    await waitFor(() => expect(screen.getByTestId("signals-unavailable")).toBeInTheDocument());

    // FAIL-ON-BUG: the field is absent from the response MODEL, not merely from this agent's
    // telemetry — waiting for it to appear is waiting forever.
    expect(screen.queryByText(/populate once trust telemetry is active/i)).not.toBeInTheDocument();
    // It must instead say the endpoint does not carry them.
    expect(screen.getByTestId("signals-unavailable")).toHaveTextContent(/does not (return|carry)/i);
  });
});

describe("a decision the engine made is not reported as a rule the operator wrote", () => {
  it("names the trust override on a trust_frozen block", async () => {
    evaluateReturns("block", "trust_frozen", 0.0);
    await run();

    // FAIL-ON-BUG: pre-fix nothing on the page distinguished this from `deny_execute_sql` firing.
    const note = await screen.findByTestId("rule-provenance");
    expect(note).toHaveTextContent(/trust override/i);
    expect(note).toHaveTextContent(/not .*an authored rule/i);
  });

  it("names the trust override on an escalate_low_trust escalation", async () => {
    evaluateReturns("escalate", "escalate_low_trust", 0.21);
    await run();

    const note = await screen.findByTestId("rule-provenance");
    expect(note).toHaveTextContent(/trust override/i);
  });

  it("names the fail-closed default rather than letting it read as coverage", async () => {
    evaluateReturns("block", "no_policy_loaded", 0.8);
    await run();

    // The Attack Graph's simulate() already refuses to report this as "blocked by policy"
    // (AttackGraph.tsx) — the Tester must not disagree with it about the same rule_id.
    const note = await screen.findByTestId("rule-provenance");
    expect(note).toHaveTextContent(/fail-closed/i);
  });

  it("says an allow came from the default, not from a rule that permits the call", async () => {
    evaluateReturns("allow", "default_allow", 0.9);
    await run();

    const note = await screen.findByTestId("rule-provenance");
    expect(note).toHaveTextContent(/no rule matched/i);
  });

  // An UNNAMED rule id is not the same claim on every decision.
  //
  // OPA returns `str(result.get("rule_id", ""))` on both the server and subprocess paths, so a module
  // that sets `decision` without setting `rule_id` produces an empty one — and the engine clamps ONLY
  // the block case (`_ensure_block_attribution` rewrites block+empty to `unattributed_block`). So
  // `{"decision": "escalate", "rule_id": ""}` and the Monitor-mode `{"decision": "audit",
  // "rule_id": ""}` reach /evaluate exactly as written; both bodies below are ones the route really
  // can return. `ruleLabel` prints an empty id as "default_allow", so keying the gloss on rule_id
  // alone printed "Allowed because NO rule matched" directly under an ESCALATE or AUDIT badge — a
  // sentence asserting the opposite of the decision beside it, on the screen whose only job is to say
  // what the policy did. An AUDIT row is a WOULD-BLOCK.
  it("does not print 'Allowed' under an ESCALATE whose rule id came back empty", async () => {
    evaluateReturns("escalate", "", 0.4);
    await run();

    const note = await screen.findByTestId("rule-provenance");
    // FAIL-ON-BUG: the default_allow gloss, verbatim, beneath an ESCALATE badge.
    expect(note).not.toHaveTextContent(/Allowed because/i);
    expect(note).toHaveTextContent(/without naming a rule/i);
    expect(note).toHaveTextContent(/placeholder for an empty rule id/i);
  });

  it("does not print 'Allowed' under an AUDIT (would-block) whose rule id came back empty", async () => {
    evaluateReturns("audit", "", 0.4);
    await run();

    const note = await screen.findByTestId("rule-provenance");
    expect(note).not.toHaveTextContent(/Allowed because/i);
    expect(note).toHaveTextContent(/without naming a rule/i);
  });

  it("still reads the allow case as the engine default (the control)", async () => {
    // The gloss is right on an ALLOW and must survive the decision gate above.
    evaluateReturns("allow", "", 0.9);
    await run();

    const note = await screen.findByTestId("rule-provenance");
    expect(note).toHaveTextContent(/Allowed because NO rule matched/i);
  });

  // MONITOR MODE IS WHERE MOST POLICY VERIFICATION HAPPENS, AND THE MAP DID NOT REACH IT.
  //
  // `_apply_posture` / `_apply_policy_mode` rewrite a block or escalate to `audit` and PREFIX the
  // rule id (`monitor_would_block:` / `policy_audit_would_block:`). `_POSTURE_EXEMPT_RULES` keeps
  // trust_frozen and the engine-health blocks hard, but `no_policy_loaded` and `escalate_low_trust`
  // are not exempt — so the single most important thing this screen can say, "there is no policy
  // here at all", arrived as `audit` / `monitor_would_block:no_policy_loaded` and the gloss for it
  // was never looked up. Silence is not a lie, but it is the finding's own scenario going unanswered.
  it("reaches the gloss through a Monitor-mode would-block prefix", async () => {
    evaluateReturns("audit", "monitor_would_block:no_policy_loaded", 0.8);
    await run();

    const note = await screen.findByTestId("rule-provenance");
    expect(note).toHaveTextContent(/evaluated, not enforced/i); // an audit row is a WOULD-block
    expect(note).toHaveTextContent(/fail-closed/i); // …and the id under the prefix still decides
  });

  it("says a softened AUTHORED rule enforced nothing", async () => {
    // No gloss exists for `deny_sql_injection` and none should be invented — but "your rule matched
    // and the call went through anyway" is the answer a rule-verification screen owes the operator.
    evaluateReturns("audit", "policy_audit_would_block:deny_sql_injection", 0.5);
    await run();

    const note = await screen.findByTestId("rule-provenance");
    expect(note).toHaveTextContent(/Nothing was stopped/i);
    expect(note).toHaveTextContent(/evaluated, not enforced/i);
  });

  it("stays quiet when a rule the operator authored actually decided", async () => {
    evaluateReturns("block", "deny_sql_injection", 0.5);
    await run();
    await waitFor(() => expect(screen.getByTestId("signals-unavailable")).toBeInTheDocument());

    // An authored rule id IS the answer — no second sentence needed, and inventing provenance for
    // it would be its own fabrication.
    expect(screen.queryByTestId("rule-provenance")).not.toBeInTheDocument();
  });
});
