// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The Intents screen exists so deny-by-default can be ADOPTED, not just shipped. These tests assert
// the properties that make it adoptable: the operator sees what would break before anything is
// saved, a draft cannot be saved without that step, the near-miss reaches the screen, and nothing on
// this page enforces.

import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Intents, paramsDetailOf, readObservedParams, unscopedArgs } from "./Intents";
import { ToastProvider } from "../components/common/Toast";
import { AppProvider } from "../store/AppContext";
import { clearApiCache } from "../hooks/useApi";
import * as client from "../api/client";

const PROPOSAL = {
  intent: {
    name: "support-bot-intent",
    class: "support-bot",
    call: [
      {
        id: "postgres-prod-read-select-rows",
        server: "postgres-prod",
        match: { verb: "read", tool_name: { in: ["select_rows"] }, sql_tables: { subsetOf: ["orders"] } },
        require: { data_classes: { noneOf: ["secret"] } }
      },
      {
        id: "send-send-email",
        match: { verb: "send", "param_paths.to": { matches: "^[^@]+@acme\\.com$" } },
        require: { data_classes: { noneOf: ["secret"] } }
      }
    ]
  },
  sampled: 5,
  params_available: true
};

const REPORT_WITH_BLOCKS = {
  total: 6,
  would_allow: 5,
  would_block: 1,
  coverage: { "postgres-prod-read-select-rows": 2, "send-send-email": 3 },
  unused_rules: [],
  blocked: [
    {
      index: 5,
      tool_name: "send_email",
      reason:
        "no intent rule matched; closest send-send-email met 3/4, failed: param_paths.to matches ^[^@]+@acme\\.com$"
    }
  ]
};

function renderPage(ns = "agents") {
  return render(
    <MemoryRouter initialEntries={[`/intents?ns=${ns}`]}>
      <AppProvider>
        <ToastProvider>
          <Intents />
        </ToastProvider>
      </AppProvider>
    </MemoryRouter>
  );
}

async function propose(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Agent class"), "support-bot");
  await user.click(screen.getByRole("button", { name: /propose intent/i }));
}

describe("Intents", () => {
  beforeEach(() => {
    clearApiCache();
    vi.restoreAllMocks();
  });

  it("proposes an intent from traffic and shows each rule as a sentence, not JSON", async () => {
    vi.spyOn(client, "apiSend").mockResolvedValue(PROPOSAL as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);

    await waitFor(() => expect(screen.getByTestId("rule-send-send-email")).toBeInTheDocument());
    const rule = screen.getByTestId("rule-send-send-email");
    // Two bands, not one flat predicate line. APPLIES TO answers "is this rule about the call I am
    // worried about?"; ALLOWED IF answers "and what must additionally hold?". Flattened together,
    // every rule looked like it might govern every call.
    expect(within(rule).getByText("Applies to")).toBeInTheDocument();
    expect(within(rule).getByText("Allowed if")).toBeInTheDocument();
    expect(within(rule).getByText(/the operation is send/i)).toBeInTheDocument();
    // The anchored recipient regex is stated as the domain it pins, not echoed as a regex.
    expect(within(rule).getByText(/the to is an address at acme\.com/i)).toBeInTheDocument();
  });

  it("keeps the engine's own predicate text one click away", async () => {
    // The near-miss report quotes these strings back, so an operator who has read a refusal must be
    // able to find the same string on the rule. One dialect, per the design brief.
    vi.spyOn(client, "apiSend").mockResolvedValue(PROPOSAL as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);

    await waitFor(() => expect(screen.getByTestId("rule-send-send-email")).toBeInTheDocument());
    await user.click(screen.getByTestId("rule-send-send-email-raw-toggle"));
    expect(screen.getByTestId("rule-send-send-email-raw")).toHaveTextContent("param_paths.to matches");
  });

  it("states a clause every rule repeats ONCE, above the set", async () => {
    // `data_classes noneOf ['secret']` is attached to every proposed rule. Repeated on each card it
    // costs a line per rule and buries the clauses that actually differ.
    vi.spyOn(client, "apiSend").mockResolvedValue(PROPOSAL as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);

    const hoisted = await screen.findByTestId("hoisted-clauses");
    expect(hoisted).toHaveTextContent(/carries none of secret/i);
    // ...and NOT on the individual cards.
    expect(within(screen.getByTestId("rule-send-send-email")).queryByText(/carries none of secret/i)).toBeNull();
  });

  it("will not let a draft be saved before the dry run", async () => {
    vi.spyOn(client, "apiSend").mockResolvedValue(PROPOSAL as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);

    await waitFor(() => expect(screen.getByRole("button", { name: /save as draft/i })).toBeDisabled());
    expect(screen.getByTestId("dryrun-hint")).toBeInTheDocument();
  });

  it("puts the near miss on screen — the rule that came closest and the clause that failed", async () => {
    const send = vi.spyOn(client, "apiSend");
    send.mockResolvedValueOnce(PROPOSAL as never).mockResolvedValueOnce(REPORT_WITH_BLOCKS as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);
    await waitFor(() => expect(screen.getByRole("button", { name: /dry run/i })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: /dry run/i }));

    await waitFor(() => expect(screen.getByText(/what this would have refused/i)).toBeInTheDocument());
    expect(screen.getByText(/closest send-send-email met 3\/4/)).toBeInTheDocument();
    expect(screen.getByText(/failed: param_paths\.to matches/)).toBeInTheDocument();
  });

  it("says plainly when nothing would break, which is the point it is safe to draft", async () => {
    const clean = { ...REPORT_WITH_BLOCKS, would_block: 0, would_allow: 6, blocked: [] };
    const send = vi.spyOn(client, "apiSend");
    send.mockResolvedValueOnce(PROPOSAL as never).mockResolvedValueOnce(clean as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);
    await user.click(screen.getByRole("button", { name: /dry run/i }));

    await waitFor(() => expect(screen.getByTestId("no-blocks")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /save as draft/i })).toBeEnabled();
  });

  it("flags a rule that matched nothing, because that rule is probably written wrongly", async () => {
    const unused = { ...REPORT_WITH_BLOCKS, unused_rules: ["postgres-prod-read-select-rows"] };
    const send = vi.spyOn(client, "apiSend");
    send.mockResolvedValueOnce(PROPOSAL as never).mockResolvedValueOnce(unused as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);
    await user.click(screen.getByRole("button", { name: /dry run/i }));

    await waitFor(() => {
      const rule = screen.getByTestId("rule-postgres-prod-read-select-rows");
      expect(within(rule).getByText(/matched nothing/i)).toBeInTheDocument();
    });
  });

  it("warns when the proposal could only see tool names", async () => {
    vi.spyOn(client, "apiSend").mockResolvedValue({ ...PROPOSAL, params_available: false } as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);

    await waitFor(() => expect(screen.getByTestId("params-warning")).toBeInTheDocument());
    // A primary state, not a footnote: with no recorded arguments a rule grants the tool outright,
    // and saying so is the difference between an informed draft and a surprise.
    expect(screen.getByText(/Proposed from tool names only/i)).toBeInTheDocument();
    expect(screen.getByTestId("params-warning")).toHaveTextContent(/grants a tool outright/i);
  });

  it("states that a saved draft is not enforcing and where enforcement actually begins", async () => {
    const clean = { ...REPORT_WITH_BLOCKS, would_block: 0, blocked: [] };
    const send = vi.spyOn(client, "apiSend");
    send
      .mockResolvedValueOnce(PROPOSAL as never)
      .mockResolvedValueOnce(clean as never)
      .mockResolvedValueOnce({ draft_id: "intent-abc123" } as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);
    await user.click(screen.getByRole("button", { name: /dry run/i }));
    await waitFor(() => expect(screen.getByRole("button", { name: /save as draft/i })).toBeEnabled());
    await user.click(screen.getByRole("button", { name: /save as draft/i }));

    await waitFor(() => expect(screen.getByTestId("draft-saved")).toBeInTheDocument());
    const banner = screen.getByTestId("draft-saved");
    expect(within(banner).getByText(/not enforcing/i)).toBeInTheDocument();
    expect(within(banner).getByText(/Policy Catalog/i)).toBeInTheDocument();
  });

  it("refuses to draft while the scope is All namespaces, because a draft targets one", async () => {
    const send = vi.spyOn(client, "apiSend");
    const clean = { ...REPORT_WITH_BLOCKS, would_block: 0, blocked: [] };
    send.mockResolvedValueOnce(PROPOSAL as never).mockResolvedValueOnce(clean as never);
    const user = userEvent.setup();
    renderPage("all");
    await propose(user);
    await user.click(screen.getByRole("button", { name: /dry run/i }));

    await waitFor(() => expect(screen.getByTestId("no-blocks")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: /save as draft/i })).toBeDisabled();
  });

  it("says the arguments were captured but unreported, rather than drawing an empty list", async () => {
    // An API that predates the observed-argument field. `params_available: true` says arguments WERE
    // captured, so the screen must not fall back to "tool names only" — and it must not render an
    // empty argument list either, because an empty list reads as "this tool takes none".
    vi.spyOn(client, "apiSend").mockResolvedValue(PROPOSAL as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);

    const band = await screen.findByTestId("observed-args-unavailable");
    expect(band).toHaveTextContent(/did not report which/i);
    expect(band).toHaveTextContent(/unknown, not as nothing to constrain/i);
    expect(screen.queryByTestId("params-warning")).toBeNull();
    expect(screen.queryByTestId("unscoped-args")).toBeNull();
  });

  it("sends the dry run to the API and never an apply", async () => {
    const send = vi.spyOn(client, "apiSend");
    send.mockResolvedValueOnce(PROPOSAL as never).mockResolvedValueOnce(REPORT_WITH_BLOCKS as never);
    const user = userEvent.setup();
    renderPage();
    await propose(user);
    await user.click(screen.getByRole("button", { name: /dry run/i }));

    await waitFor(() => expect(send).toHaveBeenCalledTimes(2));
    const paths = send.mock.calls.map((c) => String(c[0]));
    expect(paths).toEqual(["/api/v1/intents/propose", "/api/v1/intents/dry-run"]);
    expect(paths.some((p) => /apply|enforce/.test(p))).toBe(false);
  });
});

// ------------------------------------------------------------------------------------------------
// The argument names traffic carried, and the gap between them and the rule being authored.
//
// Two operators independently reported the same dead end, in nearly the same sentence: a rule was
// written that they believed covered a call, the engine enforced it exactly as written, and the model
// emitted `{"tool_name": "issue_refund", "tool_params": {"txn_id": "TXN-8891", "amount": 25.0}}` —
// which no predicate mentioned, so the call was allowed. The authoring surface showed argument names
// from the SCHEMA and never the ones recorded traffic carried, so there was no point before saving at
// which the mismatch could have been seen.
//
// These tests pin that moment. Not "a field arrived" — the operator SEEING that traffic carries
// `amount` and that their rule is silent about it, on the screen with the Save button.
// ------------------------------------------------------------------------------------------------

/** Exactly the reported call: a refund rule scoped to the TOOL and nothing else. */
const REFUND_PROPOSAL = {
  intent: {
    name: "billing-bot-intent",
    class: "billing-bot",
    call: [
      {
        id: "billing-write-issue-refund",
        match: { verb: "write", tool_name: { in: ["issue_refund"] } },
        require: { data_classes: { noneOf: ["secret"] } }
      }
    ]
  },
  sampled: 12,
  // Keys without values: `params_available` keeps its old meaning (masked VALUES), and is false.
  params_available: false,
  params_detail: "keys",
  observed_params: { issue_refund: ["amount", "txn_id"] }
};

describe("the arguments traffic carried", () => {
  beforeEach(() => {
    clearApiCache();
    vi.restoreAllMocks();
  });

  it("shows the argument names issue_refund actually carried, and FLAGS the one the rule never mentions", async () => {
    vi.spyOn(client, "apiSend").mockResolvedValue(REFUND_PROPOSAL as never);
    const user = userEvent.setup();
    renderPage();
    await user.type(screen.getByLabelText("Agent class"), "billing-bot");
    await user.click(screen.getByRole("button", { name: /propose intent/i }));

    // The names are on screen beside the rule they belong to — the thing the surface never showed.
    const band = await screen.findByTestId("observed-args-billing-write-issue-refund");
    expect(band).toHaveTextContent("amount");
    expect(band).toHaveTextContent("txn_id");
    // ...and each is marked as absent from the rule. This flag IS the deliverable.
    expect(within(band).getAllByTestId("unscoped-arg-billing-write-issue-refund")).toHaveLength(2);
    expect(band).toHaveTextContent(/allows the call whatever they contain/i);

    // Stated once at the top too, so it cannot be scrolled past on the way to Save as draft.
    const summary = screen.getByTestId("unscoped-args");
    expect(summary).toHaveTextContent(/2 arguments in traffic that no rule mentions/i);
    expect(summary).toHaveTextContent("amount");
    expect(summary).toHaveTextContent("billing-write-issue-refund");
  });

  it("does not flag an argument the rule DOES constrain", async () => {
    // The other half of the flag: it must be quiet when the rule is right, or it is noise and gets
    // ignored on the proposal where it matters.
    const scoped = {
      ...REFUND_PROPOSAL,
      intent: {
        ...REFUND_PROPOSAL.intent,
        call: [
          {
            id: "billing-write-issue-refund",
            match: { verb: "write", tool_name: { in: ["issue_refund"] } },
            require: { "param_paths.amount": { matches: "^\\d+$" }, "param_paths.txn_id": { matches: "^TXN-" } }
          }
        ]
      }
    };
    vi.spyOn(client, "apiSend").mockResolvedValue(scoped as never);
    const user = userEvent.setup();
    renderPage();
    await user.type(screen.getByLabelText("Agent class"), "billing-bot");
    await user.click(screen.getByRole("button", { name: /propose intent/i }));

    const band = await screen.findByTestId("observed-args-billing-write-issue-refund");
    expect(within(band).queryAllByTestId("unscoped-arg-billing-write-issue-refund")).toHaveLength(0);
    // Tightened during verification from /this rule constrains it/, which also matched the
    // presence-only copy and so could not tell a real value clause from `{"matches": ".*"}`.
    expect(band).toHaveTextContent(/this rule constrains its value/i);
    expect(within(band).queryAllByTestId("presence-only-arg-billing-write-issue-refund")).toHaveLength(0);
    expect(screen.queryByTestId("unscoped-args")).toBeNull();
  });

  it("never renders 'no arguments were captured' the same way as 'captured, and there are none'", async () => {
    // The recurring defect in this codebase. One tool was captured and genuinely carried nothing; the
    // other was never reported at all. Rendering those identically tells an operator a tool takes no
    // arguments when in fact nobody looked.
    //
    // FIXTURE REWRITTEN during verification, and the reason is the point of the test. It previously
    // fed `observed_params: { list_matters: [] }` — a BARE LIST, a shape the API never emits — and
    // relied on an OMITTED entry for the unknown half. The API emits an object per tool carrying its
    // own `detail`, always including the tools it saw, so neither half of the old fixture could occur
    // against the running server: the state the test name claims was unreachable from it, and the
    // real state (`detail: "none"`, empty keys) rendered as the FALSE sentence this test forbids.
    // The assertions are unchanged and now run against a payload the server can actually produce.
    const legal = {
      intent: {
        name: "legal-bot-intent",
        class: "legal-bot",
        call: [
          {
            id: "legal-read-matters",
            match: { verb: "read", tool_name: { in: ["list_matters", "search_matter"] } },
            require: {}
          }
        ]
      },
      sampled: 30,
      params_available: false,
      params_detail: "keys",
      observed_params: {
        // captured, and genuinely carried nothing
        list_matters: { detail: "keys", keys: [], pinnable: [], ambiguous: [], calls: 18, truncated: false, dropped: 0 },
        // seen in traffic, but every row predates argument-name capture — nothing is known
        search_matter: { detail: "none", keys: [], pinnable: [], ambiguous: [], calls: 12, truncated: false, dropped: 0 }
      }
    };
    vi.spyOn(client, "apiSend").mockResolvedValue(legal as never);
    const user = userEvent.setup();
    renderPage();
    await user.type(screen.getByLabelText("Agent class"), "legal-bot");
    await user.click(screen.getByRole("button", { name: /propose intent/i }));

    const captured = await screen.findByTestId("observed-args-legal-read-matters-empty-list_matters");
    const unknown = screen.getByTestId("observed-args-legal-read-matters-unknown-search_matter");
    expect(captured).toHaveTextContent(/carried\s+no arguments at all/i);
    expect(unknown).toHaveTextContent(/no argument names were recorded/i);
    // The one that matters: the unknown case must NOT claim the tool takes none.
    expect(unknown).toHaveTextContent(/not evidence it takes none/i);
    expect(captured.textContent).not.toEqual(unknown.textContent);
  });

  it("will not render a homoglyph argument as the ASCII name the operator thinks they scoped", async () => {
    // `аmount` opens with U+0430 CYRILLIC SMALL LETTER A and is pixel-identical to `amount`.
    // `input.derived.param_paths` carries VERBATIM keys — `_fold_path` folds only for collision
    // detection — so the rule's `param_paths.amount` clause does NOT cover this path. Printed raw,
    // the screen would show a name that matches the clause above it and reassure the operator that
    // the argument the traffic actually carried is constrained. It is not.
    const cyrillic = "аmount";
    const spoofed = {
      ...REFUND_PROPOSAL,
      intent: {
        ...REFUND_PROPOSAL.intent,
        call: [
          {
            id: "billing-write-issue-refund",
            match: { verb: "write", tool_name: { in: ["issue_refund"] } },
            require: { "param_paths.amount": { matches: "^\\d+$" } }
          }
        ]
      },
      observed_params: { issue_refund: [cyrillic] }
    };
    vi.spyOn(client, "apiSend").mockResolvedValue(spoofed as never);
    const user = userEvent.setup();
    renderPage();
    await user.type(screen.getByLabelText("Agent class"), "billing-bot");
    await user.click(screen.getByRole("button", { name: /propose intent/i }));

    const band = await screen.findByTestId("observed-args-billing-write-issue-refund");
    // Masked at the offending position, so WHERE it differs is visible; never printed verbatim.
    expect(band).toHaveTextContent("·mount");
    expect(band.textContent ?? "").not.toContain(cyrillic);
    expect(within(band).getByTestId("arg-lookalike-billing-write-issue-refund")).toHaveTextContent("U+0430");
    // And it is flagged as unscoped DESPITE the rule pinning the ASCII spelling — which is the truth
    // about what the engine will do.
    expect(within(band).getAllByTestId("unscoped-arg-billing-write-issue-refund")).toHaveLength(1);
    expect(screen.getByTestId("unscoped-args").textContent ?? "").not.toContain(cyrillic);
  });

  it("says the argument list is INCOMPLETE when capture hit its bound", async () => {
    // An operator shown 12 of 400 argument names who believes that is all of them is worse off than
    // one shown none — this is the fail-open class the repo keeps hitting.
    const truncated = {
      ...REFUND_PROPOSAL,
      observed_params: { issue_refund: { keys: ["amount"], truncated: true } }
    };
    vi.spyOn(client, "apiSend").mockResolvedValue(truncated as never);
    const user = userEvent.setup();
    renderPage();
    await user.type(screen.getByLabelText("Agent class"), "billing-bot");
    await user.click(screen.getByRole("button", { name: /propose intent/i }));

    const note = await screen.findByTestId("observed-args-billing-write-issue-refund-truncated-issue_refund");
    expect(note).toHaveTextContent(/cut short at the capture bound/i);
    expect(note).toHaveTextContent(/has NOT been ruled out/i);
  });

  it("states that a keys-only proposal can check PRESENCE and not value", async () => {
    vi.spyOn(client, "apiSend").mockResolvedValue(REFUND_PROPOSAL as never);
    const user = userEvent.setup();
    renderPage();
    await user.type(screen.getByLabelText("Agent class"), "billing-bot");
    await user.click(screen.getByRole("button", { name: /propose intent/i }));

    const band = await screen.findByTestId("params-keys");
    expect(band).toHaveTextContent(/argument .*names.* only/i);
    expect(band).toHaveTextContent(/present/i);
    // "keys" is NOT "nothing": the tool-names-only warning would understate what was captured, and
    // its advice ("supply sample calls") is the wrong next step here.
    expect(screen.queryByTestId("params-warning")).toBeNull();
  });
});

// ------------------------------------------------------------------------------------------------
// The three-state read itself, at the seam where a response can lie or be older than the field.
// ------------------------------------------------------------------------------------------------
describe("reading the capture state fails closed", () => {
  it("keeps params_available meaning exactly what it meant, for a response with no params_detail", () => {
    expect(paramsDetailOf({ params_available: true })).toBe("masked");
    expect(paramsDetailOf({ params_available: false })).toBe("none");
  });

  it("believes the WEAKER half of a self-contradicting response", () => {
    // `params_available: false` says masked values were not recorded. A `masked` detail beside it has
    // already been contradicted by its own response; reading it as `masked` would put a value-level
    // claim on screen for a capture that never happened.
    expect(paramsDetailOf({ params_available: false, params_detail: "masked" })).toBe("keys");
    expect(paramsDetailOf({ params_available: true, params_detail: "none" })).toBe("none");
    expect(paramsDetailOf({ params_available: false, params_detail: "keys" })).toBe("keys");
  });

  it("treats a params_detail it does not recognise as UNVERIFIED, and says so in those words", async () => {
    // The value-level read is unchanged and still fails closed: an unrecognised rung yields no claim
    // stronger than `none`.
    expect(paramsDetailOf({ params_available: true, params_detail: "full" })).toBe("none");
    expect(paramsDetailOf(null)).toBe("none");

    // ASSERTIONS REWRITTEN during verification, because the behaviour they pinned was itself an
    // instance of the defect this work exists to close. This test previously required the screen to
    // render `params-warning` — the band whose words are "No call arguments were recorded for this
    // class" and "Nothing was captured". Against a server one version newer than this console, that
    // is a definite false statement about a response that said the opposite, and it HID the argument
    // names the response actually carried, retiring the flag that is this feature's whole deliverable.
    // "Unknown" and "nothing" must not be spelled the same way. The fail-closed property the old name
    // claimed is kept and strengthened below: no value-level claim, and the loud band still fires.
    vi.spyOn(client, "apiSend").mockResolvedValue({
      ...REFUND_PROPOSAL,
      params_available: true,
      params_detail: "full"
    } as never);
    const user = userEvent.setup();
    renderPage();
    await user.type(screen.getByLabelText("Agent class"), "billing-bot");
    await user.click(screen.getByRole("button", { name: /propose intent/i }));

    const band = await screen.findByTestId("params-unrecognised");
    expect(band).toHaveTextContent(/does not know how to read/i);
    expect(band).toHaveTextContent(/unverified/i);
    // Not the "nothing was captured" band, and not the "values are present" one either.
    expect(screen.queryByTestId("params-warning")).toBeNull();
    expect(screen.queryByTestId("params-keys")).toBeNull();
    // The names the response DID send are still shown — hiding evidence is not a safe default.
    expect(screen.getByTestId("unscoped-args")).toHaveTextContent("amount");
  });

  it("distinguishes an unreported argument map from a reported empty one", () => {
    expect(readObservedParams({ sampled: 1 }).present).toBe(false);
    const reported = readObservedParams({ observed_params: {} });
    expect(reported.present).toBe(true);
    expect(reported.byTool.size).toBe(0);
    // An entry it cannot parse is left ABSENT, so the tool renders as "not reported" — never as a
    // positive claim that the tool carried nothing.
    const junk = readObservedParams({ observed_params: { issue_refund: 7 } });
    expect(junk.present).toBe(true);
    expect(junk.byTool.has("issue_refund")).toBe(false);
  });

  it("reports a key-set it had to filter as TRUNCATED rather than silently shortening it", () => {
    const { byTool } = readObservedParams({ observed_params: { issue_refund: ["amount", 7, null] } });
    expect(byTool.get("issue_refund")?.keys).toEqual(["amount"]);
    expect(byTool.get("issue_refund")?.truncated).toBe(true);
  });

  it("compares argument paths verbatim, because that is how the engine compares them", () => {
    const rule = {
      id: "r",
      match: { tool_name: "issue_refund" },
      require: { "param_paths.amount": { matches: "^\\d+$" } }
    };
    const byTool = readObservedParams({
      observed_params: { issue_refund: ["amount", "аmount", "filters.ids[0]"] }
    }).byTool;
    // `amount` is scoped and drops out. The Cyrillic-а spelling is a DIFFERENT path and stays, which
    // is exactly what the engine will do with it.
    expect(unscopedArgs(rule, byTool).map((a) => a.name)).toEqual(["filters.ids[0]", "аmount"]);
  });
});

// ------------------------------------------------------------------------------------------------
// VERIFICATION PASS — fixtures taken from the SHAPE THE SERVER ACTUALLY EMITS.
//
// Every fixture below mirrors `_ToolEvidence.as_dict()` in norviq/api/routers/intents.py exactly:
//
//   {"detail": "none"|"keys"|"masked", "keys": [...], "pinnable": [...], "ambiguous": [...],
//    "calls": N, "truncated": bool, "dropped": N}
//
// This matters more than it looks. The tests above this line feed BARE LISTS and OMITTED ENTRIES —
// two shapes the API never produces. The server always emits an entry for every tool it saw, always
// as an object, and it carries `detail` PER TOOL precisely so the console can tell "captured, and
// there were none" from "nothing was captured". A fixture that cannot produce the state its test
// name claims proves nothing about the running product.
// ------------------------------------------------------------------------------------------------

/** One tool's evidence, in the server's own shape. */
function toolEvidence(over: Record<string, unknown> = {}) {
  return {
    detail: "keys",
    keys: [] as unknown[],
    pinnable: [] as unknown[],
    ambiguous: [] as unknown[],
    calls: 3,
    truncated: false,
    dropped: 0,
    ...over
  };
}

function refundProposal(over: Record<string, unknown> = {}) {
  return {
    intent: {
      name: "billing-bot-intent",
      class: "billing-bot",
      call: [
        {
          id: "billing-write-issue-refund",
          match: { verb: "write", tool_name: { in: ["issue_refund"] } },
          require: { data_classes: { noneOf: ["secret"] } }
        }
      ]
    },
    sampled: 12,
    params_available: false,
    params_detail: "keys",
    observed_params_truncated: false,
    ...over
  };
}

async function proposeBilling(user: ReturnType<typeof userEvent.setup>) {
  await user.type(screen.getByLabelText("Agent class"), "billing-bot");
  await user.click(screen.getByRole("button", { name: /propose intent/i }));
}

describe("the server's own per-tool capture state reaches the screen", () => {
  beforeEach(() => {
    clearApiCache();
    vi.restoreAllMocks();
  });

  it("does not tell the operator a tool carried no arguments when nothing was captured for it", async () => {
    // The realistic mixed sample: argument-name capture was switched on recently, so `issue_refund`
    // has rows carrying `param_keys` and `list_matters` only has rows written before it existed. The
    // server reports that faithfully — `detail: "none"` with an empty key list — and its own comment
    // says rendering that the same way as `detail: "keys", keys: []` is this project's recurring
    // defect. An operator told "list_matters carried no arguments at all across the 12 sampled calls"
    // concludes there is nothing there to constrain. Nobody looked.
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        intent: {
          name: "billing-bot-intent",
          class: "billing-bot",
          call: [
            {
              id: "billing-mixed",
              match: { verb: "write", tool_name: { in: ["issue_refund", "list_matters"] } },
              require: {}
            }
          ]
        },
        observed_params: {
          issue_refund: toolEvidence({ detail: "keys", keys: ["amount", "txn_id"] }),
          list_matters: toolEvidence({ detail: "none", keys: [], calls: 4 })
        }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const band = await screen.findByTestId("observed-args-billing-mixed");
    const notCaptured = within(band).getByTestId("observed-args-billing-mixed-unknown-list_matters");
    expect(notCaptured).toHaveTextContent(/no argument names were recorded/i);
    expect(notCaptured).toHaveTextContent(/not evidence it takes none/i);
    // The false sentence must appear nowhere for this tool.
    expect(band.textContent ?? "").not.toMatch(/list_matters[^]*carried\s*no arguments at all/);
    expect(within(band).queryByTestId("observed-args-billing-mixed-empty-list_matters")).toBeNull();
  });

  it("still says 'captured, and carried none' when the server says exactly that", async () => {
    // The other half: `detail: "keys"` with an empty key list IS a positive observation, and must not
    // be softened into "we do not know" — that would spell a real answer as unknown.
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        observed_params: { issue_refund: toolEvidence({ detail: "keys", keys: [] }) }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const empty = await screen.findByTestId("observed-args-billing-write-issue-refund-empty-issue_refund");
    expect(empty).toHaveTextContent(/carried\s*no arguments at all/i);
  });

  it("does not call a bare presence check a constraint on the argument's value", async () => {
    // `_add_existence_predicates` writes exactly `require["param_paths.amount"] = {"matches": ".*"}`
    // — an ANY-VALUE predicate. It asserts the argument was PRESENT and nothing whatsoever about what
    // it contained. Reporting that as "this rule constrains it" retires the only flag the operator
    // had, for a rule that still allows `amount: 999999`. Weak must not be spelled like compliant.
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        intent: {
          name: "billing-bot-intent",
          class: "billing-bot",
          call: [
            {
              id: "billing-write-issue-refund",
              match: { verb: "write", tool_name: { in: ["issue_refund"] } },
              require: { "param_paths.amount": { matches: ".*" } }
            }
          ]
        },
        observed_params: { issue_refund: toolEvidence({ detail: "keys", keys: ["amount"] }) }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const band = await screen.findByTestId("observed-args-billing-write-issue-refund");
    expect(band).toHaveTextContent(/present, not what it contains/i);
    expect(band.textContent ?? "").not.toMatch(/this rule constrains its value/);
  });

  it("warns that a path the engine flagged AMBIGUOUS cannot be pinned by a clause", async () => {
    // The server ships `ambiguous` for exactly one reason, in its own words: "Names a caller can MINT
    // ... whichever the caller ordered last wins. A rule pinned on one of these is a trap, so they
    // are shown and never asserted." Shown identically to a safe name, with "add a clause for the
    // ones that matter" underneath, the console walks the operator into that trap.
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        params_available: true,
        params_detail: "masked",
        observed_params: {
          issue_refund: toolEvidence({
            detail: "masked",
            keys: ["filters.id", "txn_id"],
            pinnable: ["txn_id"],
            ambiguous: ["filters.id"]
          })
        }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const band = await screen.findByTestId("observed-args-billing-write-issue-refund");
    const note = within(band).getByTestId("arg-ambiguous-billing-write-issue-refund");
    expect(note).toHaveTextContent(/filters\.id/);
    expect(note).toHaveTextContent(/caller/i);
    // ...and it must not ALSO be reported under the unpinnable note, whose reason ("a numeric or
    // structured value has no string the engine can test") is false for it. The API excludes an
    // ambiguous path from `pinnable` by construction, so the two notes overlap unless one defers.
    // `filters.id` is a usable string path; it is unusable because a caller can mint it.
    const wrongReason = within(band).queryByTestId("arg-unpinnable-billing-write-issue-refund");
    expect(wrongReason?.textContent ?? "").not.toContain("filters.id");
  });

  it("says a value clause cannot hold on an argument the engine never derived", async () => {
    // The literal fintech payload: {"txn_id": "TXN-8891", "amount": 25.0}. Values WERE captured, so
    // the engine's own derivation is authoritative here — and `param_paths` carries string leaves
    // only, so `amount` is observed and NOT pinnable. A `param_paths.amount` clause can never be
    // satisfied; under `default decision = "block"` the rule then matches nothing and every refund is
    // refused. "Add a clause for the ones that matter" is, for this exact argument, an outage.
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        params_available: true,
        params_detail: "masked",
        observed_params: {
          issue_refund: toolEvidence({
            detail: "masked",
            keys: ["amount", "txn_id"],
            pinnable: ["txn_id"],
            calls: 12
          })
        }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const band = await screen.findByTestId("observed-args-billing-write-issue-refund");
    expect(within(band).getAllByTestId("unscoped-arg-billing-write-issue-refund").length).toBeGreaterThan(0);
    const note = within(band).getByTestId("arg-unpinnable-billing-write-issue-refund");
    expect(note).toHaveTextContent(/amount/);
    expect(note).toHaveTextContent(/never match/i);
  });

  it("flags the unconstrainable argument on a DEFAULT install, not only a masked one", async () => {
    // The regression this pins: the note was briefly gated on `detail === "masked"`, so it could only
    // fire on an install that had opted into storing values. Every persona who hit this ran a default
    // install — `params_available: false`, `detail: "keys"` — which is the one configuration where the
    // note was silent. Pinnability is a fact about the leaf TYPE, and the capture knows `amount` was a
    // number without storing the 25.0, so "keys" answers it exactly as well as "masked".
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        params_available: false,
        params_detail: "keys",
        observed_params: {
          issue_refund: toolEvidence({
            detail: "keys",
            keys: ["amount", "txn_id"],
            pinnable: ["txn_id"],
            calls: 3
          })
        }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const band = await screen.findByTestId("observed-args-billing-write-issue-refund");
    const note = within(band).getByTestId("arg-unpinnable-billing-write-issue-refund");
    expect(note).toHaveTextContent(/amount/);
    expect(note).toHaveTextContent(/never match/i);
    // `txn_id` IS pinnable, so it must not be swept into the same warning.
    expect(note).not.toHaveTextContent(/txn_id/);
  });

  it("cannot render two different argument names as the same visible text", async () => {
    // `" amount"` is plain ASCII, so `lookalikeOf` says nothing about it — and HTML collapses the
    // leading space, so it prints as `amount`. Beside a genuinely scoped `amount` the operator reads
    // the same six characters twice, once constrained and once "Not in this rule", and concludes the
    // flag is a duplicate-render bug. The name the traffic actually carried stays unconstrained.
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        intent: {
          name: "billing-bot-intent",
          class: "billing-bot",
          call: [
            {
              id: "billing-write-issue-refund",
              match: { verb: "write", tool_name: { in: ["issue_refund"] } },
              require: { "param_paths.amount": { matches: "^[0-9]+$" } }
            }
          ]
        },
        observed_params: { issue_refund: toolEvidence({ detail: "keys", keys: ["amount", " amount"] }) }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    // Scoped to the CARRIED list, not the whole band. One name legitimately appears more than once
    // across the band — the unpinnable note names the same argument again to explain why it cannot be
    // constrained — so a band-wide uniqueness check asserts the layout rather than the property. The
    // property is that two DIFFERENT names never look like one, and that is a claim about this list.
    await screen.findByTestId("observed-args-billing-write-issue-refund");
    const carried = screen.getByTestId("arg-carried-billing-write-issue-refund");
    // Compared AS THE BROWSER WOULD SHOW THEM, not as the DOM stores them. jsdom keeps the leading
    // space in `textContent` whatever the CSS says, so asserting on raw `textContent` would pass
    // against a screen that renders the two names identically — the exact defect. Collapsing runs of
    // whitespace the way HTML does is what makes this assertion mean anything.
    const asShown = within(carried)
      .getAllByTestId("arg-name")
      .map((r) => (r.textContent ?? "").replace(/\s+/g, " ").trim());
    expect(asShown).toHaveLength(2);
    expect(new Set(asShown).size).toBe(asShown.length);
  });

  it("never prints a control character from an argument name into the document", async () => {
    // ESC and friends are not decorative: `builderCompile.ts` already carries a scar from a control
    // character escaping a generated policy's header comment. The server drops these, but the console
    // reads whatever the wire hands it and must not depend on a filter it does not own.
    const evil = "txn\u001B[31mid";
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        observed_params: { issue_refund: toolEvidence({ detail: "keys", keys: ["amount", evil] }) }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const band = await screen.findByTestId("observed-args-billing-write-issue-refund");
    expect(band.textContent ?? "").not.toContain("\u001B");
  });

  it("prints the headline count as a FLOOR when the key-set behind it was cut short", async () => {
    // The per-tool list already says it was cut short. The headline above it did not: "2 arguments in
    // traffic that no rule mentions" reads as the total, so an operator who writes clauses for both
    // believes they are finished. Two of four hundred, reported as two, is the failure this project
    // keeps hitting — restated one level up from where it was already fixed.
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        observed_params: {
          issue_refund: toolEvidence({ detail: "keys", keys: ["amount", "txn_id"], truncated: true })
        }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const summary = await screen.findByTestId("unscoped-args");
    expect(summary).toHaveTextContent(/at least 2 arguments in traffic that no rule mentions/i);
    expect(summary).toHaveTextContent(/this count is a floor/i);
  });

  it("does not call the count a floor when nothing was cut short", async () => {
    // The other half — a hedge on every proposal is a hedge nobody reads.
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        observed_params: { issue_refund: toolEvidence({ detail: "keys", keys: ["amount", "txn_id"] }) }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const summary = await screen.findByTestId("unscoped-args");
    expect(summary).toHaveTextContent(/^2 arguments in traffic that no rule mentions/i);
    expect(summary.textContent ?? "").not.toMatch(/at least|floor/i);
  });

  it("renders nothing from the response except argument NAMES, and says so when it dropped some", async () => {
    // The field is specified as keys-only, so this screen must be unable to print a value even if one
    // arrives — through a sibling field, through a nested object smuggled into the key list, or
    // through a non-string entry. Every one of those is dropped, and every drop makes the list
    // INCOMPLETE, because a silently shortened list read as complete is the fail-open this exists to
    // close. The enormous name is bounded here too: `_MAX_PATH_KEY_LEN` is 256, and a name longer
    // than that was never derived under that spelling by the engine anyway.
    const huge = "z".repeat(5000);
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        observed_params: {
          issue_refund: {
            detail: "keys",
            keys: ["amount", "", 7, null, { nested: "TXN-8891" }, ["a"], huge],
            pinnable: [],
            ambiguous: [],
            calls: 12,
            truncated: false,
            dropped: 0,
            // Value-bearing siblings. Nothing reads these; the assertion below is what holds it.
            masked_params: { amount: "25.0", txn_id: "TXN-8891" },
            samples: [{ amount: 25.0 }]
          }
        }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const band = await screen.findByTestId("observed-args-billing-write-issue-refund");
    const text = band.textContent ?? "";
    expect(text).toContain("amount");
    for (const value of ["TXN-8891", "25.0", "nested"]) expect(text).not.toContain(value);
    // Entries it could not read are names the operator will not be shown — stated, not swallowed.
    expect(within(band).getByTestId("observed-args-billing-write-issue-refund-truncated-issue_refund"))
      .toHaveTextContent(/cut short at the capture bound/i);
    // The oversized name is bounded AND still distinguishable, by its true length.
    expect(text).not.toContain(huge);
    expect(text).toContain("(5000 characters)");
  });

  it("cannot let one argument name impersonate a list of two in the summary band", async () => {
    // A JSON key may contain a comma. The summary joins flagged names with ", ", so a single argument
    // literally named `amount, txn_id` reads there as two arguments — and an operator who adds
    // `param_paths.amount` and `param_paths.txn_id` has constrained neither.
    vi.spyOn(client, "apiSend").mockResolvedValue(
      refundProposal({
        observed_params: { issue_refund: toolEvidence({ detail: "keys", keys: ["amount, txn_id"] }) }
      }) as never
    );
    const user = userEvent.setup();
    renderPage();
    await proposeBilling(user);

    const summary = await screen.findByTestId("unscoped-args");
    expect(summary).toHaveTextContent(/1 argument in traffic that no rule mentions/i);
    // Every name in the band must be delimited, and the comma must sit INSIDE the delimiters, so it
    // cannot read as the separator this band uses between names.
    const names = within(summary)
      .getAllByTestId("arg-name")
      .map((n) => n.textContent ?? "");
    expect(names.every((n) => /^“[^]*”$/.test(n))).toBe(true);
    expect(names).toContain("“amount, txn_id”");
  });
});
