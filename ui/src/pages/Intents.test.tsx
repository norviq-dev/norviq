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
import { Intents } from "./Intents";
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
