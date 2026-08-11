// SPDX-License-Identifier: Apache-2.0
//
// Tests for the tool-verb classification panel. This component had NO tests, and shipped a
// fail-open: at the console's default "All namespaces" scope it POSTed the literal string "all" as
// the namespace, then reported success.
//
// Why that is a fail-open and not cosmetics. A promoted verb is stored per (namespace, tool_name)
// and the evaluator reads it back with the REQUEST's namespace, so a row written under
// namespace='all' is never consulted: `input.derived.verb` still resolves to unknown in the tool's
// real namespace, and a policy shaped `block when derived.verb == "delete"` never fires. Meanwhile
// the console moved the row to LEARNED with a green "✓ learned" chip — asserting a classification
// that does not exist — and the audit line under it read "all · promoted by admin · evidence:
// promoted without observed evidence", the 42 evidenced calls it had just displayed now gone
// (the evidence lookup is `namespace = ANY(:nss)` with nss=["all"], which matches nothing).
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { ToolVerbsPanel } from "./ToolVerbsPanel";

const server = setupServer();
beforeAll(() => server.listen());
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const CANDIDATE = {
  tool_name: "warehouse_task", calls: 42,
  verbs: { delete: 30, read: 12 },
  inferred_verb: "delete", inferred_count: 30, suggested_risk: "critical"
};

/** `namespaces` is what the server resolved the scope to. An admin asking for ns=all gets []
 *  (graphs.py `_resolve_namespaces` returns None → threats.py emits `namespaces or []`). */
function verbsHandler(namespaces: string[], promoted: unknown[] = []) {
  return http.get("/api/v1/threats/tool-verbs", () =>
    HttpResponse.json({ namespaces, overrides: promoted, candidates: [CANDIDATE] })
  );
}

function renderPanel(ns: string) {
  return render(<ToolVerbsPanel ns={ns} isAdmin onClose={() => {}} onChanged={() => {}} />);
}

describe("ToolVerbsPanel — a promotion always names one real namespace", () => {
  // Deliberately split from the disabled-state test below: the two are independent failures. One is
  // "the operator cannot tell why nothing happens"; this one is the fail-open itself.
  it("sends NOTHING to the server when the scope names no namespace", async () => {
    const posted: unknown[] = [];
    server.use(
      verbsHandler([]),
      http.post("/api/v1/threats/tool-verbs/promote", async ({ request }) => {
        posted.push(await request.json());
        return HttpResponse.json({ promoted: true, verb: "delete", risk: "critical" });
      })
    );
    renderPanel("all");
    await screen.findByTestId("toolverb-candidate");

    // Pre-fix this POSTed {"ns":"all","tool_name":"warehouse_task","verb":"delete"} and reported
    // success — a learned verb filed under a namespace no request will ever carry.
    fireEvent.click(within(screen.getByTestId("toolverb-promote-warehouse_task")).getByRole("button", { name: /^delete/i }));
    await waitFor(() => expect(screen.getByTestId("toolverb-candidate")).toBeInTheDocument());
    expect(posted).toEqual([]);
  });

  it("disables promotion at 'All namespaces' and says why, in visible text", async () => {
    server.use(verbsHandler([]));
    renderPanel("all");
    await screen.findByTestId("toolverb-candidate");

    const group = screen.getByTestId("toolverb-promote-warehouse_task");
    expect(within(group).getByRole("button", { name: /^delete/i })).toBeDisabled();

    // `.btn:disabled { pointer-events: none }` in this codebase means a title on a disabled control
    // can never be read — the reason has to be text on the page.
    const reason = screen.getByTestId("toolverb-promote-warehouse_task-reason");
    expect(reason).toHaveTextContent(/pick a single namespace/i);
    expect(reason).toHaveTextContent(/per namespace/i);
  });

  it("promotes into the concrete namespace when the console is scoped to one", async () => {
    let body: { ns?: string; tool_name?: string; verb?: string } | null = null;
    server.use(
      verbsHandler(["studioai"]),
      http.post("/api/v1/threats/tool-verbs/promote", async ({ request }) => {
        body = (await request.json()) as typeof body;
        return HttpResponse.json({ promoted: true, verb: "delete", risk: "critical" });
      })
    );
    renderPanel("studioai");
    await screen.findByTestId("toolverb-candidate");

    const group = screen.getByTestId("toolverb-promote-warehouse_task");
    // The destination is stated on the control itself, not left to be inferred.
    expect(group).toHaveTextContent(/promote in\s*studioai\s*as/i);
    const del = within(group).getByRole("button", { name: /^delete/i });
    expect(del).toBeEnabled();
    fireEvent.click(del);

    await waitFor(() => expect(body).toMatchObject({ ns: "studioai", tool_name: "warehouse_task", verb: "delete" }));
  });

  it("resolves 'all' to the single namespace the server scoped it to", async () => {
    // A viewer restricted to one namespace asks for "all"; the server answers with that one. That IS
    // a concrete scope, so promoting into it is honest.
    let body: { ns?: string } | null = null;
    server.use(
      verbsHandler(["payments"]),
      http.post("/api/v1/threats/tool-verbs/promote", async ({ request }) => {
        body = (await request.json()) as typeof body;
        return HttpResponse.json({ promoted: true, verb: "delete", risk: "critical" });
      })
    );
    renderPanel("all");
    await screen.findByTestId("toolverb-candidate");
    fireEvent.click(within(screen.getByTestId("toolverb-promote-warehouse_task")).getByRole("button", { name: /^delete/i }));
    await waitFor(() => expect(body).toMatchObject({ ns: "payments" }));
  });

  it("stays disabled when the scope resolves to SEVERAL namespaces — a candidate names none", async () => {
    server.use(verbsHandler(["payments", "hr"]));
    renderPanel("all");
    await screen.findByTestId("toolverb-candidate");
    expect(within(screen.getByTestId("toolverb-promote-warehouse_task")).getByRole("button", { name: /^delete/i })).toBeDisabled();
    expect(screen.getByTestId("toolverb-promote-warehouse_task-reason")).toBeInTheDocument();
  });
});

describe("ToolVerbsPanel — the lifecycle copy matches what promotion does", () => {
  it("does not claim a promoted verb classifies the tool 'everywhere'", async () => {
    server.use(verbsHandler(["studioai"]));
    renderPanel("studioai");
    await screen.findByTestId("toolverb-candidate");
    // The override is keyed on (namespace, tool_name) and read with the request's own namespace, so
    // "everywhere" was a claim the code underneath never delivered.
    expect(screen.queryByText(/classifies the tool everywhere/i)).not.toBeInTheDocument();
    expect(screen.getByText(/it then classifies the tool/i)).toHaveTextContent(/studioai/);
  });

  it("still shows the observed evidence that justifies the promotion", async () => {
    server.use(verbsHandler(["studioai"]));
    renderPanel("studioai");
    const row = await screen.findByTestId("toolverb-candidate");
    expect(row).toHaveTextContent(/42 evidenced calls/i);
    expect(row).toHaveTextContent(/suggests\s*delete/i);
  });
});
