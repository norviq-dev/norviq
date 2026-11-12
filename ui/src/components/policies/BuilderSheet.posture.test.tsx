// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Step 3 of the builder says what saving will do in the TARGET namespace. In a Monitor namespace the
// engine logs every match as a would-block, and the step used to offer "Save & enforce" with no note.

import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { BuilderSheet } from "./BuilderSheet";
import { clearApiCache } from "../../hooks/useApi";

vi.mock("@monaco-editor/react", () => ({
  default: ({ value }: { value?: string }) => <div data-testid="monaco-editor">{value}</div>
}));

const server = setupServer(http.get("/api/v1/agents", () => HttpResponse.json([])));
beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

function settings(namespace: string, enforcement_mode: string, enforcement_mode_source: string) {
  server.use(
    http.get("/api/v1/settings", () =>
      HttpResponse.json({ namespace, enforcement_mode, enforcement_mode_source, trust_threshold: 0.7, rate_limit: 60 })
    )
  );
}

describe("builder step 3 follows the target namespace posture", () => {
  it("Monitor namespace: notes would-block and does not offer Save & enforce", async () => {
    settings("analytics", "audit", "namespace");
    render(<BuilderSheet namespace="analytics" onClose={() => {}} />);
    expect(await screen.findByTestId("builder-monitor-note")).toHaveTextContent(/logged as would-block/);
    expect(screen.getByTestId("builder-save-btn")).toHaveTextContent("Save (Monitor)");
    expect(screen.queryByText("Save & enforce")).not.toBeInTheDocument();
  });

  it("enforcing namespace: no Monitor note, Save & enforce", async () => {
    settings("payments", "block", "namespace");
    render(<BuilderSheet namespace="payments" onClose={() => {}} />);
    expect(await screen.findByText("Save & enforce")).toBeInTheDocument();
    expect(screen.queryByTestId("builder-monitor-note")).not.toBeInTheDocument();
  });
});

// "Save & enforce" was also the label for an unread posture and for a policy of audit-only rules, which is
// saved in mode "audit" and never blocks (the evaluator's `_apply_policy_mode`).
describe("builder Save label promises enforcement only when it will happen", () => {
  it("unread posture: plain Save", async () => {
    server.use(http.get("/api/v1/settings", () => HttpResponse.json({ detail: "db down" }, { status: 503 })));
    render(<BuilderSheet namespace="payments" onClose={() => {}} />);
    await waitFor(() => expect(screen.getByTestId("builder-save-btn")).toHaveTextContent(/^Save$/));
    expect(screen.queryByText("Save & enforce")).not.toBeInTheDocument();
  });

  it("enforcing namespace, audit-only rules: Save (audit only)", async () => {
    settings("payments", "block", "namespace");
    render(<BuilderSheet namespace="payments" onClose={() => {}} />);
    expect(await screen.findByText("Save & enforce")).toBeInTheDocument();
    fireEvent.change(screen.getByTestId("builder-agent-class"), { target: { value: "builder-spike" } });
    fireEvent.click(screen.getByTestId("builder-add-rule"));
    fireEvent.change(screen.getByTestId("builder-rule-decision-0"), { target: { value: "audit" } });
    await waitFor(() => expect(screen.getByTestId("builder-save-btn")).toHaveTextContent("Save (audit only)"));
  });
});
