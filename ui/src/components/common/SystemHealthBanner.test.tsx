// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The banner exists because a Norviq failure is otherwise SILENT: sidecars fail closed, every agent's
// tool calls stop working, and the console still looks perfectly healthy. These tests pin the two
// properties that make it trustworthy — it shows a real incident, and it stays quiet otherwise.

import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HttpResponse, http } from "msw";
import { setupServer } from "msw/node";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { SystemHealthBanner } from "./SystemHealthBanner";

const OUTAGE = {
  status: "degraded",
  window_minutes: 15,
  issues: [
    {
      id: "thin_proxy_fail_closed",
      severity: "critical",
      title: "Agents are being blocked by an engine outage",
      detail: "The policy engine is unreachable, so governed tool calls are failing closed.",
      remediation: "Check norviq-api and norviq-engine pods.",
      affected_calls: 42,
      namespaces: ["chatbot-prod"],
      last_seen: "2026-07-26T10:00:00Z",
      window_minutes: 15,
    },
  ],
};

const server = setupServer();
beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

const serve = (body: unknown, status = 200) =>
  server.use(http.get("/api/v1/system-health", () => HttpResponse.json(body as object, { status })));

describe("SystemHealthBanner", () => {
  it("renders nothing while the system is healthy", async () => {
    serve({ status: "ok", issues: [], window_minutes: 15 });
    render(<SystemHealthBanner />);
    // Give the fetch a chance to resolve before asserting absence.
    await waitFor(() => expect(screen.queryByTestId("system-health-banner")).not.toBeInTheDocument());
  });

  it("surfaces an ongoing enforcement outage with its evidence and remediation", async () => {
    serve(OUTAGE);
    render(<SystemHealthBanner />);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
    expect(screen.getByText(/blocked by an engine outage/i)).toBeInTheDocument();
    // The evidence is what makes it actionable rather than alarming.
    expect(screen.getByText(/42/)).toBeInTheDocument();
    expect(screen.getByText(/chatbot-prod/)).toBeInTheDocument();
    expect(screen.getByText(/norviq-api and norviq-engine/i)).toBeInTheDocument();
  });

  it("names ungoverned traffic explicitly when the posture is fail-open", async () => {
    serve({
      status: "degraded",
      window_minutes: 15,
      issues: [{ ...OUTAGE.issues[0], id: "thin_proxy_fail_open", title: "Tool calls are running UNGOVERNED" }],
    });
    render(<SystemHealthBanner />);
    // The quietest failure mode of all — nothing breaks, nothing is enforced.
    expect(await screen.findByText(/UNGOVERNED/)).toBeInTheDocument();
  });

  it("stays silent when health cannot be fetched", async () => {
    serve({ detail: "unauthorized" }, 401);
    render(<SystemHealthBanner />);
    // A failed FETCH is not evidence of an incident (unauthenticated console, mid-reload). Crying wolf
    // on every transient blip would train operators to ignore the banner that matters.
    await waitFor(() => expect(screen.queryByTestId("system-health-banner")).not.toBeInTheDocument());
  });

  it("can be dismissed", async () => {
    serve(OUTAGE);
    render(<SystemHealthBanner />);
    await userEvent.click(await screen.findByRole("button", { name: /dismiss/i }));
    expect(screen.queryByTestId("system-health-banner")).not.toBeInTheDocument();
  });

  it("re-raises a dismissed issue when it happens again", async () => {
    serve(OUTAGE);
    const { rerender } = render(<SystemHealthBanner />);
    await userEvent.click(await screen.findByRole("button", { name: /dismiss/i }));
    expect(screen.queryByTestId("system-health-banner")).not.toBeInTheDocument();

    // A NEW occurrence carries a new last_seen. Dismissal is keyed to the occurrence, not the issue
    // class — a permanently silenced enforcement outage is the failure this component exists to prevent.
    serve({
      ...OUTAGE,
      issues: [{ ...OUTAGE.issues[0], last_seen: "2026-07-26T10:30:00Z" }],
    });
    rerender(<SystemHealthBanner key="second" />);
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
