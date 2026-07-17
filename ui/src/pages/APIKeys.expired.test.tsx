// SPDX-License-Identifier: Apache-2.0
import type { ReactNode } from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { MemoryRouter } from "react-router-dom";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { APIKeys } from "./APIKeys";
import { clearApiCache } from "../hooks/useApi";

// DEF-041: an expired-not-revoked key is dead server-side (api_keys.authenticate returns None once
// expires_at <= now) yet the pre-fix Status column read it off k.revoked alone → green "Active",
// contradicting the red EXPIRED badge the Expires column shows for the same row. These tests assert
// the two columns agree: an expired key must NOT read "Active" and must NOT expose a Revoke button.

const mockApp = { namespace: "default" };
vi.mock("../store/AppContext", () => ({
  useApp: () => mockApp,
  AppProvider: ({ children }: { children: ReactNode }) => <>{children}</>
}));

const DAY = 24 * 60 * 60 * 1000;
const EXPIRED_KEY = {
  id: "k-expired",
  prefix: "nrvq_ex",
  name: "stale-runner",
  namespace: "default",
  role: "service",
  created_at: new Date(Date.now() - 100 * DAY).toISOString(),
  last_used_at: null,
  revoked: false, // NOT revoked — only expired
  expires_at: new Date(Date.now() - DAY).toISOString() // 1 day in the past
};
const LIVE_KEY = {
  id: "k-live",
  prefix: "nrvq_lv",
  name: "active-runner",
  namespace: "default",
  role: "viewer",
  created_at: new Date(Date.now() - DAY).toISOString(),
  last_used_at: null,
  revoked: false,
  expires_at: new Date(Date.now() + 30 * DAY).toISOString() // future
};

let keysPayload: unknown[] = [];
const server = setupServer(http.get("/api/v1/keys", () => HttpResponse.json(keysPayload)));
beforeAll(() => server.listen());
beforeEach(() => {
  mockApp.namespace = "default";
  keysPayload = [];
});
afterEach(() => {
  server.resetHandlers();
  clearApiCache();
});
afterAll(() => server.close());

function renderPage() {
  return render(
    <MemoryRouter>
      <APIKeys />
    </MemoryRouter>
  );
}

describe("APIKeys — expired-key Status consistency (DEF-041)", () => {
  it("an expired-not-revoked key renders EXPIRED + a non-Active status, never green 'Active'", async () => {
    keysPayload = [EXPIRED_KEY];
    renderPage();

    // The row exists (table rendered).
    const badge = await screen.findByText("EXPIRED");
    expect(badge).toBeInTheDocument();

    // FAIL-ON-BUG: pre-fix the Status cell read "Active" for this expired key.
    expect(screen.queryByText("Active")).toBeNull();

    // Status must be consistent with the EXPIRED badge.
    expect(screen.getByText("Expired")).toBeInTheDocument();
  });

  it("does not offer Revoke on an expired key (already inert server-side)", async () => {
    keysPayload = [EXPIRED_KEY];
    renderPage();

    await screen.findByText("EXPIRED");
    // FAIL-ON-BUG: pre-fix the row still rendered a live Revoke button for the dead key.
    expect(screen.queryByRole("button", { name: /Revoke/i })).toBeNull();
  });

  it("a live (unexpired, unrevoked) key still reads Active and keeps its Revoke button", async () => {
    keysPayload = [LIVE_KEY];
    renderPage();

    const activeCell = await screen.findByText("Active");
    expect(activeCell).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Revoke/i })).toBeInTheDocument();
  });

  it("mixed fleet: only the live key reads Active; the expired one reads Expired in its own row", async () => {
    keysPayload = [EXPIRED_KEY, LIVE_KEY];
    renderPage();

    await waitFor(() => expect(screen.getByText("active-runner")).toBeInTheDocument());

    // Locate each row by its unique key name and assert its Status cell independently.
    const expiredRow = screen.getByText("stale-runner").closest("tr")!;
    const liveRow = screen.getByText("active-runner").closest("tr")!;

    expect(within(expiredRow).getByText("Expired")).toBeInTheDocument();
    expect(within(expiredRow).queryByText("Active")).toBeNull();
    expect(within(expiredRow).queryByRole("button", { name: /Revoke/i })).toBeNull();

    expect(within(liveRow).getByText("Active")).toBeInTheDocument();
    expect(within(liveRow).getByRole("button", { name: /Revoke/i })).toBeInTheDocument();
  });
});
