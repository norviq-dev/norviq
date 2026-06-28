// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiGet, fetchAllAgents, logout } from "./client";

function mockFetch() {
  const fetchMock = vi.fn(
    async () =>
      new Response(JSON.stringify([]), { status: 200, headers: { "Content-Type": "application/json" } })
  );
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function authHeaderOf(call: unknown[]): string | undefined {
  const init = call[1] as RequestInit | undefined;
  const headers = (init?.headers ?? {}) as Record<string, string>;
  return headers.Authorization;
}

describe("client auth headers (#1)", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("apiGet attaches the bearer token when nrvq_token is set", async () => {
    localStorage.setItem("nrvq_token", "tok123");
    const f = mockFetch();
    await apiGet("/api/v1/agents");
    expect(authHeaderOf(f.mock.calls[0])).toBe("Bearer tok123");
  });

  it("apiGet omits Authorization when no token is set", async () => {
    const f = mockFetch();
    await apiGet("/api/v1/agents");
    expect(authHeaderOf(f.mock.calls[0])).toBeUndefined();
  });

  it("apiGetWithSignal (via fetchAllAgents) attaches the token too", async () => {
    localStorage.setItem("nrvq_token", "tok456");
    const f = mockFetch();
    await fetchAllAgents();
    expect(authHeaderOf(f.mock.calls[0])).toBe("Bearer tok456");
  });

  it("apiGetWithSignal omits Authorization when no token", async () => {
    const f = mockFetch();
    await fetchAllAgents();
    expect(authHeaderOf(f.mock.calls[0])).toBeUndefined();
  });
});

describe("logout (#8)", () => {
  let original: Location;
  beforeEach(() => {
    original = window.location;
  });
  afterEach(() => {
    Object.defineProperty(window, "location", { value: original, writable: true, configurable: true });
    localStorage.clear();
  });

  it("clears nrvq_token and redirects to /", () => {
    localStorage.setItem("nrvq_token", "tok");
    Object.defineProperty(window, "location", {
      value: { href: "http://localhost/agents" },
      writable: true,
      configurable: true
    });
    logout();
    expect(localStorage.getItem("nrvq_token")).toBeNull();
    expect(window.location.href).toBe("/");
  });
});
