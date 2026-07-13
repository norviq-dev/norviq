// SPDX-License-Identifier: Apache-2.0
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { apiGet, fetchAllAgents, fetchSearch, logout } from "./client";

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

  it("AUTH-01: revokes the session server-side (POST /auth/logout with bearer) BEFORE clearing", async () => {
    localStorage.setItem("nrvq_token", "tok");
    Object.defineProperty(window, "location", {
      value: { href: "http://localhost/agents" },
      writable: true,
      configurable: true
    });
    const f = mockFetch();
    logout();
    expect(f).toHaveBeenCalledTimes(1); // fired synchronously, while the token still exists
    const [url, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain("/api/v1/auth/logout");
    expect(init.method).toBe("POST");
    expect(authHeaderOf(f.mock.calls[0])).toBe("Bearer tok");
    await vi.waitFor(() => expect(localStorage.getItem("nrvq_token")).toBeNull());
    expect(window.location.href).toBe("/");
  });

  it("AUTH-01: a dead API never traps logout — still clears + redirects on fetch failure", async () => {
    localStorage.setItem("nrvq_token", "tok");
    Object.defineProperty(window, "location", {
      value: { href: "http://localhost/agents" },
      writable: true,
      configurable: true
    });
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new Error("api down"))));
    logout();
    await vi.waitFor(() => expect(localStorage.getItem("nrvq_token")).toBeNull());
    expect(window.location.href).toBe("/");
  });

  it("clears and redirects immediately when no token is stored (nothing to revoke)", () => {
    Object.defineProperty(window, "location", {
      value: { href: "http://localhost/agents" },
      writable: true,
      configurable: true
    });
    const f = mockFetch();
    logout();
    expect(f).not.toHaveBeenCalled();
    expect(window.location.href).toBe("/");
  });
});

describe("fetchSearch — P2-2 scoped ⌘K search", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("makes ONE call to /api/v1/search (replaces the 3-endpoint fan-out) with the bearer token", async () => {
    localStorage.setItem("nrvq_token", "tok");
    const f = vi.fn(
      async () =>
        new Response(JSON.stringify({ tools: [], agents: [], policies: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        })
    );
    vi.stubGlobal("fetch", f);
    const res = await fetchSearch("refund");
    expect(f).toHaveBeenCalledTimes(1);
    const [url] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain("/api/v1/search?q=refund");
    expect(authHeaderOf(f.mock.calls[0] as unknown[])).toBe("Bearer tok");
    expect(res).toEqual({ tools: [], agents: [], policies: [] });
  });

  it("url-encodes the query (a '%' must not become a wildcard or break the URL)", async () => {
    const f = mockFetch();
    await fetchSearch("100% off").catch(() => undefined);
    const [url] = f.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toContain("q=100%25%20off");
  });
});
