// SPDX-License-Identifier: Apache-2.0
// B1-1: a mutation-triggered read must ALWAYS reflect the new state — the same-page consumer via refetch() (force),
// and every OTHER consumer (a remount, or a different page under its own cacheKey) because the mutation drops the
// stale cache entry. These tests pin both halves.
import { renderHook, waitFor, act } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { useApi, clearApiCache, peekApiCache, invalidateApiCache } from "./useApi";

afterEach(() => clearApiCache());

describe("useApi refetch + cache invalidation (B1-1)", () => {
  it("refetch() fetches FRESH within staleTimeMs (force skips the cache) and applies the latest value", async () => {
    let current = "v1";
    const { result } = renderHook(() =>
      useApi(() => Promise.resolve(current), [], { cacheKey: "k", staleTimeMs: 60_000 })
    );
    await waitFor(() => expect(result.current.data).toBe("v1"));
    // a mutation changed the server value; a refetch within the (huge) staleTime must still get v2, not stale v1.
    current = "v2";
    await act(async () => {
      await result.current.refetch();
    });
    expect(result.current.data).toBe("v2");
  });

  it("FAIL-ON-BUG: a NON-forced remount within staleTimeMs serves the STALE cache UNLESS invalidateApiCache ran", async () => {
    let current = "v1";
    // 1) first consumer populates the cache with v1
    const first = renderHook(() =>
      useApi(() => Promise.resolve(current), [], { cacheKey: "shared", staleTimeMs: 60_000 })
    );
    await waitFor(() => expect(first.result.current.data).toBe("v1"));
    expect(peekApiCache("shared")).toBe("v1");

    // 2) a mutation changes the server value. WITHOUT invalidation, a fresh consumer (remount / other page) mounting
    //    within staleTime reads the stale cached v1 — this is the cross-page "chip didn't update" bug.
    current = "v2";
    const staleMount = renderHook(() =>
      useApi(() => Promise.resolve(current), [], { cacheKey: "shared", staleTimeMs: 60_000 })
    );
    await waitFor(() => expect(staleMount.result.current.loading).toBe(false));
    expect(staleMount.result.current.data).toBe("v1"); // proves the stale-serve exists (the bug the fix targets)

    // 3) the fix: after a mutation, invalidateApiCache drops the entry, so the NEXT mount fetches fresh v2.
    invalidateApiCache("shar");
    expect(peekApiCache("shared")).toBeUndefined();
    const freshMount = renderHook(() =>
      useApi(() => Promise.resolve(current), [], { cacheKey: "shared", staleTimeMs: 60_000 })
    );
    await waitFor(() => expect(freshMount.result.current.data).toBe("v2"));
  });

  it("invalidateApiCache(prefix) drops only matching keys", async () => {
    const a = renderHook(() => useApi(() => Promise.resolve("A"), [], { cacheKey: "policy-packs:default", staleTimeMs: 60_000 }));
    const b = renderHook(() => useApi(() => Promise.resolve("B"), [], { cacheKey: "audit:default", staleTimeMs: 60_000 }));
    await waitFor(() => expect(a.result.current.data).toBe("A"));
    await waitFor(() => expect(b.result.current.data).toBe("B"));
    invalidateApiCache("policy-packs:");
    expect(peekApiCache("policy-packs:default")).toBeUndefined(); // busted
    expect(peekApiCache("audit:default")).toBe("B");             // untouched — other 36 sites unaffected
  });
});
