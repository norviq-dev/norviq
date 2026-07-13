// SPDX-License-Identifier: Apache-2.0
// K1 — the Overview KPI cards went stuck-at-0 because useApi (a) applied whichever response resolved LAST (no
// latest-wins ordering, so a slow warm-up {total:0} clobbered a newer real value) and (b) cached the empty {0} for
// staleTimeMs, short-circuiting later loads. These tests pin the fix: latest-wins + never-cache-empty + bounded
// empty-retry.
import { renderHook, act, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useApi, clearApiCache, peekApiCache } from "./useApi";

afterEach(() => clearApiCache());

/** A loader whose every invocation returns a fresh promise we can resolve by call index. */
function controllable<T>() {
  const calls: Array<(v: T) => void> = [];
  const loader = vi.fn(() => new Promise<T>((resolve) => calls.push(resolve)));
  return { loader, resolve: (i: number, v: T) => calls[i](v) };
}

describe("useApi — latest-wins + no-stuck-zero (K1)", () => {
  it("applies a fetched response to state and re-renders", async () => {
    const loader = vi.fn(() => Promise.resolve({ total: 5 }));
    const { result } = renderHook(() => useApi(loader, []));
    await waitFor(() => expect(result.current.data).toEqual({ total: 5 }));
    expect(result.current.loading).toBe(false);
  });

  it("RACE: a stale early response that resolves AFTER a newer one does NOT clobber it (latest-wins)", async () => {
    const { loader, resolve } = controllable<{ total: number }>();
    const { result } = renderHook(() => useApi(loader, []));
    // initial load is call 0 (in flight). Fire a refetch → call 1 (the NEWER load).
    await act(async () => { void result.current.refetch(); });
    // the newer load (call 1) resolves with the REAL value first…
    await act(async () => { resolve(1, { total: 100 }); });
    // …then the stale earlier load (call 0) resolves with an empty warm-up 0 — it must be dropped.
    await act(async () => { resolve(0, { total: 0 }); });
    expect(result.current.data).toEqual({ total: 100 }); // real value survives, not 0
  });

  it("STUCK REPRO: an earlier REAL response is NOT dropped just because a newer load has STARTED", async () => {
    // This is the 158c8ef defect: the strict `mySeq === seqRef.current` guard drops a resolved response the moment
    // any other load has *started* (bumped seqRef), even if that newer load is still in flight and applies nothing.
    // A real 200/{total:3346} from the initial load is dropped while a refetch/retry/poll is mid-flight → the card
    // is stuck at 0 with nothing to re-apply it. The monotonic guard (apply unless a strictly-newer response
    // already applied) fixes it.
    const { loader, resolve } = controllable<{ total: number }>();
    const { result } = renderHook(() => useApi(loader, []));
    // load#0 (initial) is in flight; start load#1 (a refetch/poll) — it is "newer" and also in flight.
    await act(async () => { void result.current.refetch(); });
    // load#0 resolves the REAL data while load#1 is still pending.
    await act(async () => { resolve(0, { total: 3346 }); });
    // Strict-latest drops it (0's mySeq !== the latest seq) → data stays null → STUCK. Monotonic applies it.
    expect(result.current.data).toEqual({ total: 3346 });
  });

  it("NO PERMANENT STUCK: after an empty is applied, any later successful real response binds", async () => {
    const { loader, resolve } = controllable<{ total: number }>();
    const { result } = renderHook(() => useApi(loader, []));
    // initial load resolves empty (warm-up) — applied.
    await act(async () => { resolve(0, { total: 0 }); });
    expect(result.current.data).toEqual({ total: 0 });
    // a later refetch (range change / poll) returns real data — it MUST bind (never permanently 0).
    await act(async () => { void result.current.refetch(); });
    await act(async () => { resolve(1, { total: 3346 }); });
    expect(result.current.data).toEqual({ total: 3346 });
  });

  it("NO-POISON: an empty response is never written to the cache (so a later load re-fetches)", async () => {
    const loader = vi.fn(() => Promise.resolve({ total: 0 }));
    const key = "kpi-nopoison";
    const { result } = renderHook(() =>
      useApi(loader, [], { cacheKey: key, staleTimeMs: 30_000, isEmpty: (d) => (d?.total ?? 0) === 0 })
    );
    await waitFor(() => expect(result.current.data).toEqual({ total: 0 }));
    // the empty value is shown (the truth right now) but NOT cached — nothing to poison the 30s window.
    expect(peekApiCache(key)).toBeUndefined();
  });

  it("caches a NON-empty response (normal path still memoizes)", async () => {
    const loader = vi.fn(() => Promise.resolve({ total: 42 }));
    const key = "kpi-cache";
    const { result } = renderHook(() =>
      useApi(loader, [], { cacheKey: key, staleTimeMs: 30_000, isEmpty: (d) => (d?.total ?? 0) === 0 })
    );
    await waitFor(() => expect(result.current.data).toEqual({ total: 42 }));
    expect(peekApiCache(key)).toEqual({ total: 42 });
  });

  it("RETRY: an empty first response is retried until a real value binds (bounded)", async () => {
    let call = 0;
    const loader = vi.fn(() => Promise.resolve(call++ === 0 ? { total: 0 } : { total: 77 }));
    const { result } = renderHook(() =>
      useApi(loader, [], { isEmpty: (d) => (d?.total ?? 0) === 0, emptyRetries: 3, emptyRetryMs: 10 })
    );
    // first resolve is empty → a bounded retry fires → the second resolve is real → cards bind the real value.
    await waitFor(() => expect(result.current.data).toEqual({ total: 77 }), { timeout: 1500 });
    expect(loader.mock.calls.length).toBeGreaterThanOrEqual(2);
  });

  it("RETRY is bounded: a persistently-empty response stops after emptyRetries (no infinite loop)", async () => {
    const loader = vi.fn(() => Promise.resolve({ total: 0 }));
    renderHook(() =>
      useApi(loader, [], { isEmpty: (d) => (d?.total ?? 0) === 0, emptyRetries: 2, emptyRetryMs: 10 })
    );
    await new Promise((r) => setTimeout(r, 200)); // let all retries drain
    expect(loader).toHaveBeenCalledTimes(3); // 1 initial + 2 bounded retries, then it accepts the 0
  });

  it("re-binds when deps change (range switch re-fetches)", async () => {
    const loader = vi.fn((n: number) => Promise.resolve({ total: n }));
    let range = 1;
    const { result, rerender } = renderHook(() => useApi(() => loader(range), [range]));
    await waitFor(() => expect(result.current.data).toEqual({ total: 1 }));
    range = 2;
    rerender();
    await waitFor(() => expect(result.current.data).toEqual({ total: 2 }));
  });
});
