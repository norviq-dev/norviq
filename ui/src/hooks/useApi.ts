// useApi — the shared data-fetching hook: runs a loader when its deps change, exposing loading/error/
// data with an in-memory response cache (cacheKey + staleTimeMs) and optional polling (refetchIntervalMs).
// The module-level cache helpers (prime / peek / readFresh / invalidate / clear) let callers seed and
// bust that shared cache across components.

import { useCallback, useEffect, useRef, useState } from "react";

type UseApiOptions<T = unknown> = {
  cacheKey?: string;
  staleTimeMs?: number;
  refetchIntervalMs?: number;
  /**
   * Treat a resolved value as "not yet real". An empty value is NEVER written to the module cache (so a
   * transient/warm-up `{total:0}` can't poison the staleTime window and short-circuit later loads), and — if
   * attempts remain — it triggers a bounded retry so the real value replaces it once it resolves. The empty value
   * is still applied to state so the UI shows the current truth immediately (a genuinely-empty range stays 0).
   */
  isEmpty?: (data: T) => boolean;
  /** Max bounded retries when a resolved value is empty, per deps cycle (default 0 = off). */
  emptyRetries?: number;
  /** Delay before an empty-triggered retry (default 1000ms). */
  emptyRetryMs?: number;
};

const CACHE = new Map<string, { timestamp: number; value: unknown }>();

/** Clear the in-memory response cache (test utility — avoids cross-test state leakage). */
export function clearApiCache(): void {
  CACHE.clear();
}

/**
 * Invalidate cached responses after a mutation so the NEXT load (even a non-forced remount, or a DIFFERENT page
 * that reads the same data under its own cacheKey) fetches fresh instead of serving a stale entry inside its
 * `staleTimeMs` window. Pass a key prefix — every cache entry whose key starts with it is dropped. This is the
 * cross-page/remount half of "a mutation-triggered read always reflects the new state": the same-page consumer
 * gets it via `refetch()` (force), and every other consumer gets it because its stale cache entry is gone.
 * Safe for all consumers — it only drops cache (forcing a fresh fetch), never mutates or corrupts state.
 */
export function invalidateApiCache(keyPrefix: string): void {
  for (const key of [...CACHE.keys()]) {
    if (key.startsWith(keyPrefix)) CACHE.delete(key);
  }
}

/** Test utility: peek at a cached entry (undefined when absent). Used to assert empty responses are NOT cached. */
export function peekApiCache(key: string): unknown {
  return CACHE.get(key)?.value;
}

/** Peek at a cached entry only if still within `maxAgeMs` (else undefined) — read-through for non-hook callers. */
export function readFreshApiCache(key: string, maxAgeMs: number): unknown {
  const hit = CACHE.get(key);
  return hit && Date.now() - hit.timestamp < maxAgeMs ? hit.value : undefined;
}

/** Prime the shared cache so a subsequent useApi consumer of the same key gets a hit (write-through for
 *  non-hook callers like AppContext's posture fetch). Invalidation (invalidateApiCache) still applies. */
export function primeApiCache(key: string, value: unknown): void {
  CACHE.set(key, { timestamp: Date.now(), value });
}

export function useApi<T>(loader: () => Promise<T>, deps: unknown[] = [], options: UseApiOptions<T> = {}) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const refetchRef = useRef<() => Promise<void>>(async () => {});
  // Each load gets a monotonically-increasing id (`seqRef`); `appliedRef` is the id of the newest load whose
  // result was applied to state. A load applies its result UNLESS a strictly-NEWER load has ALREADY applied one
  // (mySeq < appliedRef) or its cycle was torn down (active=false). This is MONOTONIC — it never permanently drops
  // a response that is newer-than-applied. The prior `mySeq === seqRef.current` was the stuck-at-0 bug: it dropped
  // a valid response the instant any newer load merely STARTED (bumped seqRef), even while that newer load was
  // still in flight / would resolve empty / would itself be superseded — so a real 200 could be lost with nothing
  // to re-apply it.
  const seqRef = useRef(0);
  const appliedRef = useRef(0);
  // Has THIS deps cycle produced data yet? On error the catch below deliberately keeps the previous
  // value — a brief flicker to empty is worse than showing the last good numbers a moment longer —
  // but that means after a NAMESPACE SWITCH whose read fails, `data` is the PREVIOUS namespace's,
  // and every consumer renders it under the new namespace's header as measured fact.
  //
  // Six separately-reported defects were all this one hook contract: the audit log printed one
  // namespace's blocked call under another's name, Compliance kept the old ATLAS coverage, the
  // Overview republished the old coverage %, and an intent proposed in namespace A stayed
  // Save-enabled after switching to B. Each page was "fixed" by testing `data == null`, which is
  // never true here — so the fix looked right and changed nothing.
  //
  // `stale` is the fact those pages actually needed: we are holding data, and it is NOT this deps
  // cycle's. A consumer can then say so instead of asserting it.
  const [freshForDeps, setFreshForDeps] = useState(false);
  const { cacheKey, staleTimeMs = 0, refetchIntervalMs, isEmpty, emptyRetries = 0, emptyRetryMs = 1000 } = options;

  useEffect(() => {
    let active = true;
    let emptyAttempts = 0; // reset per deps cycle (e.g. a range change gets a fresh retry budget)
    let emptyRetryTimer: ReturnType<typeof setTimeout> | null = null;
    appliedRef.current = 0; // fresh apply-watermark per deps cycle, so this cycle's first response always binds
    setFreshForDeps(false); // whatever we are holding belongs to the PREVIOUS cycle until this one lands

    const load = (force = false): Promise<void> => {
      const mySeq = ++seqRef.current;
      // apply unless torn down, or a strictly-newer load already applied a result
      const canApply = () => active && mySeq >= appliedRef.current;

      if (cacheKey && !force) {
        const cached = CACHE.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < staleTimeMs) {
          if (canApply()) {
            setData(cached.value as T);
            appliedRef.current = mySeq;
            setFreshForDeps(true);
            setLoading(false);
          }
          return Promise.resolve();
        }
      }

      setLoading(true);
      return loader()
        .then((value) => {
          if (!canApply()) return; // a strictly-newer response already applied — drop this (genuinely stale) one
          const empty = isEmpty ? isEmpty(value) : false;
          setData(value);
          setError(null);
          appliedRef.current = mySeq;
          setFreshForDeps(true);
          // Never cache an empty value — that is what poisons the staleTime window and sticks the cards at 0.
          if (cacheKey && !empty) CACHE.set(cacheKey, { timestamp: Date.now(), value });
          // Warm-up: an empty response schedules a bounded retry so the real value binds quickly once it exists.
          if (empty && emptyAttempts < emptyRetries) {
            emptyAttempts += 1;
            emptyRetryTimer = setTimeout(() => {
              if (active) void load(true);
            }, emptyRetryMs);
          }
        })
        .catch((err: Error) => {
          if (canApply()) setError(err.message);
        })
        .finally(() => {
          if (canApply()) setLoading(false);
        });
    };
    refetchRef.current = () => load(true);

    load();
    const timer =
      refetchIntervalMs != null
        ? setInterval(() => {
            void load(true);
          }, refetchIntervalMs)
        : null;

    return () => {
      active = false; // drop this cycle's in-flight loads (so old-range data can't flash after a range change)
      refetchRef.current = async () => {};
      if (timer) clearInterval(timer);
      if (emptyRetryTimer) clearTimeout(emptyRetryTimer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  const refetch = useCallback(() => refetchRef.current(), []);
  // `stale` = we are holding data and it is NOT this deps cycle's. Read it wherever the deps carry a
  // SCOPE (a namespace, a cluster, a time range): rendering held data as if it described the new
  // scope is how a console reports one namespace's security posture under another's name.
  const stale = data !== null && !freshForDeps;
  return { data, error, loading, stale, setData, refetch };
}
