import { useCallback, useEffect, useRef, useState } from "react";

type UseApiOptions = {
  cacheKey?: string;
  staleTimeMs?: number;
  refetchIntervalMs?: number;
};

const CACHE = new Map<string, { timestamp: number; value: unknown }>();

/** Clear the in-memory response cache (test utility — avoids cross-test state leakage). */
export function clearApiCache(): void {
  CACHE.clear();
}

export function useApi<T>(loader: () => Promise<T>, deps: unknown[] = [], options: UseApiOptions = {}) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const refetchRef = useRef<() => Promise<void>>(async () => {});
  const { cacheKey, staleTimeMs = 0, refetchIntervalMs } = options;

  useEffect(() => {
    let active = true;
    const load = (force = false) => {
      if (cacheKey && !force) {
        const cached = CACHE.get(cacheKey);
        if (cached && Date.now() - cached.timestamp < staleTimeMs) {
          setData(cached.value as T);
          setLoading(false);
          return Promise.resolve();
        }
      }

      setLoading(true);
      return loader()
        .then((value) => {
          if (active) {
            setData(value);
            setError(null);
            if (cacheKey) CACHE.set(cacheKey, { timestamp: Date.now(), value });
          }
        })
        .catch((err: Error) => {
          if (active) setError(err.message);
        })
        .finally(() => {
          if (active) setLoading(false);
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
      active = false;
      refetchRef.current = async () => {};
      if (timer) clearInterval(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  const refetch = useCallback(() => refetchRef.current(), []);
  return { data, error, loading, setData, refetch };
}
