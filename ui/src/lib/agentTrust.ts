// Agent trust as the console shows it: which client caches hold it, and the states a row can be in beside
// the four trust bands.
//
// `/api/v1/agents` and `/api/v1/search` report each agent's freeze and cap as the engine enforces them, read
// from the trust store on every request (norviq/api/routers/agents.py::_overlay_controls). Two states are
// neither a band nor a freeze:
//   * "unscored": the score the console held was taken while a control that has since been lifted was in
//     force (a freeze, or a cap that held the score down). The engine's score is not known until the agent's
//     next call.
//   * controls "unavailable": the API could not read the store. The engine fails CLOSED when it cannot read
//     it, so the agent may be blocked on every call. `frozen` is null and the category is "unknown". This must
//     never be shown as "not frozen".

import { invalidateApiCache } from "../hooks/useApi";

/** Every useApi cache key prefix whose entries show an agent's trust, freeze or cap. */
export const TRUST_CACHE_PREFIXES = ["agent-monitor:", "dashboard-agents:"] as const;

const listeners = new Set<() => void>();

/**
 * After a freeze, an unfreeze or a cap change: drop every cached answer that shows trust or freeze state, and
 * tell components that keep their own copy (the header's alert counts) to drop it too. Before this only the
 * Agent Monitor's own entry was dropped, so the Overview's trust donut kept the old freeze for up to a minute.
 */
export function invalidateTrustCaches(): void {
  for (const prefix of TRUST_CACHE_PREFIXES) invalidateApiCache(prefix);
  for (const listener of [...listeners]) listener();
}

/** Run `listener` on every invalidateTrustCaches(). Returns the unsubscribe function. */
export function onTrustCachesInvalidated(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

export type AgentControlsState = { controls?: string | null; frozen?: boolean | null; category?: string | null };

/** The API could not read this agent's freeze and cap from the trust store. */
export function controlsUnavailable(row: AgentControlsState): boolean {
  return row.controls === "unavailable";
}

/** True only when the API says the agent is frozen (an older API without `frozen`: its category). */
export function isFrozen(row: AgentControlsState): boolean {
  if (controlsUnavailable(row)) return false;
  return row.frozen ?? (row.category ?? "").toLowerCase() === "frozen";
}

/** The label used when the freeze state could not be read. */
export const FREEZE_UNKNOWN = "freeze unknown";

/**
 * The trust donut's slices. The four bands always (a zero is a measurement), then "unscored" and
 * "freeze unknown" only when some agent is in that state: they used to fall out of the donut silently, so
 * its total did not match the agents listed and an unreadable freeze vanished from the chart.
 */
export function trustDistribution(rows: AgentControlsState[]): Array<{ name: string; value: number }> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const name = controlsUnavailable(row) ? FREEZE_UNKNOWN : (row.category ?? "").toLowerCase();
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  const slices = ["high", "medium", "low", "frozen"].map((name) => ({ name, value: counts.get(name) ?? 0 }));
  for (const name of ["unscored", FREEZE_UNKNOWN]) {
    const value = counts.get(name) ?? 0;
    if (value > 0) slices.push({ name, value });
  }
  return slices;
}
