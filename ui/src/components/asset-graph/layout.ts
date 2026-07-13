// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Asset Graph overview layout math — pure and unit-testable (feat/asset-graph-quality).
// The overview must stay LEGIBLE at real data volume: the fit never zooms below MIN_FIT_SCALE
// (11.5px labels stay >= ~9.4px rendered); when everything can't fit at the floor, the canvas
// pans instead of shrinking. Columns adapt to the canvas aspect so ~8 agent circles use the
// full width instead of stacking in the mock's fixed 2-column grid.

// Legibility floor: 11.5px labels render >= ~9.8px at 0.85 (crisp headroom); the adaptive grid still
// fits ~8 agents, and overflow pans rather than shrinking below this.
export const MIN_FIT_SCALE = 0.85;
export const MAX_FIT_SCALE = 1.6;

/** Column count for the per-agent circle grid: match the laid-out content to the canvas aspect. */
export function overviewColumns(clusterCount: number, width: number, height: number): number {
  if (clusterCount <= 1) return 1;
  const aspect = height > 0 ? width / height : 2.3;
  const raw = Math.round(Math.sqrt(clusterCount * aspect));
  return Math.max(2, Math.min(5, Math.min(raw, clusterCount)));
}

/** Clamp the raw fit scale into [MIN, MAX]. `clamped` = the content overflows at the floor (pan). */
export function clampFitScale(raw: number): { scale: number; clamped: boolean } {
  if (!Number.isFinite(raw) || raw <= 0) return { scale: MIN_FIT_SCALE, clamped: true };
  if (raw < MIN_FIT_SCALE) return { scale: MIN_FIT_SCALE, clamped: true };
  if (raw > MAX_FIT_SCALE) return { scale: MAX_FIT_SCALE, clamped: false };
  return { scale: raw, clamped: false };
}

/** Ring radius for one agent circle: grows with ring membership, floor keeps labels breathing. */
export function ringRadius(ringNodeCount: number): number {
  return ringNodeCount ? Math.max(95, (ringNodeCount * 50) / (2 * Math.PI)) : 0;
}

/**
 * Hull padding beyond the ring radius so the dashed circle encloses EVERY ring node AND its label.
 * Ring nodes sit at exactly ringRadius; the furthest painted point is nodeRadius (tool = 9) + the
 * outward label offset (~TYPE_R+16 ≈ 24px). 46px = 9 + 24 + ~13px breathing room, so no node/label
 * can poke outside the hull. clusterGaps already keeps neighbors ~118px apart after this growth.
 */
export const HULL_PAD = 46;

/** Grid gaps derived from the LARGEST ring on screen (+label margins) — tight but collision-free. */
export function clusterGaps(maxRingRadius: number): { colGap: number; rowGap: number } {
  const r = Math.max(95, maxRingRadius);
  return {
    colGap: Math.round(2 * r + 210), // horizontal: ring + node labels on both sides
    rowGap: Math.round(2 * r + 170) // vertical: ring + cluster label above / node label below
  };
}
