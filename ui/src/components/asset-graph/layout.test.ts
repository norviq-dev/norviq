// SPDX-License-Identifier: Apache-2.0
// Overview layout math (feat/asset-graph-quality): aspect-driven columns, the min/max fit clamp
// that keeps labels >= ~9px rendered, and ring/gap sizing.
import { describe, expect, it } from "vitest";
import { HULL_PAD, MAX_FIT_SCALE, MIN_FIT_SCALE, clampFitScale, clusterGaps, overviewColumns, ringRadius } from "./layout";

describe("overviewColumns", () => {
  it("matches content to a ~2.35:1 canvas", () => {
    expect(overviewColumns(4, 1600, 680)).toBe(3); // sqrt(4*2.35)≈3.1
    expect(overviewColumns(8, 1600, 680)).toBe(4); // sqrt(8*2.35)≈4.3
  });

  it("clamps to [2, 5] and never exceeds the cluster count", () => {
    expect(overviewColumns(2, 1600, 680)).toBe(2);
    expect(overviewColumns(40, 1600, 680)).toBe(5);
    expect(overviewColumns(1, 1600, 680)).toBe(1);
    expect(overviewColumns(3, 4000, 400)).toBe(3); // raw would be huge; capped at count then 5
  });

  it("tolerates a degenerate height", () => {
    expect(overviewColumns(6, 1600, 0)).toBeGreaterThanOrEqual(2);
  });
});

describe("clampFitScale", () => {
  it("floors at MIN and reports clamped (pan instead of shrink)", () => {
    expect(clampFitScale(0.6)).toEqual({ scale: MIN_FIT_SCALE, clamped: true });
    expect(MIN_FIT_SCALE).toBe(0.85);
  });

  it("ceils at MAX without clamped", () => {
    expect(clampFitScale(2.4)).toEqual({ scale: MAX_FIT_SCALE, clamped: false });
  });

  it("passes mid-range through", () => {
    expect(clampFitScale(1.0)).toEqual({ scale: 1.0, clamped: false });
  });

  it("treats garbage as the floor", () => {
    expect(clampFitScale(NaN).scale).toBe(MIN_FIT_SCALE);
    expect(clampFitScale(-1).clamped).toBe(true);
  });

  it("keeps 11.5px node labels >= 9px at the floor", () => {
    expect(11.5 * MIN_FIT_SCALE).toBeGreaterThanOrEqual(9);
    expect(11 * MIN_FIT_SCALE).toBeGreaterThanOrEqual(9); // blocked-badge text
  });
});

describe("ringRadius / clusterGaps", () => {
  it("ring grows with membership above the 95px floor", () => {
    expect(ringRadius(0)).toBe(0);
    expect(ringRadius(3)).toBe(95);
    expect(ringRadius(14)).toBeGreaterThan(95);
  });

  it("gaps scale with the largest ring (tight when rings are small)", () => {
    const small = clusterGaps(95);
    const large = clusterGaps(160);
    expect(small.colGap).toBe(400);
    expect(small.rowGap).toBe(360);
    expect(large.colGap).toBeGreaterThan(small.colGap);
    expect(large.rowGap).toBeGreaterThan(small.rowGap);
  });

  it("HULL_PAD encloses the furthest ring node + its label so nothing pokes outside", () => {
    // Furthest painted point from ring = node radius (tool = 9) + outward label offset (~TYPE_R+16 ≈ 24).
    const NODE_R = 9; // TYPE_R.tool (largest ring-node radius)
    const LABEL_OFFSET = NODE_R + 16; // AssetGraphCanvas label x/y offset for ring nodes
    expect(HULL_PAD).toBeGreaterThanOrEqual(NODE_R + LABEL_OFFSET);
    // A ring node at ringRadius + its label must stay inside hullRadius = ringRadius + HULL_PAD.
    const r = ringRadius(14);
    const hullRadius = r + HULL_PAD;
    expect(hullRadius).toBeGreaterThanOrEqual(r + NODE_R + LABEL_OFFSET);
  });

  it("keeps DENSE neighboring hulls collision-free after growing by HULL_PAD", () => {
    // customer-support ~25 tools → ringRadius ~199; hulls grow to r+46 each, gap must stay positive.
    const r = ringRadius(25);
    const { colGap } = clusterGaps(r);
    const edgeGap = colGap - 2 * (r + HULL_PAD);
    expect(edgeGap).toBeGreaterThan(0);
  });
});
