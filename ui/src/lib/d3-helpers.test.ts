// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { NODE_COLORS, NODE_RADIUS, edgeColor, timeAgo } from "./d3-helpers";

describe("edgeColor", () => {
  it("returns gray when history is undefined", () => {
    expect(edgeColor()).toBe("#444");
  });

  it("returns gray when total is 0", () => {
    expect(edgeColor({ allow: 0, block: 0, escalate: 0 })).toBe("#444");
  });

  it("returns red when >50% blocked", () => {
    expect(edgeColor({ allow: 1, block: 5, escalate: 0 })).toBe("#FF3B5C");
  });
});

describe("timeAgo", () => {
  it("returns dash for undefined", () => {
    expect(timeAgo()).toBe("-");
  });

  it("returns minutes for recent past", () => {
    const t = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    expect(timeAgo(t)).toBe("5 min ago");
  });
});

describe("constants", () => {
  it("NODE_COLORS has all 4 types", () => {
    expect(NODE_COLORS).toHaveProperty("agent");
    expect(NODE_COLORS).toHaveProperty("tool");
    expect(NODE_COLORS).toHaveProperty("data");
    expect(NODE_COLORS).toHaveProperty("namespace");
  });

  it("NODE_RADIUS has all 4 types", () => {
    expect(NODE_RADIUS).toHaveProperty("agent");
    expect(NODE_RADIUS).toHaveProperty("tool");
    expect(NODE_RADIUS).toHaveProperty("data");
    expect(NODE_RADIUS).toHaveProperty("namespace");
  });
});
