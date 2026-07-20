// SPDX-License-Identifier: Apache-2.0
// The single source of truth for which routes the global header time-range drives.
import { describe, it, expect } from "vitest";
import { isTimeScoped, TIME_SCOPED_PATHS } from "./routeMeta";

describe("routeMeta.isTimeScoped — global range applies ONLY to genuinely range-driven routes", () => {
  it("is TRUE for the range-driven pages (Overview + Audit + Compliance)", () => {
    expect(isTimeScoped("/")).toBe(true);
    expect(isTimeScoped("/audit")).toBe(true);
    expect(isTimeScoped("/audit/anything")).toBe(true);
    // Compliance IS range-scoped (per-technique evidence changes with the window) — the global header range is
    // now its single source of truth.
    expect(isTimeScoped("/compliance")).toBe(true);
    expect([...TIME_SCOPED_PATHS]).toEqual(["/", "/audit", "/compliance"]);
  });

  it("is FALSE for current-state pages (Catalog / Packs / Target Settings)", () => {
    expect(isTimeScoped("/policies/catalog")).toBe(false);
    expect(isTimeScoped("/policies/packs")).toBe(false);
    expect(isTimeScoped("/policies/targets")).toBe(false);
  });

  it("is FALSE for pages with their OWN in-page range picker (Attack Graph / Asset Graph)", () => {
    expect(isTimeScoped("/threats/graph")).toBe(false);
    expect(isTimeScoped("/asset-graph")).toBe(false);
  });

  it("is FALSE for the remaining non-time-scoped routes (Tester / Agents / Settings / Fleet)", () => {
    for (const p of ["/test", "/agents", "/settings/general", "/settings/api-keys", "/settings/about", "/fleet"]) {
      expect(isTimeScoped(p)).toBe(false);
    }
  });
});
