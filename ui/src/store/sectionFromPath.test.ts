// SPDX-License-Identifier: Apache-2.0
// /fleet is multi-cluster MANAGEMENT — it resolves to the Security Operations section (was Intelligence).
import { describe, expect, it } from "vitest";
import { sectionFromPath } from "./AppContext";

describe("sectionFromPath", () => {
  it("maps /fleet to security (Fleet is management/ops)", () => {
    expect(sectionFromPath("/fleet")).toBe("security");
  });
  it("keeps the existing mappings", () => {
    expect(sectionFromPath("/")).toBe("intelligence");
    expect(sectionFromPath("/threats/graph")).toBe("intelligence");
    expect(sectionFromPath("/asset-graph")).toBe("intelligence");
    expect(sectionFromPath("/settings/general")).toBe("settings");
    expect(sectionFromPath("/audit")).toBe("security");
    expect(sectionFromPath("/policies/catalog")).toBe("security");
  });
});
