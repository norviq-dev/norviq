// SPDX-License-Identifier: Apache-2.0
// F-34: /fleet must resolve to the Intelligence section (its nav item lives there), not fall through to Security.
import { describe, expect, it } from "vitest";
import { sectionFromPath } from "./AppContext";

describe("sectionFromPath", () => {
  it("maps /fleet to intelligence (F-34)", () => {
    expect(sectionFromPath("/fleet")).toBe("intelligence");
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
