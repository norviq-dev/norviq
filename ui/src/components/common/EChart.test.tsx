// SPDX-License-Identifier: Apache-2.0
// Regression guard: the echarts-for-react CJS default import must resolve to a valid React
// component, not the module namespace object. If it regresses to `{ default: Fn }`, rendering the
// chart throws React error #130 ("element type is invalid: got object") and Dashboard/Agents/Fleet
// go blank. isValidElementType() catches exactly that shape without needing a canvas.
import { describe, expect, it } from "vitest";
import ReactEChartsCore from "./EChart";
import { DonutChart } from "./DonutChart";
import { ScoreGauge } from "./ScoreGauge";
import { CategoryBars } from "../charts/CategoryBars";
import { VolumeChart } from "../charts/VolumeChart";

// A renderable React element type is a function/class OR an object carrying React's $$typeof marker
// (memo/forwardRef). The bug was ReactEChartsCore resolving to the CJS namespace object
// ({ default: Fn }) which has NEITHER — rendering it throws React #130.
function isRenderableComponent(x: unknown): boolean {
  if (typeof x === "function") return true;
  return typeof x === "object" && x !== null && "$$typeof" in (x as Record<string, unknown>);
}

describe("echarts interop is a valid React component", () => {
  it("EChart wrapper resolves to a renderable component (not the CJS namespace object)", () => {
    expect(typeof ReactEChartsCore).toBe("function");
    expect(isRenderableComponent(ReactEChartsCore)).toBe(true);
  });

  it("every chart component that renders on Dashboard/Agents/Fleet is a valid element type", () => {
    for (const Comp of [DonutChart, ScoreGauge, CategoryBars, VolumeChart]) {
      expect(isRenderableComponent(Comp)).toBe(true);
    }
  });
});
