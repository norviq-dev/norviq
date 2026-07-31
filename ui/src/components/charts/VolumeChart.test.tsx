// Tests for VolumeChart — the Overview's "Tool Call Volume" series.
//
// Regression guard for a chart that rendered to NOTHING while its tooltip still worked. /audit/volume
// buckets by hour regardless of the selected range, so a freshly-installed or low-traffic tenant gets a
// single bucket. A one-point line has no segment to stroke and no area beneath it, so with
// `symbol: "none"` nothing was drawn at all — yet `tooltip: {trigger: "axis"}` kept reporting the
// numbers on hover. The chart looked broken while the data was fine.
//
// The canvas is not inspectable under jsdom, so assert on the option object handed to ECharts — that is
// the thing that decides whether a mark is drawn.
import { render } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

const captured: Array<Record<string, any>> = [];

vi.mock("../common/EChart", () => ({
  default: ({ option }: { option: Record<string, any> }) => {
    captured.push(option);
    return <div data-testid="echart-stub" />;
  }
}));

import { VolumeChart } from "./VolumeChart";

const lastOption = () => captured[captured.length - 1];

describe("VolumeChart", () => {
  it("draws the point itself when there is only ONE bucket (otherwise nothing renders)", () => {
    render(<VolumeChart data={[{ time: "2026-07-31 21:00", allow: 81, block: 114 }]} />);
    const series = lastOption().series;
    for (const s of series) {
      // A lone point is the only drawable mark — suppressing the symbol makes the series invisible.
      expect(s.symbol).toBe("circle");
      expect(s.showSymbol).toBe(true);
      expect(s.symbolSize).toBeGreaterThan(0);
    }
    // The data must still be intact — this guards the fix, not a rewrite of the series.
    expect(series[0].data).toEqual([81]);
    expect(series[1].data).toEqual([114]);
  });

  it("keeps symbols off once there are enough points to draw a line", () => {
    render(
      <VolumeChart
        data={[
          { time: "2026-07-31 19:00", allow: 10, block: 2 },
          { time: "2026-07-31 20:00", allow: 14, block: 5 },
          { time: "2026-07-31 21:00", allow: 81, block: 114 }
        ]}
      />
    );
    const series = lastOption().series;
    for (const s of series) {
      expect(s.symbol).toBe("none");
      expect(s.showSymbol).toBe(false);
    }
  });

  it("renders an empty series without throwing", () => {
    expect(() => render(<VolumeChart data={[]} />)).not.toThrow();
  });
});
