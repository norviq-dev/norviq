// SPDX-License-Identifier: Apache-2.0
// P3: the Trust Distribution donut must show ALL categories (incl value 0) in the legend with their counts,
// and must NOT draw a degenerate 0-width arc. The echarts canvas is stubbed; the legend is plain React.
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

vi.mock("./EChart", () => ({ default: () => <div data-testid="echart-stub" /> }));

import { DonutChart } from "./DonutChart";

describe("DonutChart (P3)", () => {
  it("shows all four categories with counts including zero", () => {
    render(
      <DonutChart
        data={[
          { name: "high", value: 5 },
          { name: "medium", value: 2 },
          { name: "low", value: 0 },
          { name: "frozen", value: 0 }
        ]}
      />
    );
    const legend = screen.getByRole("list", { name: /legend/i });
    // low 0 and frozen 0 are legible without hover (each has its own listitem with the count).
    for (const [name, count] of [["high", "5"], ["medium", "2"], ["low", "0"], ["frozen", "0"]] as const) {
      const item = within(legend).getByText(name).closest("[role=listitem]") as HTMLElement;
      expect(item).toBeTruthy();
      expect(within(item).getByText(count)).toBeInTheDocument();
    }
    expect(within(legend).getAllByRole("listitem")).toHaveLength(4);
  });
});
