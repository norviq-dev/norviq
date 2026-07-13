import { memo } from "react";
import ReactEChartsCore from "../common/EChart";
import * as echarts from "echarts/core";
import { BarChart } from "echarts/charts";
import { GridComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { Panel } from "../common/Panel";

echarts.use([BarChart, GridComponent, TooltipComponent, CanvasRenderer]);

const AXIS_GREY = "#2A2A2A";
const baseTooltip = {
  backgroundColor: "#252525",
  borderColor: "#3a3a3a",
  borderWidth: 1,
  textStyle: { color: "#ffffff", fontFamily: "Outfit", fontSize: 12 }
};

export const CategoryBars = memo(function CategoryBars({
  data,
  title = "Category Scores",
  sub,
  bare = false
}: {
  // CAP-2: an optional per-bar `color` overrides the default score-tier colour — used by the Tool Usage
  // chart to colour bars by the tool's RISK tier instead of by call volume.
  data: Array<{ category: string; score: number; color?: string }>;
  title?: string;
  sub?: string;
  /** Render just the chart (no Panel wrapper) so a parent card can compose it with siblings + one legend. */
  bare?: boolean;
}) {
  const option = {
    tooltip: { trigger: "axis", ...baseTooltip },
    // Extra right gutter so the on-bar value label ("100%") never clips against the panel edge.
    grid: { left: 130, right: 44, top: 14, bottom: 14 },
    xAxis: {
      type: "value",
      max: 100,
      axisLabel: { color: "#a0a0a0", fontSize: 11 },
      splitLine: { lineStyle: { color: AXIS_GREY } }
    },
    yAxis: {
      type: "category",
      data: data.map((d) => d.category),
      axisLine: { lineStyle: { color: AXIS_GREY } },
      axisLabel: { color: "#a0a0a0", fontSize: 12 }
    },
    series: [
      {
        type: "bar",
        barWidth: 13,
        // A faint full-width track so a LOW score reads as "low", not a broken/near-invisible sliver.
        showBackground: true,
        backgroundStyle: { color: "rgba(255,255,255,0.05)", borderRadius: [0, 4, 4, 0] },
        // The score value at the end of each bar — the chart is now legible without hovering.
        label: {
          show: true,
          position: "right",
          color: "#c7cdd6",
          fontSize: 11,
          fontWeight: 600,
          formatter: "{c}%"
        },
        data: data.map((d) => ({
          value: d.score,
          itemStyle: {
            borderRadius: [0, 4, 4, 0],
            color: d.color ?? (d.score > 80 ? "#00E5A0" : d.score >= 60 ? "#FFB020" : "#FF3B5C")
          }
        }))
      }
    ]
  };
  const chart = (
    <ReactEChartsCore
      echarts={echarts}
      option={option}
      style={{ height: Math.max(120, data.length * 40 + 40), width: "100%" }}
      className="chart-box"
    />
  );
  if (bare) return chart;
  return (
    <Panel title={title} sub={sub}>
      {chart}
    </Panel>
  );
});
