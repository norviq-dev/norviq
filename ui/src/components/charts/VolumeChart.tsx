import { memo } from "react";
import ReactEChartsCore from "../common/EChart";
import * as echarts from "echarts/core";
import { LineChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { Panel } from "../common/Panel";

echarts.use([LineChart, GridComponent, TooltipComponent, LegendComponent, CanvasRenderer]);

const AXIS_GREY = "#2A2A2A";
const ALLOW_COLOR = "#00E5A0";
const BLOCK_COLOR = "#FF3B5C";
const baseTooltip = {
  backgroundColor: "#252525",
  borderColor: "#3a3a3a",
  borderWidth: 1,
  textStyle: { color: "#ffffff", fontFamily: "Outfit", fontSize: 12 }
};

export const VolumeChart = memo(function VolumeChart({
  data,
  title = "Tool Call Volume",
  labels = ["Allow", "Block"]
}: {
  data: Array<{ time: string; allow: number; block: number }>;
  title?: string;
  labels?: [string, string];
}) {
  // A single bucket has no line SEGMENT to draw and no area beneath it, so with `symbol: "none"` the
  // series renders to literally nothing — while `tooltip: {trigger: "axis"}` still reports the numbers
  // on hover. The chart reads as broken: metrics but no chart. This is not an edge case; /audit/volume
  // buckets by HOUR regardless of the selected range, so every freshly-installed or low-traffic tenant
  // lands here. Draw the point itself when it is the only thing there is to draw.
  const sparse = data.length < 2;
  const option = {
    color: [ALLOW_COLOR, BLOCK_COLOR],
    tooltip: { trigger: "axis", ...baseTooltip },
    legend: {
      data: labels,
      bottom: 0,
      textStyle: { color: "#a0a0a0", fontSize: 11 },
      icon: "roundRect",
      itemWidth: 10,
      itemHeight: 10
    },
    grid: { left: 36, right: 20, top: 16, bottom: 38 },
    xAxis: {
      type: "category",
      boundaryGap: false,
      data: data.map((d) => d.time),
      axisLine: { lineStyle: { color: AXIS_GREY } },
      axisLabel: { color: "#a0a0a0", fontSize: 10, interval: 3 }
    },
    yAxis: {
      type: "value",
      axisLine: { show: false },
      axisLabel: { color: "#a0a0a0", fontSize: 11 },
      splitLine: { lineStyle: { color: AXIS_GREY } }
    },
    series: [
      {
        name: labels[0],
        data: data.map((d) => d.allow),
        type: "line",
        smooth: true,
        symbol: sparse ? "circle" : "none",
        symbolSize: sparse ? 7 : 0,
        showSymbol: sparse,
        areaStyle: { color: "#00E5A018" },
        lineStyle: { color: ALLOW_COLOR, width: 2 },
        itemStyle: { color: ALLOW_COLOR }
      },
      {
        name: labels[1],
        data: data.map((d) => d.block),
        type: "line",
        smooth: true,
        symbol: sparse ? "circle" : "none",
        symbolSize: sparse ? 7 : 0,
        showSymbol: sparse,
        areaStyle: { color: "#FF3B5C18" },
        lineStyle: { color: BLOCK_COLOR, width: 2 },
        itemStyle: { color: BLOCK_COLOR }
      }
    ]
  };
  return (
    <Panel title={title}>
      <ReactEChartsCore
        echarts={echarts}
        option={option}
        style={{ height: 230, width: "100%" }}
        className="chart-box"
      />
    </Panel>
  );
});
