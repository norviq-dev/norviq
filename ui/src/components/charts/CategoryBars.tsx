import { memo } from "react";
import ReactEChartsCore from "echarts-for-react/lib/core";
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
  title = "Category Scores"
}: {
  data: Array<{ category: string; score: number }>;
  title?: string;
}) {
  const option = {
    tooltip: { trigger: "axis", ...baseTooltip },
    grid: { left: 130, right: 28, top: 14, bottom: 14 },
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
        barWidth: 11,
        data: data.map((d) => ({
          value: d.score,
          itemStyle: {
            borderRadius: [0, 4, 4, 0],
            color: d.score > 80 ? "#00E5A0" : d.score >= 60 ? "#FFB020" : "#FF3B5C"
          }
        }))
      }
    ]
  };
  return (
    <Panel title={title}>
      <ReactEChartsCore
        echarts={echarts}
        option={option}
        style={{ height: 244, width: "100%" }}
        className="chart-box"
      />
    </Panel>
  );
});
