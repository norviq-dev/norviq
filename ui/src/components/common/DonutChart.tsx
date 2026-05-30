import { memo } from "react";
import ReactEChartsCore from "echarts-for-react/lib/core";
import * as echarts from "echarts/core";
import { PieChart } from "echarts/charts";
import { LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { Panel } from "./Panel";

echarts.use([PieChart, LegendComponent, TooltipComponent, CanvasRenderer]);

const COLORS: Record<string, string> = {
  high: "#00E5A0",
  medium: "#FFB020",
  low: "#FF3B5C",
  frozen: "#666666"
};
const FALLBACK = ["#00E5A0", "#FFB020", "#FF3B5C", "#666666"];

const baseTooltip = {
  backgroundColor: "#252525",
  borderColor: "#3a3a3a",
  borderWidth: 1,
  textStyle: { color: "#ffffff", fontFamily: "Outfit", fontSize: 12 }
};

export const DonutChart = memo(function DonutChart({
  data,
  title = "Trust Distribution"
}: {
  data: Array<{ name: string; value: number }>;
  title?: string;
}) {
  const option = {
    tooltip: { trigger: "item", ...baseTooltip },
    legend: { bottom: 0, textStyle: { color: "#a0a0a0", fontSize: 11 }, icon: "circle", itemWidth: 9 },
    series: [
      {
        name: title,
        type: "pie",
        radius: ["52%", "76%"],
        center: ["50%", "44%"],
        avoidLabelOverlap: false,
        itemStyle: { borderRadius: 6, borderColor: "#0D0D0D", borderWidth: 3 },
        label: { show: true, color: "#ffffff", fontSize: 11, formatter: "{c}" },
        data: data.map((item, i) => ({
          ...item,
          itemStyle: { color: COLORS[item.name] ?? FALLBACK[i % 4] }
        }))
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
