import { memo } from "react";
import ReactEChartsCore from "./EChart";
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
  const colorFor = (name: string, i: number) => COLORS[name] ?? FALLBACK[i % 4];
  // P3: only NON-ZERO categories become arcs — a 0-value slice would otherwise draw a degenerate sliver.
  const arcs = data
    .map((item, i) => ({ ...item, itemStyle: { color: colorFor(item.name, i) } }))
    .filter((item) => item.value > 0);
  const option = {
    tooltip: { trigger: "item", ...baseTooltip },
    // P3: echarts legend replaced by a custom one below so EVERY category (incl value 0) is listed with its count.
    legend: { show: false },
    series: [
      {
        name: title,
        type: "pie",
        radius: ["52%", "76%"],
        center: ["50%", "50%"],
        avoidLabelOverlap: false,
        itemStyle: { borderRadius: 6, borderColor: "#0D0D0D", borderWidth: 3 },
        label: { show: true, color: "#ffffff", fontSize: 11, formatter: "{c}" },
        data: arcs
      }
    ]
  };
  return (
    <Panel title={title}>
      <ReactEChartsCore
        echarts={echarts}
        option={option}
        style={{ height: 196, width: "100%" }}
        className="chart-box"
      />
      {/* P3: full legend — all categories with counts INCLUDING zero (was hover-only), consistent Overview+Agents. */}
      <div
        role="list"
        aria-label={`${title} legend`}
        style={{ display: "flex", flexWrap: "wrap", justifyContent: "center", gap: "6px 16px", marginTop: 2 }}
      >
        {data.map((item, i) => (
          <span
            key={item.name}
            role="listitem"
            style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11, color: item.value > 0 ? "#c8c8c8" : "#8a8a8a" }}
          >
            <span style={{ width: 9, height: 9, borderRadius: "50%", background: colorFor(item.name, i), opacity: item.value > 0 ? 1 : 0.45, flex: "none" }} />
            <span style={{ textTransform: "capitalize" }}>{item.name}</span>
            <span className="mono" style={{ fontVariantNumeric: "tabular-nums" }}>{item.value}</span>
          </span>
        ))}
      </div>
    </Panel>
  );
});
