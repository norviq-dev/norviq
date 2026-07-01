import { memo } from "react";
import ReactEChartsCore from "echarts-for-react/lib/core";
import * as echarts from "echarts/core";
import { GaugeChart } from "echarts/charts";
import { TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import { Panel } from "./Panel";

echarts.use([GaugeChart, TooltipComponent, CanvasRenderer]);

export const ScoreGauge = memo(function ScoreGauge({
  score,
  title = "Security Score",
  unit = "%",
  sub
}: {
  score: number;
  title?: string;
  unit?: string;
  sub?: string;
}) {
  const bounded = Math.max(0, Math.min(100, score));
  // F-63: the caption is supplied by the caller (the gauge is honest about WHAT it measures); default coloring.
  const color = bounded > 75 ? "#00e5a0" : bounded > 50 ? "#ffb020" : "#ff3b5c";
  const caption = sub ?? (bounded > 75 ? "Low Risk" : bounded > 50 ? "Medium Risk" : "High Risk");

  const option = {
    series: [
      {
        type: "gauge",
        startAngle: 180,
        endAngle: 0,
        min: 0,
        max: 100,
        radius: "135%",
        center: ["50%", "90%"],
        pointer: { show: false },
        progress: {
          show: true,
          width: 20,
          roundCap: true,
          itemStyle: {
            color: {
              type: "linear",
              x: 0,
              y: 0,
              x2: 1,
              y2: 0,
              colorStops: [
                { offset: 0, color: "#00E5A0" },
                { offset: 0.5, color: "#FFB020" },
                { offset: 1, color: "#FF3B5C" }
              ]
            }
          }
        },
        axisLine: { lineStyle: { width: 20, color: [[1, "#2A2A2A"]] } },
        axisTick: { show: false },
        splitLine: { show: false },
        axisLabel: { show: false },
        detail: { show: false },
        data: [{ value: bounded }]
      }
    ]
  };

  return (
    <Panel title={title}>
      <div style={{ position: "relative" }}>
        <ReactEChartsCore
          echarts={echarts}
          option={option}
          style={{ height: 200, width: "100%" }}
          className="chart-box"
        />
        <div style={{ textAlign: "center", marginTop: -86 }}>
          <div style={{ fontSize: 40, fontWeight: 700, letterSpacing: "-.02em", lineHeight: 1 }}>{bounded}{unit}</div>
          <div style={{ fontSize: 13, color, marginTop: 2 }}>{caption}</div>
        </div>
      </div>
    </Panel>
  );
});
