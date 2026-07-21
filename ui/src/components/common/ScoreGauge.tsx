import { memo } from "react";
import ReactEChartsCore from "./EChart";
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
  sub?: React.ReactNode;
}) {
  const bounded = Math.max(0, Math.min(100, score));
  // The caption is supplied by the caller (the gauge is honest about WHAT it measures); default coloring.
  const color = bounded > 75 ? "#00e5a0" : bounded > 50 ? "#ffb020" : "#ff3b5c";
  const caption = sub ?? (bounded > 75 ? "Low Risk" : bounded > 50 ? "Medium Risk" : "High Risk");
  // A caller-supplied descriptive caption is NEUTRAL grey — the score's risk-band color (#ff3b5c at low
  // coverage) is reserved for real block/risk decisions and must not tint a "rules present" description. Only
  // the built-in risk labels (Low/Medium/High Risk, when no `sub` is given) keep the risk color.
  const captionColor = sub != null ? "var(--text-muted)" : color;

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
        {/* Big % stays pulled up INTO the arc (centered in the half-gauge). */}
        <div style={{ textAlign: "center", marginTop: -86 }}>
          <div style={{ fontSize: 40, fontWeight: 700, letterSpacing: "-.02em", lineHeight: 1 }} data-testid="score-gauge-value">{bounded}{unit}</div>
        </div>
      </div>
      {/* The caption sits BELOW the gauge, not in the in-arc overlay, so the long "rules present · N%
          proven-blocking (last run)" doesn't overlap the arc/number. Marker + text + neutral color. */}
      <div style={{ textAlign: "center", fontSize: 13, color: captionColor, marginTop: 44 }} data-testid="score-gauge-caption">{caption}</div>
    </Panel>
  );
});
