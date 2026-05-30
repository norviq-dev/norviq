// ============================================================================
// NORVIQ UI KIT — charts.jsx
// ECharts wrappers: ScoreGauge, CategoryBars, VolumeChart, DonutChart.
// Each renders into a div ref and disposes on unmount.
// ============================================================================
function useECharts(option, deps) {
  const ref = useRef(null);
  const inst = useRef(null);
  useEffect(() => {
    if (!ref.current || !window.echarts) return;
    if (!inst.current) inst.current = window.echarts.init(ref.current);
    inst.current.setOption(option, true);
    const onResize = () => inst.current && inst.current.resize();
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, deps);
  useEffect(() => () => { if (inst.current) { inst.current.dispose(); inst.current = null; } }, []);
  return ref;
}

const AXIS_GREY = "#1A2744";
const baseTooltip = {
  backgroundColor: "#152040", borderColor: "#2a3f6a", borderWidth: 1,
  textStyle: { color: "#e8edf5", fontFamily: "Outfit", fontSize: 12 }
};

function ScoreGauge({ score }) {
  const bounded = Math.max(0, Math.min(100, score));
  const risk = bounded > 75 ? "Low Risk" : bounded > 50 ? "Medium Risk" : "High Risk";
  const color = bounded > 75 ? "#00e5a0" : bounded > 50 ? "#ffb020" : "#ff3b5c";
  const ref = useECharts({
    series: [{
      type: "gauge", startAngle: 180, endAngle: 0, min: 0, max: 100, radius: "135%",
      center: ["50%", "90%"], pointer: { show: false },
      progress: { show: true, width: 20, roundCap: true, itemStyle: { color: {
        type: "linear", x: 0, y: 0, x2: 1, y2: 0,
        colorStops: [{ offset: 0, color: "#00E5A0" }, { offset: 0.5, color: "#FFB020" }, { offset: 1, color: "#FF3B5C" }]
      }}},
      axisLine: { lineStyle: { width: 20, color: [[1, AXIS_GREY]] } },
      axisTick: { show: false }, splitLine: { show: false }, axisLabel: { show: false },
      detail: { show: false }, data: [{ value: bounded }]
    }]
  }, [bounded]);
  return (
    <Panel title="Security Score">
      <div style={{ position: "relative" }}>
        <div ref={ref} style={{ height: 200 }} className="chart-box"></div>
        <div style={{ textAlign: "center", marginTop: -86 }}>
          <div style={{ fontSize: 40, fontWeight: 700, letterSpacing: "-.02em", lineHeight: 1 }}>{bounded}</div>
          <div style={{ fontSize: 13, color, marginTop: 2 }}>{risk}</div>
        </div>
      </div>
    </Panel>
  );
}

function CategoryBars({ data, title = "Category Scores" }) {
  const ref = useECharts({
    tooltip: { trigger: "axis", ...baseTooltip },
    grid: { left: 130, right: 28, top: 14, bottom: 14 },
    xAxis: { type: "value", max: 100, axisLabel: { color: "#8494b2", fontSize: 11 }, splitLine: { lineStyle: { color: AXIS_GREY } } },
    yAxis: { type: "category", data: data.map((d) => d.category), axisLine: { lineStyle: { color: AXIS_GREY } }, axisLabel: { color: "#8494b2", fontSize: 12 } },
    series: [{
      type: "bar", barWidth: 11,
      data: data.map((d) => ({ value: d.score, itemStyle: {
        borderRadius: [0, 4, 4, 0],
        color: d.score > 80 ? "#00E5A0" : d.score >= 60 ? "#FFB020" : "#FF3B5C"
      }}))
    }]
  }, [data]);
  return <Panel title={title}><div ref={ref} style={{ height: 244 }} className="chart-box"></div></Panel>;
}

function VolumeChart({ data, title = "Tool Call Volume", labels = ["Allow", "Block"] }) {
  const ref = useECharts({
    tooltip: { trigger: "axis", ...baseTooltip },
    legend: { data: labels, bottom: 0, textStyle: { color: "#8494b2", fontSize: 11 }, icon: "roundRect", itemWidth: 10, itemHeight: 10 },
    grid: { left: 36, right: 20, top: 16, bottom: 38 },
    xAxis: { type: "category", boundaryGap: false, data: data.map((d) => d.time), axisLine: { lineStyle: { color: AXIS_GREY } }, axisLabel: { color: "#8494b2", fontSize: 10, interval: 3 } },
    yAxis: { type: "value", axisLine: { show: false }, axisLabel: { color: "#8494b2", fontSize: 11 }, splitLine: { lineStyle: { color: AXIS_GREY } } },
    series: [
      { name: labels[0], data: data.map((d) => d.allow), type: "line", smooth: true, symbol: "none", areaStyle: { color: "#00E5A018" }, lineStyle: { color: "#00E5A0", width: 2 } },
      { name: labels[1], data: data.map((d) => d.block), type: "line", smooth: true, symbol: "none", areaStyle: { color: "#FF3B5C18" }, lineStyle: { color: "#FF3B5C", width: 2 } }
    ]
  }, [data]);
  return <Panel title={title}><div ref={ref} style={{ height: 230 }} className="chart-box"></div></Panel>;
}

function DonutChart({ data, title = "Trust Distribution" }) {
  const COLORS = { high: "#00E5A0", medium: "#FFB020", low: "#FF3B5C", frozen: "#4A5A78" };
  const fallback = ["#00E5A0", "#FFB020", "#FF3B5C", "#4A5A78"];
  const ref = useECharts({
    tooltip: { trigger: "item", ...baseTooltip },
    legend: { bottom: 0, textStyle: { color: "#8494b2", fontSize: 11 }, icon: "circle", itemWidth: 9 },
    series: [{
      name: title, type: "pie", radius: ["52%", "76%"], center: ["50%", "44%"], avoidLabelOverlap: false,
      itemStyle: { borderRadius: 6, borderColor: "#060B18", borderWidth: 3 },
      label: { show: true, color: "#e8edf5", fontSize: 11, formatter: "{c}" },
      data: data.map((it, i) => ({ ...it, itemStyle: { color: COLORS[it.name] || fallback[i % 4] } }))
    }]
  }, [data]);
  return <Panel title={title}><div ref={ref} style={{ height: 230 }} className="chart-box"></div></Panel>;
}

Object.assign(window, { ScoreGauge, CategoryBars, VolumeChart, DonutChart });
