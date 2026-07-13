// SPDX-License-Identifier: Apache-2.0
// Native ECharts React wrapper — the single interop point every chart renders through.
//
// Previously this re-exported `echarts-for-react/lib/core`, but that package transitively pulls in
// `size-sensor`, whose maintainer npm account was compromised in the May 2026 "Mini Shai-Hulud"
// supply-chain campaign (malicious versions 1.0.4/1.1.4/1.2.4; `echarts-for-react` itself shipped
// malicious 3.0.7/3.1.7/3.2.7). Our resolved `size-sensor@1.0.3` predates the payload and is clean,
// but the whole family is a standing supply-chain risk (a `^` bump could pull a poisoned sibling), so
// we drop `echarts-for-react` entirely and cover the four props this codebase actually uses
// (`echarts`, `option`, `style`, `className`) with a native `ResizeObserver` instead of size-sensor.
//
// Kept as a plain function component with a default export named `ReactEChartsCore` so the four chart
// callers are unchanged, and so the UI-1 interop regression guard (`typeof === "function"`) holds.
import { useEffect, useRef } from "react";
import type * as EChartsCore from "echarts/core";

export interface EChartProps {
  echarts: typeof EChartsCore;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  option: Record<string, any>;
  style?: React.CSSProperties;
  className?: string;
}

export default function ReactEChartsCore({ echarts, option, style, className }: EChartProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const chartRef = useRef<EChartsCore.ECharts | null>(null);

  // Init once (and re-init only if the echarts module instance itself changes). A ResizeObserver keeps
  // the chart sized to its container — the job echarts-for-react used size-sensor for.
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const chart = echarts.init(el);
    chartRef.current = chart;
    const ro = new ResizeObserver(() => chart.resize());
    ro.observe(el);
    return () => {
      ro.disconnect();
      chart.dispose();
      chartRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [echarts]);

  // Apply option updates (notMerge=true, matching echarts-for-react's default for full re-renders).
  useEffect(() => {
    chartRef.current?.setOption(option, true);
  }, [option]);

  return <div ref={containerRef} style={style} className={className} />;
}
