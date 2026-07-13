// Interop-safe re-export of echarts-for-react's core component.
// echarts-for-react is a CommonJS package (`module.exports = EChartsReactCore`). Under Vite 8 /
// Rolldown the default import binds the module NAMESPACE object (`{ default: Fn }`) rather than the
// component function, so rendering `<ReactEChartsCore>` throws React error #130 ("element type is
// invalid: got object"). Normalize the interop once here so every chart imports a real component.
import ReactEChartsCoreImport from "echarts-for-react/lib/core";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ReactEChartsCore = ((ReactEChartsCoreImport as any)?.default ??
  ReactEChartsCoreImport) as typeof ReactEChartsCoreImport;

export default ReactEChartsCore;
