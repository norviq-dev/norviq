import { memo, useEffect, useState } from "react";

function useCountUp(value: number, ms = 500) {
  const [v, setV] = useState(0);
  useEffect(() => {
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const p = Math.min((now - start) / ms, 1);
      setV(Math.round(value * p));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value, ms]);
  return v;
}

export const KPICard = memo(function KPICard({
  label,
  value,
  trend,
  color = "var(--accent)"
}: {
  label: string;
  value: number;
  trend: string;
  color?: string;
}) {
  const display = useCountUp(value);
  return (
    <div
      className="panel kpi"
      style={{
        background: "var(--bg-surface)",
        boxShadow: "var(--shadow-card)"
      }}
    >
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{display.toLocaleString()}</div>
      <div className="kpi-trend" style={{ color }}>
        {trend}
      </div>
    </div>
  );
});
