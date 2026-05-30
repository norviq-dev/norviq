export function StatTile({ label, value, color }: { label: string; value: number; color?: string }) {
  return (
    <div className="panel panel-pad">
      <div className="kpi-label">{label}</div>
      <div
        style={{
          fontSize: 24,
          fontWeight: 600,
          marginTop: 6,
          color: color || "var(--text-primary)",
          fontVariantNumeric: "tabular-nums"
        }}
      >
        {value.toLocaleString()}
      </div>
    </div>
  );
}
