export function AssetGraphLegend() {
  return (
    <div style={{ display: "flex", gap: 12, flexWrap: "wrap", fontSize: 12 }}>
      <span>agent</span>
      <span>tool</span>
      <span>data</span>
      <span>namespace</span>
      <span>allowed</span>
      <span>mixed</span>
      <span>blocked</span>
    </div>
  );
}
