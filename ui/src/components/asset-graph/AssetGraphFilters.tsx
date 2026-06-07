import type { AssetNode } from "./types";

export type AssetGraphFiltersState = {
  types: AssetNode["type"][];
  riskLevels: Array<"low" | "medium" | "high" | "critical">;
  search: string;
};

type Props = {
  filters: AssetGraphFiltersState;
  onChange: (filters: AssetGraphFiltersState) => void;
};

const TYPES: AssetNode["type"][] = ["agent", "tool", "data", "namespace"];
const RISKS: AssetGraphFiltersState["riskLevels"] = ["low", "medium", "high", "critical"];

export function AssetGraphFilters({ filters, onChange }: Props) {
  const toggleType = (type: AssetNode["type"]) => {
    onChange({
      ...filters,
      types: filters.types.includes(type) ? filters.types.filter((t) => t !== type) : [...filters.types, type]
    });
  };
  const toggleRisk = (risk: "low" | "medium" | "high" | "critical") => {
    onChange({
      ...filters,
      riskLevels: filters.riskLevels.includes(risk)
        ? filters.riskLevels.filter((r) => r !== risk)
        : [...filters.riskLevels, risk]
    });
  };
  return (
    <div style={{ display: "grid", gap: 8 }}>
      <input placeholder="Search node name" value={filters.search} onChange={(e) => onChange({ ...filters, search: e.target.value })} />
      <div>
        {TYPES.map((type) => (
          <label key={type} style={{ marginRight: 10 }}>
            <input type="checkbox" checked={filters.types.includes(type)} onChange={() => toggleType(type)} /> {type}
          </label>
        ))}
      </div>
      <div>
        {RISKS.map((risk) => (
          <label key={risk} style={{ marginRight: 10 }}>
            <input type="checkbox" checked={filters.riskLevels.includes(risk)} onChange={() => toggleRisk(risk)} /> {risk}
          </label>
        ))}
      </div>
    </div>
  );
}
