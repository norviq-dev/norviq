import type { AttackPath } from "./types";

type Props = {
  paths: AttackPath[];
  selectedPathId?: string;
  onSelect: (path: AttackPath) => void;
};

export function AttackPathList({ paths, selectedPathId, onSelect }: Props) {
  return (
    <div style={{ display: "grid", gap: 6 }}>
      {paths.map((path) => (
        <button key={path.path_id} onClick={() => onSelect(path)} style={{ textAlign: "left", border: selectedPathId === path.path_id ? "2px solid #7C5CFC" : "1px solid #333", borderRadius: 8, padding: 8 }}>
          {path.path_id} - {path.severity} - {path.risk_score.toFixed(2)}
        </button>
      ))}
    </div>
  );
}
