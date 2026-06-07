import type { AttackPath } from "./types";

type Props = {
  path?: AttackPath;
};

export function AttackPathDetail({ path }: Props) {
  if (!path) return <div>Select a path to view details.</div>;
  return (
    <div style={{ border: "1px solid #333", borderRadius: 8, padding: 10 }}>
      <div>Path: {path.path_id}</div>
      <div>Blocked by policy: {path.blocked_by_policy ? "Yes" : "No"}</div>
      {path.steps.map((step) => (
        <div key={`${path.path_id}-${step.step_num}`}>
          {step.step_num}. {step.action} ({step.policy_check})
        </div>
      ))}
    </div>
  );
}
