import { useState } from "react";
import type { AttackPath } from "./types";

type Props = {
  path?: AttackPath;
  onSimulate: (path: AttackPath) => Promise<{ blocked: boolean }>;
};

export function SimulateAttackButton({ path, onSimulate }: Props) {
  const [message, setMessage] = useState<string>("");
  const [running, setRunning] = useState(false);
  const handleClick = async () => {
    if (!path) return;
    setRunning(true);
    try {
      const result = await onSimulate(path);
      setMessage(result.blocked ? "Simulation blocked by policy." : "Simulation found a policy gap.");
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Simulation failed");
    } finally {
      setRunning(false);
    }
  };
  return (
    <div>
      <button onClick={handleClick} disabled={!path || running}>
        {running ? "Simulating..." : "Simulate Attack"}
      </button>
      {message && <div>{message}</div>}
    </div>
  );
}
