import { useEffect, useMemo, useState } from "react";
import { AttackGraphCanvas } from "../components/attack-graph/AttackGraphCanvas";
import { AttackPathDetail } from "../components/attack-graph/AttackPathDetail";
import { AttackPathList } from "../components/attack-graph/AttackPathList";
import { SimulateAttackButton } from "../components/attack-graph/SimulateAttackButton";
import type { AttackPath, AttackPathsResponse } from "../components/attack-graph/types";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";
import { apiUrl } from "../api/client";

export function AttackGraph() {
  const { namespace } = useApp();
  const [data, setData] = useState<AttackPathsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState<string>("all");
  const [selected, setSelected] = useState<AttackPath | undefined>(undefined);

  useEffect(() => {
    let alive = true;
    const token = localStorage.getItem("nrvq_token");
    const query = severity === "all" ? "" : `&severity=${encodeURIComponent(severity)}`;
    setLoading(true);
    setError("");
    fetch(apiUrl(`/api/v1/attack-paths?namespace=${encodeURIComponent(namespace)}${query}`), {
      headers: token ? { Authorization: `Bearer ${token}` } : {}
    })
      .then(async (res) => {
        if (!res.ok) throw new Error(`Request failed: ${res.status}`);
        const json = (await res.json()) as AttackPathsResponse;
        if (alive) setData(json);
      })
      .catch((e: unknown) => {
        if (alive) setError(e instanceof Error ? e.message : "Failed to load");
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [namespace, severity]);

  const paths = useMemo(() => data?.paths ?? [], [data]);
  const criticalCount = paths.filter((p) => p.severity === "critical").length;
  const highCount = paths.filter((p) => p.severity === "high").length;

  if (loading) return <div>Loading attack graph...</div>;
  if (error) return <div>Failed to load attack graph: {error}</div>;
  if (!data || paths.length === 0) return <div>No attack paths found for this namespace.</div>;

  return (
    <div className="page-enter">
      <PageHead title="Attack Graph" subtitle={`Showing: ${namespace}`} />
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <div>Total: {paths.length}</div>
        <div>Critical: {criticalCount}</div>
        <div>High: {highCount}</div>
      </div>
      <label>
        Severity:
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="all">all</option>
          <option value="critical">critical</option>
          <option value="high">high</option>
          <option value="medium">medium</option>
          <option value="low">low</option>
        </select>
      </label>
      <Panel title="Threat Relationships" sub="Computed attack paths">
        <AttackGraphCanvas
          paths={paths}
          nodes={data.nodes}
          selectedPathId={selected?.path_id}
          onSelectPath={setSelected}
        />
        <AttackPathList paths={paths} selectedPathId={selected?.path_id} onSelect={setSelected} />
        <AttackPathDetail path={selected} />
        <SimulateAttackButton path={selected} onSimulate={async (path) => ({ blocked: path.blocked_by_policy })} />
      </Panel>
    </div>
  );
}

export default AttackGraph;
