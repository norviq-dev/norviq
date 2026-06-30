import { useEffect, useMemo, useState } from "react";
import { AttackGraphCanvas } from "../components/attack-graph/AttackGraphCanvas";
import { AttackPathDetail } from "../components/attack-graph/AttackPathDetail";
import { AttackPathList } from "../components/attack-graph/AttackPathList";
import { SimulateAttackButton } from "../components/attack-graph/SimulateAttackButton";
import type { AttackPath, AttackPathsResponse } from "../components/attack-graph/types";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";
import { apiSend, apiUrl } from "../api/client";

/** Derive the agent_class from a path's source node id (spiffe ".../sa/<class>" or "agent:<class>"). */
function agentClassFromSource(sourceId: string): string {
  const sa = sourceId.match(/\/sa\/([^/]+)/);
  if (sa) return sa[1];
  const parts = sourceId.split(":");
  return parts[parts.length - 1] || "unknown";
}

export function AttackGraph() {
  const { namespace } = useApp();
  const [data, setData] = useState<AttackPathsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState<string>("all");
  const [selected, setSelected] = useState<AttackPath | undefined>(undefined);
  const [recomputing, setRecomputing] = useState(false);

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
  }, [namespace, severity, recomputing]);

  // F-26: attack paths are PRECOMPUTED server-side (from the recorded asset graph) into the attack_paths table.
  // The page now offers an explicit recompute so an empty graph is not a silent dead-end.
  const recompute = async () => {
    setRecomputing(true);
    setError("");
    try {
      await apiSend(`/api/v1/attack-paths/compute?namespace=${encodeURIComponent(namespace)}`, "POST");
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Recompute failed");
    } finally {
      setRecomputing(false); // toggles the load effect to refetch
    }
  };

  const paths = useMemo(() => data?.paths ?? [], [data]);
  const criticalCount = paths.filter((p) => p.severity === "critical").length;
  const highCount = paths.filter((p) => p.severity === "high").length;

  // Make Simulate discoverable: auto-select the highest-risk path (API returns paths sorted desc).
  useEffect(() => {
    if (!selected && paths.length > 0) setSelected(paths[0]);
  }, [paths, selected]);

  // Run a REAL evaluation of the selected path: evaluate each actionable step as a tool call by
  // the source agent and report blocked from the live decision — an attacker is stopped if ANY
  // step blocks. (Not the precomputed blocked_by_policy flag.)
  const simulatePath = async (path: AttackPath): Promise<{ blocked: boolean }> => {
    const agentClass = agentClassFromSource(path.source_id);
    const agent_identity = {
      spiffe_id: `spiffe://norviq/ns/${namespace}/sa/${agentClass}`,
      namespace,
      agent_class: agentClass
    };
    const tools = path.steps.map((s) => s.action).filter((a) => a && a !== "traverse");
    const probes = tools.length > 0 ? tools : [path.target_id];
    let blocked = false;
    for (const tool of probes) {
      const res = await apiSend<{ decision: string }>("/api/v1/evaluate", "POST", {
        tool_name: tool,
        tool_params: {},
        agent_identity,
        session_id: `simulate-${path.path_id}`
      });
      if (res.decision === "block") {
        blocked = true;
        break;
      }
    }
    return { blocked };
  };

  if (loading) return <div>Loading attack graph...</div>;
  if (error) return <div>Failed to load attack graph: {error}</div>;
  if (!data || paths.length === 0) {
    return (
      <div className="page-enter">
        <PageHead title="Attack Graph" subtitle={`Showing: ${namespace}`} />
        <Panel title="No attack paths yet" sub="Attack paths are precomputed from the runtime asset graph">
          <p style={{ color: "var(--text-secondary)", maxWidth: 640 }}>
            Attack paths are derived server-side from the asset graph the engine records (agent → tool → data) and
            stored for this namespace. None are stored yet — either no critical agent→tool→data chains have been
            observed for <code>{namespace}</code>, or a recompute has not run. Recompute reads the latest recorded
            graph (source: <code>/api/v1/attack-paths/compute</code>).
          </p>
          <button onClick={recompute} disabled={recomputing}>
            {recomputing ? "Recomputing…" : "Recompute attack paths"}
          </button>
        </Panel>
      </div>
    );
  }

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
        <SimulateAttackButton path={selected} onSimulate={simulatePath} />
      </Panel>
    </div>
  );
}

export default AttackGraph;
