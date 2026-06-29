import { apiGet } from "../api/client";
import { useApi } from "../hooks/useApi";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

type Deployment = { name: string; namespace: string; agent_class: string };

// Read-only view of what policies can target in this namespace: the live namespaces (from the cluster
// selector) and the workloads observed for the active namespace (/deployments). No fabricated lists.
export function TargetSettings() {
  const { namespace, namespaces } = useApp();
  const deployments = useApi<Deployment[]>(
    () => apiGet<Deployment[]>(`/api/v1/deployments?namespace=${encodeURIComponent(namespace)}`),
    [namespace]
  );
  const rows = deployments.data ?? [];

  return (
    <div className="page-enter">
      <PageHead title="Target Settings" subtitle={`Showing: ${namespace}`} />
      <Panel title="Targetable Namespaces" sub="Namespaces a policy can be scoped to (live)">
        {namespaces.length === 0 ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>No namespaces discovered.</div>
        ) : (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {namespaces.map((ns) => (
              <span
                key={ns}
                className="mono"
                style={{ fontSize: 12, padding: "4px 10px", borderRadius: 6, background: "#1f1f1f" }}
              >
                {ns}
              </span>
            ))}
          </div>
        )}
      </Panel>
      <Panel title="Targetable Workloads" sub={`Workloads observed in "${namespace}" (live)`}>
        {deployments.loading ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>Loading…</div>
        ) : deployments.error ? (
          <div style={{ color: "var(--block)", fontSize: 13 }}>Could not load workloads.</div>
        ) : rows.length === 0 ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>No workloads observed in this namespace.</div>
        ) : (
          <table className="tbl">
            <thead>
              <tr>
                <th>Name</th>
                <th>Agent class</th>
                <th>Namespace</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={`${d.namespace}/${d.name}`}>
                  <td style={{ fontWeight: 500 }}>{d.name}</td>
                  <td className="mono">{d.agent_class}</td>
                  <td className="mono muted">{d.namespace}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
