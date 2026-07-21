// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// fleet-mgmt — the Agents page for a REMOTE cluster, rendered at the hub from the relayed AgentRollup
// (GET /fleet/agents). Read-only (trust mutations stay on the spoke's own console). Labeled with freshness.

import { useEffect, useState } from "react";
import { fetchFleetAgents, type FleetAgent } from "../../api/fleet";
import { PageHead } from "./PageHead";
import { Panel } from "./Panel";
import { FreshnessBadge } from "./ClusterScopedMonitor";

const CATEGORY_COLOR: Record<string, string> = {
  high: "var(--success,#30a46c)", medium: "var(--warning,#f5a623)", low: "var(--danger,#e5484d)", frozen: "var(--text-muted)"
};

export function RemoteAgents({ cluster, lastHeartbeat }: { cluster: string; lastHeartbeat: string | null }) {
  const [agents, setAgents] = useState<FleetAgent[]>([]);
  const [err, setErr] = useState(false);
  useEffect(() => {
    let live = true;
    fetchFleetAgents(cluster).then((a) => live && setAgents(a)).catch(() => live && setErr(true));
    return () => {
      live = false;
    };
  }, [cluster]);

  return (
    <div className="page-enter">
      <PageHead title="Agents" subtitle={`Showing: ${cluster} (hub view)`} />
      <FreshnessBadge lastHeartbeat={lastHeartbeat} />
      <Panel title={`Agents on ${cluster}`} sub="Relayed trust rollup — read-only at the hub">
        {err ? (
          <div style={{ padding: 16, color: "var(--text-muted)", fontSize: 13 }}>Could not load {cluster}'s agents from the hub.</div>
        ) : agents.length === 0 ? (
          <div style={{ padding: 16, color: "var(--text-muted)", fontSize: 13 }}>No agents relayed for {cluster} yet.</div>
        ) : (
          <table className="tbl">
            <thead>
              <tr><th>SPIFFE ID</th><th>Namespace</th><th>Class</th><th>Trust</th><th>Category</th><th>Last seen</th></tr>
            </thead>
            <tbody>
              {agents.map((a) => (
                <tr key={a.spiffe_id}>
                  <td className="mono" style={{ fontSize: 12 }}>{a.spiffe_id}</td>
                  <td className="mono">{a.namespace}</td>
                  <td className="mono">{a.agent_class}</td>
                  <td>{(a.trust_score ?? 0).toFixed(2)}</td>
                  <td style={{ color: CATEGORY_COLOR[(a.trust_category ?? "").toLowerCase()] ?? "var(--text-secondary)" }}>
                    {a.trust_category}
                  </td>
                  <td className="mono muted">{a.last_seen ? new Date(a.last_seen).toLocaleString() : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
