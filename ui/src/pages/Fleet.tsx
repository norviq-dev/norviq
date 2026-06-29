// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Fleet overview (F045, P1 read-only): per-cluster status + aggregated agents + audit summaries across
// clusters, served by the fleet-api hub. Gated by VITE_FLEET_API_URL — single-cluster installs never see it.

import { useEffect, useState } from "react";
import { useApp } from "../store/AppContext";
import {
  fleetEnabled,
  fetchFleetAgents,
  fetchFleetAuditSummary,
  fetchFleetClusters,
  type FleetAgent,
  type FleetAuditSummary,
  type FleetCluster
} from "../api/fleet";

const cellStyle: React.CSSProperties = { padding: "8px 12px", borderBottom: "1px solid var(--border, #2a2a2a)", textAlign: "left" };

export function Fleet() {
  const { selectedCluster } = useApp();
  const cluster = selectedCluster && selectedCluster !== "local" ? selectedCluster : "all";
  const [clusters, setClusters] = useState<FleetCluster[]>([]);
  const [agents, setAgents] = useState<FleetAgent[]>([]);
  const [audit, setAudit] = useState<FleetAuditSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!fleetEnabled) return;
    let live = true;
    Promise.all([fetchFleetClusters(), fetchFleetAgents(cluster), fetchFleetAuditSummary("24h", cluster)])
      .then(([c, a, s]) => {
        if (!live) return;
        setClusters(c);
        setAgents(a);
        setAudit(s);
        setError(null);
      })
      .catch((e) => live && setError(String(e)));
    return () => {
      live = false;
    };
  }, [cluster]);

  if (!fleetEnabled) {
    return (
      <div style={{ padding: 24, color: "var(--text-secondary)" }}>
        Fleet view is not configured. Set <code>VITE_FLEET_API_URL</code> to a fleet-api hub to aggregate clusters.
      </div>
    );
  }

  const agentsByCluster = (cid: string) => agents.filter((a) => a.cluster_id === cid).length;
  const auditFor = (cid: string) => audit.find((s) => s.cluster_id === cid);

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 20, marginBottom: 4 }}>Fleet</h1>
      <p style={{ color: "var(--text-secondary)", marginBottom: 16 }}>
        Cross-cluster visibility (read-only). {clusters.length} cluster(s){cluster !== "all" ? `, filtered to ${cluster}` : ""}.
      </p>
      {error && <div style={{ color: "var(--danger, #e5484d)", marginBottom: 12 }}>Failed to load fleet data: {error}</div>}
      <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 13 }}>
        <thead>
          <tr>
            {["Cluster", "Region", "Status", "Last heartbeat", "Agents", "Allow (24h)", "Block (24h)"].map((h) => (
              <th key={h} style={{ ...cellStyle, color: "var(--text-secondary)", fontWeight: 600 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {clusters.map((c) => {
            const s = auditFor(c.id);
            return (
              <tr key={c.id}>
                <td style={cellStyle}>{c.name || c.id}</td>
                <td style={cellStyle}>{c.region || "—"}</td>
                <td style={{ ...cellStyle, color: c.status === "healthy" ? "var(--success, #30a46c)" : "var(--warning, #f5a623)" }}>
                  {c.status}
                </td>
                <td style={cellStyle}>{c.last_heartbeat ? new Date(c.last_heartbeat).toLocaleString() : "—"}</td>
                <td style={cellStyle}>{agentsByCluster(c.id)}</td>
                <td style={cellStyle}>{s?.allow ?? 0}</td>
                <td style={cellStyle}>{s?.block ?? 0}</td>
              </tr>
            );
          })}
          {clusters.length === 0 && !error && (
            <tr>
              <td style={{ ...cellStyle, color: "var(--text-secondary)" }} colSpan={7}>No clusters registered yet.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export default Fleet;
