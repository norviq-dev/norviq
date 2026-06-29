// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Fleet overview (F045): P1 per-cluster status + aggregated agents/audit; P2 signed policy-push authoring +
// per-cluster rollout status; P3 live drill-down into one cluster's audit (P4 residency may block it).
// Gated by VITE_FLEET_API_URL — single-cluster installs never see it.

import Editor from "@monaco-editor/react";
import { useEffect, useState } from "react";
import { useApp } from "../store/AppContext";
import {
  fleetEnabled,
  authorFleetPolicy,
  fetchFleetAuditSummary,
  fetchFleetClusters,
  fetchFleetDrilldown,
  fetchFleetRollout,
  type FleetAuditRecord,
  type FleetAuditSummary,
  type FleetCluster,
  type FleetRollout
} from "../api/fleet";

const cell: React.CSSProperties = { padding: "8px 12px", borderBottom: "1px solid var(--border, #2a2a2a)", textAlign: "left" };
const STATE_COLOR: Record<string, string> = {
  applied: "var(--success, #30a46c)", pending: "var(--text-secondary)",
  failed: "var(--danger, #e5484d)", diverged: "var(--warning, #f5a623)"
};

const DEFAULT_REGO = `package norviq.fleetpush

default decision = "allow"
decision = "block" { input.tool_name == "drop_table" }
rule_id = "fleet_block" { decision == "block" }
reason = "blocked by fleet policy" { decision == "block" }
`;

export function Fleet() {
  const { selectedCluster } = useApp();
  const cluster = selectedCluster && selectedCluster !== "local" ? selectedCluster : "all";
  const [clusters, setClusters] = useState<FleetCluster[]>([]);
  const [audit, setAudit] = useState<FleetAuditSummary[]>([]);
  const [rollout, setRollout] = useState<FleetRollout[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [drill, setDrill] = useState<{ cluster: string; records: FleetAuditRecord[]; blocked?: boolean } | null>(null);

  // policy authoring form
  const [rego, setRego] = useState(DEFAULT_REGO);
  const [name, setName] = useState("");
  const [ns, setNs] = useState("default");
  const [agentClass, setAgentClass] = useState("");
  const [selector, setSelector] = useState("");
  const [pushMsg, setPushMsg] = useState<string | null>(null);

  const reload = () => {
    Promise.all([fetchFleetClusters(), fetchFleetAuditSummary("24h", cluster), fetchFleetRollout()])
      .then(([c, a, r]) => { setClusters(c); setAudit(a); setRollout(r); setError(null); })
      .catch((e) => setError(String(e)));
  };
  useEffect(() => { if (fleetEnabled) reload(); /* eslint-disable-next-line */ }, [cluster]);

  if (!fleetEnabled) {
    return (
      <div style={{ padding: 24, color: "var(--text-secondary)" }}>
        Fleet view is not configured. Set <code>VITE_FLEET_API_URL</code> to a fleet-api hub to manage clusters.
      </div>
    );
  }

  const rolloutFor = (cid: string) => rollout.find((r) => r.cluster_id === cid);
  const auditFor = (cid: string) => audit.find((s) => s.cluster_id === cid);

  const push = async () => {
    setPushMsg(null);
    let target: Record<string, string> = {};
    if (selector.trim()) {
      try { target = JSON.parse(selector); } catch { setPushMsg("selector must be JSON, e.g. {\"env\":\"prod\"}"); return; }
    }
    try {
      const res = await authorFleetPolicy({ name, namespace: ns, agent_class: agentClass, rego_source: rego, target_selector: target });
      setPushMsg(`Signed policy "${res.name}" v${res.version} published — clusters will pull + verify + apply.`);
      reload();
    } catch (e) {
      setPushMsg(`Push failed (${String(e).includes("403") ? "admin role required" : String(e)})`);
    }
  };

  const openDrill = async (cid: string) => {
    try {
      const d = await fetchFleetDrilldown(cid);
      setDrill({ cluster: cid, records: d.records ?? [], blocked: d.residency_blocked });
    } catch (e) {
      setDrill({ cluster: cid, records: [], blocked: false });
      setError(String(e));
    }
  };

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ fontSize: 20, marginBottom: 4 }}>Fleet</h1>
      <p style={{ color: "var(--text-secondary)", marginBottom: 16 }}>
        Cross-cluster management (read + signed policy push). {clusters.length} cluster(s).
      </p>
      {error && <div style={{ color: "var(--danger, #e5484d)", marginBottom: 12 }}>Failed to load: {error}</div>}

      <h2 style={{ fontSize: 15, margin: "8px 0" }}>Clusters &amp; rollout</h2>
      <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 13, marginBottom: 24 }}>
        <thead>
          <tr>{["Cluster", "Region", "Status", "Allow 24h", "Block 24h", "Bundle", "Rollout", ""].map((h) => (
            <th key={h} style={{ ...cell, color: "var(--text-secondary)", fontWeight: 600 }}>{h}</th>
          ))}</tr>
        </thead>
        <tbody>
          {clusters.map((c) => {
            const s = auditFor(c.id); const ro = rolloutFor(c.id);
            return (
              <tr key={c.id}>
                <td style={cell}>{c.name || c.id}</td>
                <td style={cell}>{c.region || "—"}</td>
                <td style={{ ...cell, color: c.status === "healthy" ? "var(--success, #30a46c)" : "var(--warning, #f5a623)" }}>{c.status}</td>
                <td style={cell}>{s?.allow ?? 0}</td>
                <td style={cell}>{s?.block ?? 0}</td>
                <td style={cell}>v{ro?.bundle_version ?? 0}</td>
                <td style={{ ...cell, color: STATE_COLOR[ro?.state ?? "pending"] }}>{ro?.state ?? "—"}</td>
                <td style={cell}><button onClick={() => openDrill(c.id)} style={{ fontSize: 12 }}>Drill down</button></td>
              </tr>
            );
          })}
          {clusters.length === 0 && !error && (
            <tr><td style={{ ...cell, color: "var(--text-secondary)" }} colSpan={8}>No clusters registered yet.</td></tr>
          )}
        </tbody>
      </table>

      <h2 style={{ fontSize: 15, margin: "8px 0" }}>Push signed policy</h2>
      <p style={{ color: "var(--text-secondary)", fontSize: 12, marginBottom: 8 }}>
        Authored on the hub, signed, distributed to matching clusters; each spoke verifies the signature before applying. Admin only.
      </p>
      <div style={{ display: "flex", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="policy name" style={{ flex: 1, minWidth: 120 }} />
        <input value={ns} onChange={(e) => setNs(e.target.value)} placeholder="namespace" style={{ width: 120 }} />
        <input value={agentClass} onChange={(e) => setAgentClass(e.target.value)} placeholder="agent_class" style={{ width: 140 }} />
        <input value={selector} onChange={(e) => setSelector(e.target.value)} placeholder='target {"env":"prod"} or {"cluster_id":"fleet-a"}' style={{ flex: 1, minWidth: 200 }} />
      </div>
      <Editor height="280px" defaultLanguage="rego" theme="vs-dark" value={rego}
        onChange={(v) => setRego(v ?? "")} options={{ minimap: { enabled: false }, fontSize: 12.5 }} />
      <div style={{ marginTop: 8 }}>
        <button onClick={push}>Push policy</button>
        {pushMsg && <span style={{ marginLeft: 12, color: "var(--text-secondary)" }}>{pushMsg}</span>}
      </div>

      {drill && (
        <div style={{ position: "fixed", right: 0, top: 0, bottom: 0, width: 480, background: "var(--bg, #111)", borderLeft: "1px solid var(--border,#2a2a2a)", padding: 16, overflow: "auto" }}>
          <div style={{ display: "flex", justifyContent: "space-between" }}>
            <h3 style={{ fontSize: 14 }}>Live audit — {drill.cluster}</h3>
            <button onClick={() => setDrill(null)}>✕</button>
          </div>
          {drill.blocked ? (
            <p style={{ color: "var(--warning,#f5a623)", fontSize: 13 }}>Residency: this cluster keeps raw logs in-cluster. Drill-down is disabled.</p>
          ) : (
            <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 12 }}>
              <tbody>
                {drill.records.map((r, i) => (
                  <tr key={i}><td style={cell}>{r.decision}</td><td style={cell}>{r.tool_name}</td><td style={cell}>{r.namespace}</td></tr>
                ))}
                {drill.records.length === 0 && <tr><td style={cell} colSpan={3}>No records.</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

export default Fleet;
