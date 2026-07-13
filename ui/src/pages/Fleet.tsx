// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Fleet overview (F045): P1 per-cluster status + aggregated agents/audit; P2 signed policy-push authoring +
// per-cluster rollout status; P3 live drill-down into one cluster's audit (P4 residency may block it).
// Gated by VITE_FLEET_API_URL — single-cluster installs never see it.

import "../lib/monaco"; // SLIM-MONACO: bundle Monaco locally (no cdn.jsdelivr fetch) — must precede <Editor>
import Editor from "@monaco-editor/react";
import { useEffect, useState } from "react";
import { registerRego } from "../lib/monaco-rego";
import { ApplyResultPanel, type ApplyResult } from "../components/common/ApplyResultPanel";
import { useApp } from "../store/AppContext";
import {
  fleetEnabled,
  authorFleetPolicy,
  fetchFleetAuditSummary,
  fetchFleetClusters,
  fetchFleetDrilldown,
  fetchFleetPolicies,
  fetchFleetRollout,
  mintJoinToken,
  removeCluster,
  retractFleetPolicy,
  type FleetAuditRecord,
  type FleetAuditSummary,
  type FleetCluster,
  type FleetPolicyRow,
  type FleetRollout,
  type JoinTokenResult
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
  const [selector, setSelector] = useState('{"env":"prod"}');  // F-33: sane default target (was empty -> 422)
  const [confirmFleetWide, setConfirmFleetWide] = useState(false);  // F-40: explicit confirm for a fleet-wide push
  const [pushMsg, setPushMsg] = useState<string | null>(null);
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null);  // Stage 1: apply-result transparency panel
  const [policies, setPolicies] = useState<FleetPolicyRow[]>([]);  // F-52: pushed policies (retractable)
  // Single-cluster-first enrollment: add (mint join token) + remove cluster.
  const [addOpen, setAddOpen] = useState(false);
  const [joinCid, setJoinCid] = useState("");
  const [joinHub, setJoinHub] = useState("");
  const [joinResult, setJoinResult] = useState<JoinTokenResult | null>(null);
  const [addMsg, setAddMsg] = useState<string | null>(null);

  const mint = async () => {
    setAddMsg(null);
    try {
      setJoinResult(await mintJoinToken(joinCid.trim(), joinHub.trim()));
    } catch (e) {
      setAddMsg(`Mint failed: ${String(e).replace(/^Error:\s*/, "")}`);
    }
  };
  const remove = async (id: string) => {
    setPushMsg(null);
    try {
      await removeCluster(id);
      setPushMsg(`Removed "${id}" from the hub. Run \`norviq fleet leave\` on it to stop pulling.`);
      reload();
    } catch (e) {
      setPushMsg(`Remove failed: ${String(e).replace(/^Error:\s*/, "")}`);
    }
  };

  const reload = () => {
    Promise.all([fetchFleetClusters(), fetchFleetAuditSummary("24h", cluster), fetchFleetRollout(), fetchFleetPolicies()])
      .then(([c, a, r, p]) => { setClusters(c); setAudit(a); setRollout(r); setPolicies(p); setError(null); })
      .catch((e) => setError(String(e)));
  };

  // F-52: retract a pushed policy — it leaves every cluster's bundle and each spoke reconciles on next pull.
  const retract = async (pname: string) => {
    setPushMsg(null);
    try {
      await retractFleetPolicy(pname);
      // Stage 1: show the retract outcome + watch each spoke reconcile (F-52) back via the rollout poll.
      setApplyResult({
        kind: "fleet",
        title: `Retracted "${pname}"`,
        ok: true,
        outcome: `Removed from the hub. It leaves every targeted cluster's bundle; each spoke reconciles (deletes the dropped policy) on its next pull (≤1 interval).`,
        manifest: { name: pname, namespace: "—", agent_class: "—" },
        fleetPolicyName: pname
      });
      reload();
    } catch (e) {
      setPushMsg(`Retract failed: ${String(e).replace(/^Error:\s*/, "")}`);
    }
  };
  useEffect(() => { if (fleetEnabled) reload(); /* eslint-disable-next-line */ }, [cluster]);

  // F-56: close the drilldown with Esc (in addition to the ✕ button and the backdrop click).
  useEffect(() => {
    if (!drill) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setDrill(null); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [drill]);

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
    // F-33: client-side validation — no request fires on an empty/invalid form; surface the server's detail otherwise.
    if (!name.trim()) { setPushMsg("policy name required"); return; }
    if (!agentClass.trim()) { setPushMsg("agent_class required (a specific class, not a managed scope)"); return; }
    // F-40: baseline/pack scopes are managed per-cluster — never fleet-pushed (fail fast; the server also 422s).
    if (agentClass === "__baseline__" || agentClass === "__pack__") {
      setPushMsg(`'${agentClass}' is managed per-cluster — change a baseline via its seed and packs via the packs API, not fleet push.`);
      return;
    }
    let target: Record<string, string> = {};
    if (selector.trim()) {
      try { target = JSON.parse(selector); } catch { setPushMsg("target must be JSON, e.g. {\"env\":\"prod\"}"); return; }
    }
    if (Object.keys(target).length === 0) { setPushMsg("target required, e.g. {\"env\":\"prod\"} or {\"cluster_id\":\"fleet-a\"}"); return; }
    // F-40: a fleet-wide target (no cluster_id) requires explicit confirmation.
    const fleetWide = !target.cluster_id;
    if (fleetWide && !confirmFleetWide) { setPushMsg("this target matches more than one cluster — tick “Confirm fleet-wide push”."); return; }
    try {
      const res = await authorFleetPolicy({ name, namespace: ns, agent_class: agentClass, rego_source: rego, target_selector: target, confirm_fleet_wide: confirmFleetWide });
      setPushMsg(null);
      // Stage 1: the apply-result panel shows the exact manifest + honest outcome + LIVE propagation (rollout poll).
      setApplyResult({
        kind: "fleet",
        title: `Fleet policy "${res.name}" v${res.version} published`,
        ok: true,
        outcome: `Authored at the hub + signed (RS256). Distributed as a signed bundle — each targeted spoke verifies the signature and applies it on its next pull (≤1 interval).`,
        manifest: { name: res.name, namespace: ns, agent_class: agentClass, target_selector: target, rego },
        fleetPolicyName: res.name,
        targetClusters: target.cluster_id ? [target.cluster_id] : undefined
      });
      reload();
    } catch (e) {
      const msg = String(e).replace(/^Error:\s*/, "");
      const codeMatch = msg.match(/NRVQ-[A-Z]+-\d+/);
      setApplyResult({
        kind: "fleet",
        title: "Push rejected",
        ok: false,
        outcome: msg.includes("403") ? "admin role required" : msg,
        code: codeMatch ? codeMatch[0] : undefined,
        manifest: { name, namespace: ns, agent_class: agentClass, target_selector: target, rego }
      });
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
      {/* F-59: the ONE cluster selector is the global nav dropdown (top-left) — switching it repoints this view. */}
      <p style={{ color: "var(--text-secondary)", marginBottom: 16 }}>
        Cross-cluster management (read + signed policy push). {clusters.length} cluster(s).
        {" "}Showing: <strong>{cluster === "all" ? "all clusters" : cluster}</strong> — switch via the cluster menu (top-left).
      </p>
      {error && <div style={{ color: "var(--danger, #e5484d)", marginBottom: 12 }}>Failed to load: {error}</div>}

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", margin: "8px 0" }}>
        <h2 style={{ fontSize: 15 }}>Clusters &amp; rollout</h2>
        <button className="btn btn-outline" style={{ fontSize: 13 }} onClick={() => { setAddOpen(true); setJoinResult(null); }}>+ Add cluster</button>
      </div>
      <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 13, marginBottom: 24 }}>
        <thead>
          <tr>{["Cluster", "Region", "Status", "Allow 24h", "Block 24h", "Bundle", "Rollout", "", ""].map((h, i) => (
            <th key={i} style={{ ...cell, color: "var(--text-secondary)", fontWeight: 600 }}>{h}</th>
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
                <td style={cell}><button onClick={() => remove(c.id)} style={{ fontSize: 12, color: "var(--danger, #e5484d)" }}>Remove</button></td>
              </tr>
            );
          })}
          {clusters.length === 0 && !error && (
            <tr><td style={{ ...cell, color: "var(--text-secondary)" }} colSpan={9}>No clusters registered yet — use “Add cluster” to mint a join token.</td></tr>
          )}
        </tbody>
      </table>

      {addOpen && (
        <>
          <div onClick={() => setAddOpen(false)} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 30 }} />
          <div style={{ position: "fixed", top: "12%", left: "50%", transform: "translateX(-50%)", width: 620, maxWidth: "94vw", background: "var(--bg, #111)", border: "1px solid var(--border,#2a2a2a)", borderRadius: 12, padding: 18, zIndex: 31 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <h3 style={{ fontSize: 15 }}>Add a cluster</h3>
              <button onClick={() => setAddOpen(false)}>✕</button>
            </div>
            <p style={{ color: "var(--text-secondary)", fontSize: 12, marginBottom: 12 }}>
              Mint a short-lived join token. On the NEW cluster (a plain single-cluster install) run the command below — one action, no Helm wiring.
            </p>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
              <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--text-secondary)" }}>
                New cluster id
                <input className="input" value={joinCid} onChange={(e) => setJoinCid(e.target.value)} placeholder="fleet-d" />
              </label>
              <label style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--text-secondary)" }}>
                Hub URL (spoke-reachable)
                <input className="input" value={joinHub} onChange={(e) => setJoinHub(e.target.value)} placeholder="http://hub-host:31090" />
              </label>
            </div>
            <button className="btn btn-primary" disabled={!joinCid.trim() || !joinHub.trim()} onClick={mint}>Mint join token</button>
            {addMsg && <div style={{ color: "var(--danger,#e5484d)", fontSize: 12, marginTop: 8 }}>{addMsg}</div>}
            {joinResult && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>Run this on the new cluster (expires {new Date(joinResult.expires_at).toLocaleTimeString()}):</div>
                <div style={{ display: "flex", gap: 8 }}>
                  <code style={{ flex: 1, fontSize: 11, padding: "8px 10px", background: "var(--bg-elevated,#161616)", border: "1px solid var(--border)", borderRadius: 6, overflow: "auto", whiteSpace: "nowrap" }}>{joinResult.join_command}</code>
                  <button className="btn btn-outline" style={{ fontSize: 12 }} onClick={() => navigator.clipboard.writeText(joinResult.join_command)}>Copy</button>
                </div>
              </div>
            )}
          </div>
        </>
      )}

      <h2 style={{ fontSize: 15, margin: "8px 0" }}>Push signed policy</h2>
      <p style={{ color: "var(--text-secondary)", fontSize: 12, marginBottom: 8 }}>
        Authored on the hub, signed, distributed to matching clusters; each spoke verifies the signature before applying. Admin only.
      </p>
      {/* F-60: real, visible form — labels ABOVE each field, themed `.input` (borders/background/focus). */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12, marginBottom: 12 }}>
        {([
          { lab: "Policy name", v: name, set: setName, ph: "block-drop-table" },
          { lab: "Namespace", v: ns, set: setNs, ph: "default" },
          { lab: "Agent class", v: agentClass, set: setAgentClass, ph: "customer-support" },
          { lab: "Target", v: selector, set: setSelector, ph: '{"cluster_id":"fleet-a"}' }
        ] as const).map((f) => (
          <label key={f.lab} style={{ display: "flex", flexDirection: "column", gap: 4, fontSize: 12, color: "var(--text-secondary)" }}>
            {f.lab}
            <input className="input" value={f.v} onChange={(e) => f.set(e.target.value)} placeholder={f.ph} />
          </label>
        ))}
      </div>
      {/* F-40: confirm a fleet-wide push (a target with no cluster_id matches more than one cluster). */}
      <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)", marginBottom: 8 }}>
        <input type="checkbox" checked={confirmFleetWide} onChange={(e) => setConfirmFleetWide(e.target.checked)} />
        Confirm fleet-wide push (target matches more than one cluster). Not needed for a single <code>cluster_id</code> target.
      </label>
      <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>Rego policy</div>
      <div style={{ border: "1px solid var(--border)", borderRadius: 8, overflow: "hidden" }}>
        <Editor height="280px" defaultLanguage="rego" theme="vs-dark" value={rego} beforeMount={registerRego}
          onChange={(v) => setRego(v ?? "")} options={{ minimap: { enabled: false }, fontSize: 12.5 }} />
      </div>
      <div style={{ marginTop: 10, display: "flex", alignItems: "center", gap: 12 }}>
        <button className="btn btn-primary" onClick={push}>Push signed policy</button>
        {pushMsg && <span style={{ color: "var(--text-secondary)", fontSize: 13 }}>{pushMsg}</span>}
      </div>
      {/* Stage 1: the apply-result panel — exact manifest + honest outcome + live propagation (push AND retract). */}
      <ApplyResultPanel result={applyResult} onClose={() => setApplyResult(null)} />

      {/* F-52: pushed policies are retractable — retract removes it from every cluster's bundle; spokes reconcile. */}
      <h2 style={{ fontSize: 15, margin: "24px 0 8px" }}>Pushed policies</h2>
      <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 13, marginBottom: 24 }}>
        <thead>
          <tr>{["Name", "Namespace", "Agent class", "Target", "Mode", "v", ""].map((h) => (
            <th key={h} style={{ ...cell, color: "var(--text-secondary)", fontWeight: 600 }}>{h}</th>
          ))}</tr>
        </thead>
        <tbody>
          {policies.map((p) => (
            <tr key={p.name}>
              <td style={cell}>{p.name}</td>
              <td style={cell}>{p.namespace}</td>
              <td style={cell}>{p.agent_class}</td>
              <td style={{ ...cell, fontFamily: "var(--font-mono)" }}>{JSON.stringify(p.target_selector ?? {})}</td>
              <td style={cell}>{p.enforcement_mode}</td>
              <td style={cell}>{p.version}</td>
              <td style={cell}>
                <button onClick={() => retract(p.name)} style={{ fontSize: 12, color: "var(--danger, #e5484d)" }}>Retract</button>
              </td>
            </tr>
          ))}
          {policies.length === 0 && (
            <tr><td style={{ ...cell, color: "var(--text-secondary)" }} colSpan={7}>No fleet policies pushed.</td></tr>
          )}
        </tbody>
      </table>

      {drill && (() => {
        const s = auditFor(drill.cluster); const ro = rolloutFor(drill.cluster);
        const c = clusters.find((x) => x.id === drill.cluster);
        const total = s?.total ?? 0; const blk = s?.block ?? 0;
        const blockRate = total ? Math.round((blk / total) * 100) : 0;
        const denials = drill.records.filter((r) => r.decision === "block" || r.decision === "escalate");
        const stat: React.CSSProperties = { padding: "8px 10px", border: "1px solid var(--border,#2a2a2a)", borderRadius: 8, flex: 1, minWidth: 100 };
        return (
        <>
          {/* F-56: backdrop — click outside closes the panel. */}
          <div onClick={() => setDrill(null)} style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.45)", zIndex: 30 }} />
          <div style={{ position: "fixed", right: 0, top: 0, bottom: 0, width: 520, maxWidth: "94vw", background: "var(--bg, #111)", borderLeft: "1px solid var(--border,#2a2a2a)", padding: 16, overflow: "auto", zIndex: 31 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h3 style={{ fontSize: 14 }}>
              {c?.name || drill.cluster}{" "}
              <span style={{ fontSize: 12, color: c?.status === "healthy" ? "var(--success,#30a46c)" : "var(--warning,#f5a623)" }}>● {c?.status ?? "—"}</span>
            </h3>
            <button onClick={() => setDrill(null)}>✕</button>
          </div>
          {drill.blocked ? (
            <p style={{ color: "var(--warning,#f5a623)", fontSize: 13 }}>Residency: this cluster keeps raw logs in-cluster. Drill-down is disabled.</p>
          ) : (
            <>
              {/* F-56: decision-grade summary — block rate, bundle/rollout, recent denials (not just the table row). */}
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap", margin: "12px 0", fontSize: 12 }}>
                <div style={stat}><div style={{ color: "var(--text-secondary)" }}>Block rate 24h</div><div style={{ fontSize: 18, fontWeight: 600 }}>{blockRate}%</div><div style={{ color: "var(--text-muted)" }}>{blk}/{total}</div></div>
                <div style={stat}><div style={{ color: "var(--text-secondary)" }}>Bundle</div><div style={{ fontSize: 18, fontWeight: 600 }}>v{ro?.bundle_version ?? 0}</div><div style={{ color: STATE_COLOR[ro?.state ?? "pending"] }}>{ro?.state ?? "—"}</div></div>
                <div style={stat}><div style={{ color: "var(--text-secondary)" }}>Region</div><div style={{ fontSize: 14, fontWeight: 600, marginTop: 4 }}>{c?.region || "—"}</div></div>
              </div>
              <h4 style={{ fontSize: 12, color: "var(--text-secondary)", margin: "10px 0 4px" }}>Recent denials ({denials.length})</h4>
              <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 12 }}>
                <thead><tr>{["Decision", "Tool", "Rule", "Agent"].map((h) => <th key={h} style={{ ...cell, color: "var(--text-secondary)" }}>{h}</th>)}</tr></thead>
                <tbody>
                {denials.map((r, i) => (
                  <tr key={i}>
                    <td style={{ ...cell, color: r.decision === "block" ? "var(--danger,#e5484d)" : "var(--warning,#f5a623)" }}>{r.decision}</td>
                    <td style={cell}>{r.tool_name}</td>
                    <td style={{ ...cell, fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>{r.rule_id || "—"}</td>
                    <td style={cell}>{r.agent_class || "—"}</td>
                  </tr>
                ))}
                {denials.length === 0 && <tr><td style={cell} colSpan={4}>No denials in the recent window.</td></tr>}
              </tbody>
            </table>
            </>
          )}
          </div>
        </>
        );
      })()}
    </div>
  );
}

export default Fleet;
