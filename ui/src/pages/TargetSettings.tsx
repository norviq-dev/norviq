// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// F-58: repurposed from a read-only namespaces/workloads list into "Effective Policy & Governance" — the one
// place that answers "what is actually governing this target right now": the effective policy LAYER STACK per
// agent-class (derived from the real evaluator, never re-implemented) + the namespace governance controls
// (enforcement mode, the F-51 apply-mode, and which sector packs are applied).

import { useEffect, useMemo, useState } from "react";
import {
  apiGet,
  fetchEffectivePolicy,
  fetchMe,
  fetchPolicyPacks,
  fetchSettings,
  saveSettings,
  type EffectiveLayer
} from "../api/client";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";

type PolicyRow = { agent_class: string; target_type: string };

export function TargetSettings() {
  const { namespace } = useApp();
  const me = useApi(() => fetchMe(), []);
  const isAdmin = me.data?.role === "admin";

  const policies = useApi<PolicyRow[]>(
    () => apiGet<PolicyRow[]>(`/api/v1/policies?namespace=${encodeURIComponent(namespace)}`),
    [namespace]
  );
  const settings = useApi(() => fetchSettings(namespace), [namespace], { cacheKey: `tgt-settings:${namespace}`, staleTimeMs: 15_000 });
  const packs = useApi(() => fetchPolicyPacks(namespace), [namespace], { cacheKey: `tgt-packs:${namespace}`, staleTimeMs: 15_000 });

  // agent-class targets (exclude the reserved overlay scopes — they show up as layers, not as targets)
  const classes = useMemo(
    () => (policies.data ?? []).filter((p) => p.target_type === "class" && !p.agent_class.startsWith("__")).map((p) => p.agent_class),
    [policies.data]
  );
  const [agentClass, setAgentClass] = useState("");
  useEffect(() => { if (classes.length && !classes.includes(agentClass)) setAgentClass(classes[0]); }, [classes, agentClass]);

  const [layers, setLayers] = useState<EffectiveLayer[]>([]);
  const [effErr, setEffErr] = useState<string | null>(null);
  useEffect(() => {
    if (!agentClass) { setLayers([]); return; }
    fetchEffectivePolicy(namespace, agentClass)
      .then((r) => { setLayers(r.layers); setEffErr(null); })
      .catch((e) => { setLayers([]); setEffErr(String(e)); });
  }, [namespace, agentClass]);

  const applyMode = settings.data?.apply_mode === "dry_run_only" ? "dry_run_only" : "enforce";
  const [savingMode, setSavingMode] = useState(false);
  const [modeMsg, setModeMsg] = useState<string | null>(null);
  const setMode = async (m: "enforce" | "dry_run_only") => {
    setSavingMode(true); setModeMsg(null);
    try { await saveSettings(namespace, { apply_mode: m }); await settings.refetch(); setModeMsg(`Apply mode: ${m}`); }
    catch (e) { setModeMsg(`Failed: ${(e instanceof Error ? e.message : String(e)).replace(/^Error:\s*/, "")}`); }
    finally { setSavingMode(false); }
  };

  const enabledPacks = (packs.data ?? []).filter((p) => p.enabled);
  const cell: React.CSSProperties = { padding: "8px 12px", borderBottom: "1px solid var(--border, #2a2a2a)", textAlign: "left" };

  return (
    <div className="page-enter">
      <PageHead title="Effective Policy & Governance" subtitle={`Namespace: ${namespace}`} />

      <Panel title="Governance" sub="How this namespace is governed right now (server-enforced).">
        <div style={{ display: "flex", gap: 24, flexWrap: "wrap", alignItems: "flex-start" }}>
          <div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>Enforcement mode</div>
            <div className="mono" style={{ fontSize: 16, fontWeight: 600 }}>{settings.data?.enforcement_mode ?? "—"}</div>
          </div>
          <div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>Apply mode (F-51)</div>
            <div className="tabs-kit" style={{ display: "flex" }}>
              {(["enforce", "dry_run_only"] as const).map((m) => (
                <button key={m} className={`tab-kit${applyMode === m ? " active" : ""}`} disabled={!isAdmin || savingMode}
                  onClick={() => setMode(m)}>
                  {m === "enforce" ? "Enforce" : "Dry-run only"}
                </button>
              ))}
            </div>
            {modeMsg && <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>{modeMsg}</div>}
            {!isAdmin && <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>Admin only</div>}
          </div>
          <div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>Sector packs applied</div>
            <div style={{ marginTop: 4, display: "flex", gap: 6, flexWrap: "wrap" }}>
              {enabledPacks.length === 0
                ? <span style={{ fontSize: 13, color: "var(--text-muted)" }}>none</span>
                : enabledPacks.map((p) => <span key={p.id} style={{ fontSize: 11, padding: "2px 8px", borderRadius: 6, border: "1px solid var(--border)" }}>{p.title}</span>)}
            </div>
          </div>
        </div>
      </Panel>

      <Panel title="Effective policy for a target" sub="The exact layer stack the evaluator resolves for this agent class (derived from real enforcement — overlays are tighten-only).">
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>Agent class:</span>
          <select className="input" value={agentClass} onChange={(e) => setAgentClass(e.target.value)} style={{ fontSize: 13, padding: "4px 8px" }}>
            {classes.length === 0 && <option value="">(no agent-class policies)</option>}
            {classes.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </div>
        {effErr && <div style={{ color: "var(--block)", fontSize: 13 }}>Could not resolve: {effErr}</div>}
        {agentClass && !effErr && (
          <table style={{ borderCollapse: "collapse", width: "100%", fontSize: 13 }}>
            <thead>
              <tr>{["#", "Layer", "Scope", "Priority", "Type"].map((h) => (
                <th key={h} style={{ ...cell, color: "var(--text-secondary)", fontWeight: 600 }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {layers.map((l, i) => (
                <tr key={l.scope}>
                  <td style={cell}>{i + 1}</td>
                  <td style={cell}>{l.label}</td>
                  <td style={{ ...cell, fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>{l.scope}</td>
                  <td style={cell}>{l.priority}</td>
                  <td style={cell}>{l.overlay ? <span style={{ color: "var(--accent)" }}>overlay (tighten-only)</span> : "base"}</td>
                </tr>
              ))}
              {layers.length === 0 && (
                <tr><td style={{ ...cell, color: "var(--text-secondary)" }} colSpan={5}>No policy layers in force — calls fall through to the engine default.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

export default TargetSettings;
