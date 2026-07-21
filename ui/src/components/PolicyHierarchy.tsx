// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// The Policy precedence HIERARCHY — the resolution stack the evaluator ACTUALLY uses for a (namespace,
// agent-class), rendered top-to-bottom in priority order. It renders GET /policies/effective VERBATIM (scope, order,
// priority, overlay flag) — precedence is NEVER re-implemented in the UI; it always mirrors real enforcement.
//
// The "Mode" column reflects the effective per-namespace enforcement posture (Block / Monitor)
// from GET /settings, so the hierarchy agrees with the Namespace Governance card. Still cluster-aware in STRUCTURE
// only (the cluster header is inert on the single-cluster GA surface).

import { useEffect, useMemo, useState } from "react";
import { apiGet, fetchEffectivePolicy, fetchSettings, type EffectiveLayer } from "../api/client";
import { fleetEnabled } from "../api/fleet";
import { Panel } from "./common/Panel";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";

// The full conceptual precedence template, highest-priority-wins top→bottom. Each in-force layer from the API is
// classified into one of these slots so the UI can show which slots are IN FORCE vs an EMPTY slot (not configured).
// This is presentation only — it never reorders the API's authoritative stack.
type Slot = { key: string; label: string; fleetOnly?: boolean; match: (ns: string, ac: string, scope: string, cls: string) => boolean };
const TEMPLATE: Slot[] = [
  { key: "cluster", label: "cluster policy", fleetOnly: true, match: () => false },
  { key: "cluster-baseline", label: "cluster baseline (comprehensive)", match: (ns, ac) => ns === "__cluster__" && ac === "__baseline__" },
  { key: "ns-baseline", label: "namespace baseline", match: (ns, ac) => ac === "__baseline__" && ns !== "__cluster__" },
  { key: "pack", label: "sector pack (overlay)", match: (_ns, ac) => ac === "__pack__" },
  { key: "override", label: "override / weaken (overlay)", match: (_ns, ac) => ac === "__pack_override__" || ac === "__pack_weaken__" },
  { key: "guardrail", label: "tool-allowlist guardrail (overlay)", match: (_ns, ac) => ac === "__guardrail__" },
  { key: "workload", label: "workload policy", match: (_ns, _ac, scope) => scope.startsWith("workload:") },
  { key: "class", label: "agent-class policy", match: (_ns, ac, _scope, cls) => ac === cls }
];

function acOf(scope: string): { ns: string; ac: string } {
  const i = scope.indexOf(":");
  return i < 0 ? { ns: scope, ac: "" } : { ns: scope.slice(0, i), ac: scope.slice(i + 1) };
}

type PolicyRow = { agent_class: string; target_type: string };

export function PolicyHierarchy({ namespace, testId = "policy-hierarchy" }: { namespace: string; testId?: string }) {
  const { servedCluster, scopeCluster } = useApp();

  // Agent classes configured in this namespace (exclude the reserved overlay scopes — they are LAYERS, not targets).
  const policies = useApi<PolicyRow[]>(
    () => apiGet<PolicyRow[]>(`/api/v1/policies?namespace=${encodeURIComponent(namespace)}`),
    [namespace],
    { cacheKey: `hier-classes:${namespace}`, staleTimeMs: 15_000 }
  );
  const classes = useMemo(
    // dedupe: the "all" view returns policies across namespaces, so a class name shared by two namespaces
    // would otherwise produce duplicate <option>s (and duplicate React keys).
    () => [...new Set((policies.data ?? []).filter((p) => p.target_type === "class" && !p.agent_class.startsWith("__")).map((p) => p.agent_class))],
    [policies.data]
  );
  // A namespace can have ENFORCING overlays (a `__pack__` from an enabled sector pack, or a
  // `__baseline__`/`__guardrail__`) with NO agent-class policy. Those overlay rows are correctly excluded from
  // the class picker (they are LAYERS, not targets), but if that left the picker empty the hierarchy rendered
  // nothing — hiding a pack that IS enforcing. Offer a namespace-wide view ("*") that resolves the ns overlays
  // (baseline + packs apply to every class), so a pack-only namespace still shows its enforcing stack.
  const hasOverlays = useMemo(
    () => (policies.data ?? []).some((p) => p.target_type === "class" && p.agent_class.startsWith("__")),
    [policies.data]
  );
  const NS_WIDE = "*";
  const pickerClasses = useMemo(
    () => (classes.length > 0 ? classes : hasOverlays ? [NS_WIDE] : []),
    [classes, hasOverlays]
  );
  const [agentClass, setAgentClass] = useState("");
  useEffect(() => { if (pickerClasses.length && !pickerClasses.includes(agentClass)) setAgentClass(pickerClasses[0]); }, [pickerClasses, agentClass]);

  // The effective stack — cacheKey `effective:` so a pack/policy mutation (which busts that prefix) re-fetches it.
  const eff = useApi<{ layers: EffectiveLayer[]; note?: string }>(
    () => (agentClass ? fetchEffectivePolicy(namespace, agentClass) : Promise.resolve({ layers: [] })),
    [namespace, agentClass],
    { cacheKey: `effective:${namespace}:${agentClass}`, staleTimeMs: 15_000 }
  );
  const layers = eff.data?.layers ?? [];

  // The effective per-ns enforcement posture (Block / Monitor). "audit" is displayed as "Monitor".
  const posture = useApi(
    () => fetchSettings(namespace),
    [namespace],
    { cacheKey: `hier-posture:${namespace}`, staleTimeMs: 15_000 }
  );
  const modeLabel = posture.data?.enforcement_mode === "audit" ? "Monitor" : "Block";
  const modeTitle = posture.data?.enforcement_mode === "audit"
    ? "Monitor — evaluate & log would-block, but allow (observe mode)"
    : "Block — matching policies are enforced";

  const presentSlot = (key: string) => {
    const slot = TEMPLATE.find((s) => s.key === key);
    return !!slot && layers.some((l) => { const { ns, ac } = acOf(l.scope); return slot.match(ns, ac, l.scope, agentClass); });
  };

  const cell: React.CSSProperties = { padding: "8px 12px", borderBottom: "1px solid var(--border, #2a2a2a)", textAlign: "left" };
  const muted = "var(--text-muted)";

  return (
    <Panel
      title="Resolution hierarchy"
      sub="The exact layer stack the evaluator resolves for this agent class — highest-priority-wins, top to bottom. Overlays only TIGHTEN (never weaken). Rendered from real enforcement (/policies/effective), never re-derived."
      action={
        // Cluster dimension — inert on the single-cluster GA surface; structural so fleet drops in later.
        <span data-testid={`${testId}-cluster`} title="Cluster scope (single-cluster on this deployment)"
          style={{ fontSize: 11, color: muted, border: "1px solid var(--border)", borderRadius: 6, padding: "2px 8px" }}>
          cluster: <span className="mono">{fleetEnabled ? scopeCluster : servedCluster || "—"}</span>
        </span>
      }
    >
      {/* Resolution is inherently PER-NAMESPACE (baseline + packs + guardrails are ns-scoped), so the "all"
          view has no single coherent stack — resolving against ns="all" matches no real layers and would
          show a misleadingly thin stack. Ask the operator to pick a namespace instead. */}
      {namespace === "all" ? (
        <div className="muted" style={{ fontSize: 13, padding: "10px 2px" }}>
          Select a specific namespace (top-left scope switcher) to see its resolution hierarchy — the layer
          stack is per-namespace.
        </div>
      ) : (
      <>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>Agent class:</span>
        <select data-testid={`${testId}-class`} className="input" value={agentClass} onChange={(e) => setAgentClass(e.target.value)} style={{ fontSize: 13, padding: "4px 8px" }}>
          {pickerClasses.length === 0 && <option value="">(no agent-class policies)</option>}
          {pickerClasses.map((c) => (
            <option key={c} value={c}>{c === NS_WIDE ? "All classes · namespace overlays" : c}</option>
          ))}
        </select>
      </div>

      {eff.error && <div style={{ color: "var(--block)", fontSize: 13 }}>Could not resolve: {String(eff.error)}</div>}
      {!eff.error && (
        <table data-testid={`${testId}-table`} style={{ borderCollapse: "collapse", width: "100%", fontSize: 13 }}>
          <thead>
            <tr>{["#", "Layer", "Scope", "Priority", "Type", "Mode", "Presence"].map((h) => (
              <th key={h} style={{ ...cell, color: "var(--text-secondary)", fontWeight: 600 }}>{h}</th>
            ))}</tr>
          </thead>
          <tbody>
            {layers.map((l, i) => (
              <tr key={l.scope} data-testid={`${testId}-row`}>
                <td style={cell}>{i + 1}</td>
                <td style={cell}>{l.label}</td>
                <td data-testid={`${testId}-scope`} style={{ ...cell, fontFamily: "var(--font-mono)", color: muted }}>{l.scope}</td>
                <td data-testid={`${testId}-priority`} style={cell}>{l.priority}</td>
                <td style={cell}>{l.overlay
                  ? <span data-testid={`${testId}-overlay`} style={{ color: "var(--accent)" }}>overlay (tighten-only)</span>
                  : <span style={{ color: "var(--text-secondary)" }}>base</span>}</td>
                {/* The effective per-ns posture (Block / Monitor), from GET /settings. */}
                <td style={cell}><span data-testid={`${testId}-mode`} data-mode={modeLabel.toLowerCase()} title={modeTitle}
                  style={{ fontSize: 11, color: modeLabel === "Monitor" ? "var(--escalate)" : "var(--text-secondary)", border: "1px solid var(--border)", borderRadius: 6, padding: "1px 7px" }}>{modeLabel}</span></td>
                <td style={cell}><span style={{ display: "inline-flex", alignItems: "center", gap: 5, color: "var(--good, #2ecc71)" }}>
                  <span style={{ width: 7, height: 7, borderRadius: "50%", background: "var(--good, #2ecc71)" }} /> in force
                </span></td>
              </tr>
            ))}
            {layers.length === 0 && (
              <tr><td style={{ ...cell, color: "var(--text-secondary)" }} colSpan={7}>
                {agentClass ? "No policy layers in force — calls fall through to the engine default." : "Select an agent class."}
              </td></tr>
            )}
          </tbody>
        </table>
      )}

      {/* Presence legend — the full precedence template, marking which conceptual slots are in force vs an empty slot
          (not configured). Purely informational; it never reorders the authoritative API stack above. */}
      {agentClass && !eff.error && (
        <div data-testid={`${testId}-template`} style={{ marginTop: 12, fontSize: 11.5, color: muted }}>
          <div style={{ marginBottom: 4, fontWeight: 600, color: "var(--text-secondary)" }}>Precedence template (highest wins, top→bottom)</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {TEMPLATE.filter((s) => !s.fleetOnly || fleetEnabled).map((s) => {
              const on = presentSlot(s.key);
              return (
                <span key={s.key} data-testid={`${testId}-slot-${s.key}`} data-present={on ? "1" : "0"}
                  style={{ padding: "2px 8px", borderRadius: 6, border: `1px solid ${on ? "var(--good, #2ecc71)" : "var(--border)"}`,
                    color: on ? "var(--good, #2ecc71)" : muted, opacity: on ? 1 : 0.7 }}>
                  {on ? "✓" : "○"} {s.label}
                </span>
              );
            })}
          </div>
        </div>
      )}
      </>
      )}
    </Panel>
  );
}

export default PolicyHierarchy;
