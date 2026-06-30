// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Fleet-mgmt Stage 1 — the Rancher-style APPLY RESULT panel. After a local Apply or a fleet Push, show HONESTLY:
//   - the exact declarative manifest applied (name + target cluster/namespace/agent_class + rego),
//   - the real outcome ("stored vN + loaded into the engine" / "signed bundle distributed" — NOT a fake kubectl apply),
//   - the NRVQ code on error,
//   - propagation: local = loaded@vN; fleet = live rollout (distributed -> <cluster> pulled @vN -> enforcing).
// The fleet variant polls GET /fleet/rollout so the operator watches pending -> applied per cluster.

import { useEffect, useState } from "react";
import { fetchFleetRollout, type FleetRollout } from "../../api/fleet";

export type ApplyManifest = {
  name?: string;
  cluster?: string; // target cluster for a fleet push; omitted for local (served cluster)
  namespace: string;
  agent_class: string;
  enforcement_mode?: string;
  target_selector?: Record<string, string>;
  rego?: string;
};

export type ApplyResult = {
  kind: "local" | "fleet";
  title: string;
  manifest: ApplyManifest;
  ok: boolean;
  outcome: string; // honest outcome line
  code?: string; // NRVQ-* on error
  /** fleet only: the pushed policy name — when set the panel polls rollout to show propagation. */
  fleetPolicyName?: string;
  /** fleet only: clusters the push targeted (to scope the rollout rows shown). */
  targetClusters?: string[];
};

const STATE_COLOR: Record<string, string> = {
  applied: "var(--success, #30a46c)",
  pending: "var(--text-secondary)",
  failed: "var(--danger, #e5484d)",
  diverged: "var(--warning, #f5a623)"
};

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div style={{ display: "flex", gap: 10, fontSize: 12.5, lineHeight: 1.8 }}>
      <span style={{ color: "var(--text-muted)", minWidth: 110 }}>{k}</span>
      <span className="mono" style={{ color: "var(--text-primary)", wordBreak: "break-all" }}>{v}</span>
    </div>
  );
}

export function ApplyResultPanel({ result, onClose }: { result: ApplyResult | null; onClose: () => void }) {
  const [rollout, setRollout] = useState<FleetRollout[]>([]);
  const polling = result?.kind === "fleet" && !!result.fleetPolicyName && result.ok;

  useEffect(() => {
    if (!polling) return;
    let live = true;
    const tick = () =>
      fetchFleetRollout()
        .then((r) => live && setRollout(r))
        .catch(() => {});
    tick();
    const id = setInterval(tick, 5000);
    return () => {
      live = false;
      clearInterval(id);
    };
  }, [polling, result?.fleetPolicyName]);

  if (!result) return null;
  const m = result.manifest;
  const accent = result.ok ? "var(--success, #30a46c)" : "var(--danger, #e5484d)";
  const rows = result.targetClusters?.length
    ? rollout.filter((r) => result.targetClusters!.includes(r.cluster_id))
    : rollout;

  return (
    <div
      style={{
        marginTop: 14,
        border: `1px solid ${accent}`,
        borderRadius: 12,
        background: "var(--bg-surface, #141414)",
        overflow: "hidden"
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "10px 14px",
          borderBottom: "1px solid var(--border, #2a2a2a)"
        }}
      >
        <span style={{ fontWeight: 600, fontSize: 13.5, color: accent }}>
          {result.ok ? "✓ " : "✗ "}
          {result.title}
        </span>
        <button className="icon-btn" style={{ width: 26, height: 26 }} onClick={onClose} title="Dismiss">
          ✕
        </button>
      </div>
      <div style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: 12 }}>
        {/* the honest outcome */}
        <div style={{ fontSize: 13, color: result.ok ? "var(--text-primary)" : accent }}>
          {result.outcome}
          {result.code && <span className="mono" style={{ color: "var(--text-muted)", marginLeft: 8 }}>{result.code}</span>}
        </div>

        {/* the declarative manifest actually applied */}
        <div>
          <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 6 }}>
            {result.kind === "fleet" ? "NrvqFleetPolicy (signed)" : "Resource configured"}
          </div>
          <div style={{ background: "#0e0e0e", border: "1px solid var(--border,#2a2a2a)", borderRadius: 8, padding: "10px 12px" }}>
            {m.name && <Row k="name" v={m.name} />}
            {m.cluster && <Row k="cluster" v={m.cluster} />}
            <Row k="namespace" v={m.namespace} />
            <Row k="agent_class" v={m.agent_class} />
            {m.enforcement_mode && <Row k="enforcement" v={m.enforcement_mode} />}
            {m.target_selector && Object.keys(m.target_selector).length > 0 && (
              <Row k="target" v={JSON.stringify(m.target_selector)} />
            )}
          </div>
          {m.rego && (
            <pre
              style={{
                marginTop: 8,
                maxHeight: 160,
                overflow: "auto",
                background: "#0e0e0e",
                border: "1px solid var(--border,#2a2a2a)",
                borderRadius: 8,
                padding: "10px 12px",
                fontSize: 12,
                color: "var(--text-secondary)"
              }}
            >
              {m.rego}
            </pre>
          )}
        </div>

        {/* propagation */}
        {polling && (
          <div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 6 }}>
              Propagation — signed bundle, each spoke verifies + pulls
            </div>
            {rows.length === 0 ? (
              <div style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>distributed — waiting for the spoke's next pull…</div>
            ) : (
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12.5 }}>
                <tbody>
                  {rows.map((r) => {
                    const enforcing = r.state === "applied" && r.applied_version === r.bundle_version;
                    return (
                      <tr key={r.cluster_id}>
                        <td className="mono" style={{ padding: "4px 8px", color: "var(--text-primary)" }}>{r.cluster_id}</td>
                        <td style={{ padding: "4px 8px", color: STATE_COLOR[r.state] ?? "var(--text-secondary)" }}>
                          {enforcing ? `enforcing @v${r.applied_version}` : `${r.state} (desired v${r.bundle_version}, applied v${r.applied_version})`}
                        </td>
                        <td className="mono" style={{ padding: "4px 8px", color: "var(--text-muted)", textAlign: "right" }}>
                          {r.updated_at ? new Date(r.updated_at).toLocaleTimeString() : ""}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
