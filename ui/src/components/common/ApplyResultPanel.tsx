// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Fleet-mgmt — the Rancher-style APPLY RESULT panel. After a local Apply or a fleet Push, show HONESTLY:
//   - the exact declarative manifest applied (name + target cluster/namespace/agent_class + rego),
//   - the real outcome ("stored vN + loaded into the engine" / "signed bundle distributed" — NOT a fake kubectl apply),
//   - the NRVQ code on error,
//   - propagation: local = loaded@vN; fleet = live rollout (distributed -> <cluster> pulled @vN -> enforcing).
// The fleet variant polls GET /fleet/rollout so the operator watches pending -> applied per cluster.

import { useEffect, useState } from "react";
import { fetchFleetRollout, type FleetRollout } from "../../api/fleet";
import { verifyPolicyApplied } from "../../api/client";
import { KitButton } from "./KitButton";

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
  /** local only: the version the write claims to have produced. When set, the panel polls
   *  GET /api/v1/policies?namespace= to confirm current_version actually converged before showing
   *  ENFORCING — a 200 alone is not proof the policy is loaded on the read path. */
  expectedVersion?: number;
  /** local only: optionally also require enforcement_mode to match before declaring a match. */
  expectedMode?: string;
  /** local only: for a local verify flow that has NO `expectedVersion` to poll against (e.g. a
   *  policy-pack toggle, verified by its own bespoke poll rather than the version-poll above) — the caller
   *  drives this tri-state directly: `true` while its OWN verification is still in flight, `"stalled"` if
   *  that verification gave up without confirming, `false`/unset once it confirmed. Keeps the status badge
   *  honest: without this the badge fell straight to APPLIED (no expectedVersion -> not localVerifying)
   *  while the body text underneath still said "Verifying…", a visible contradiction. */
  pendingVerify?: boolean | "stalled";
};

const LOCAL_VERIFY_INTERVAL_MS = 1500;
const LOCAL_VERIFY_MAX_TRIES = 4; // ~6s total — matches the HA cross-replica sync budget (~1s) with headroom

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

  // A local Apply/Create/Rollback that returns 200 is not proof the policy is loaded on the read
  // path — poll the plain list endpoint (DB-authoritative, no session affinity assumed — either replica may
  // answer) until current_version (and enforcement_mode, when given) actually converges, or give up honestly.
  const [localVerify, setLocalVerify] = useState<"idle" | "verifying" | "matched" | "stalled">("idle");
  const [localRetryNonce, setLocalRetryNonce] = useState(0);
  const localVerifying = result?.kind === "local" && result.ok && !!result.expectedVersion;
  const ns = result?.manifest.namespace;
  const cls = result?.manifest.agent_class;
  const expectedVersion = result?.expectedVersion;
  const expectedMode = result?.expectedMode;

  useEffect(() => {
    if (!localVerifying || !ns || !cls || !expectedVersion) {
      setLocalVerify("idle");
      return;
    }
    let live = true;
    let tries = 0;
    let timeoutId: ReturnType<typeof setTimeout>;
    setLocalVerify("verifying");
    const tick = async () => {
      tries += 1;
      try {
        const v = await verifyPolicyApplied(ns, cls, expectedVersion);
        if (!live) return;
        const modeOk = expectedMode ? v.enforcement_mode === expectedMode : true;
        if (v.matched && modeOk) {
          setLocalVerify("matched");
          return;
        }
      } catch {
        // A verify-read failure is treated like a non-match this tick — keep polling until the budget is spent
        // rather than flipping straight to a scary state over one flaky read.
      }
      if (!live) return;
      if (tries >= LOCAL_VERIFY_MAX_TRIES) {
        setLocalVerify("stalled");
      } else {
        timeoutId = setTimeout(tick, LOCAL_VERIFY_INTERVAL_MS);
      }
    };
    tick();
    return () => {
      live = false;
      clearTimeout(timeoutId);
    };
  }, [localVerifying, ns, cls, expectedVersion, expectedMode, localRetryNonce]);

  if (!result) return null;
  const m = result.manifest;
  const accent = result.ok ? "var(--success, #30a46c)" : "var(--danger, #e5484d)";
  const rows = result.targetClusters?.length
    ? rollout.filter((r) => result.targetClusters!.includes(r.cluster_id))
    : rollout;

  // The single, unmistakable status the operator reads first:
  //   FAILED      — the apply/push was rejected (guard hit, error) → show the NRVQ code + reason.
  //   PROPAGATING — a fleet push accepted at the hub, now polling each spoke's pull/verify/apply.
  //   VERIFYING   — a local write returned 200; polling a live read to confirm it actually converged.
  //   STALLED     — verification timed out with no match (amber, NOT red — may still be propagating).
  //   ENFORCING vN — the live read confirmed the expected version (+ mode, if given) is what's loaded.
  //   APPLIED     — a local write with no expectedVersion given (legacy callers), or a fully-rolled-out push.
  const status: { label: string; color: string } = !result.ok
    ? { label: "FAILED", color: "var(--danger, #e5484d)" }
    : polling
    ? { label: "PROPAGATING", color: "var(--warning, #f5a623)" }
    // A caller-driven verify with no expectedVersion (e.g. the PolicyPacks toggle) — honor its own
    // pending/stalled state BEFORE falling to the version-poll branches below, so the badge never shows
    // APPLIED while the body underneath still reads "Verifying…".
    : result.pendingVerify === true
    ? { label: "VERIFYING", color: "var(--text-secondary)" }
    : result.pendingVerify === "stalled"
    ? { label: "STALLED", color: "var(--warning, #f5a623)" }
    : localVerifying && localVerify === "verifying"
    ? { label: "VERIFYING", color: "var(--text-secondary)" }
    : localVerifying && localVerify === "stalled"
    ? { label: "STALLED", color: "var(--warning, #f5a623)" }
    : localVerifying && localVerify === "matched"
    ? { label: `ENFORCING v${expectedVersion}`, color: "var(--success, #30a46c)" }
    : { label: "APPLIED", color: "var(--success, #30a46c)" };

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
        <span style={{ display: "inline-flex", alignItems: "center", gap: 10, fontWeight: 600, fontSize: 13.5, color: accent }}>
          <span
            aria-label={`Apply status: ${status.label}`}
            style={{
              fontSize: 11,
              fontWeight: 700,
              letterSpacing: ".08em",
              padding: "2px 8px",
              borderRadius: 999,
              color: status.color,
              border: `1px solid ${status.color}`,
              background: `color-mix(in srgb, ${status.color} 14%, transparent)`
            }}
          >
            {status.label}
          </span>
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

        {/* Local verify-by-poll — HONEST copy, no "loaded on every pod" claim (the Service has no
            session affinity; this confirms a live read, not a full-fleet rollout like the fleet case above). */}
        {localVerifying && (
          <div>
            <div style={{ fontSize: 11, color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: ".06em", marginBottom: 6 }}>
              Verification — live read
            </div>
            {localVerify === "verifying" && (
              <div style={{ fontSize: 12.5, color: "var(--text-secondary)" }}>
                Verifying — confirming the new version is loaded…
              </div>
            )}
            {localVerify === "matched" && (
              <div style={{ fontSize: 12.5, color: "var(--success, #30a46c)" }}>
                Enforcing v{expectedVersion} — confirmed via a live read (DB-authoritative; cross-replica sync ~1s).
              </div>
            )}
            {localVerify === "stalled" && (
              <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                <span style={{ fontSize: 12.5, color: "var(--warning, #f5a623)" }}>
                  This connection hasn't picked up v{expectedVersion} yet — it may still be propagating across
                  replicas. This is not necessarily a failure.
                </span>
                <KitButton
                  variant="ghost"
                  size="sm"
                  onClick={() => setLocalRetryNonce((n) => n + 1)}
                >
                  Check again
                </KitButton>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
