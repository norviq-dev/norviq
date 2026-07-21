// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// "Namespace Governance" — the namespace-scoped governance KNOBS (enforcement mode, the
// apply-mode, and which sector packs are applied). The "effective policy" resolved-stack view lives in
// the Policy Catalog hierarchy (the one place that answers "how does this resolve") — a link is provided here with
// the namespace preserved.

import {
  fetchMe,
  fetchPolicyPacks,
  fetchSettings,
  saveSettings
} from "../api/client";
import { Link } from "react-router-dom";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApi, invalidateApiCache } from "../hooks/useApi";
import { useMutationScope } from "../hooks/useMutationScope";
import { useApp } from "../store/AppContext";
import { useState } from "react";

export function TargetSettings() {
  const { namespace, refreshPosture } = useApp();
  const me = useApi(() => fetchMe(), []);
  const isAdmin = me.data?.role === "admin";

  const settings = useApi(() => fetchSettings(namespace), [namespace], { cacheKey: `tgt-settings:${namespace}`, staleTimeMs: 15_000 });
  const packs = useApi(() => fetchPolicyPacks(namespace), [namespace], { cacheKey: `tgt-packs:${namespace}`, staleTimeMs: 15_000 });

  const applyMode = settings.data?.apply_mode === "dry_run_only" ? "dry_run_only" : "enforce";
  // TGT-POSTURE-01: the enforcement axis (Block ⇄ Monitor). Wire value stays block|audit; "audit" is DISPLAYED
  // as "Monitor" so it doesn't collide with the `audit` decision or the Audit Log.
  const enforcementMode = settings.data?.enforcement_mode === "audit" ? "audit" : "block";
  // The toggles are namespace-scoped mutations — never let them target the phantom aggregate ("all").
  const { canMutate, blockedReason } = useMutationScope();
  const [savingMode, setSavingMode] = useState(false);
  const [modeMsg, setModeMsg] = useState<string | null>(null);
  const invalidatePostureCaches = () => {
    // Include `policy-settings:` — Policy Catalog reads apply_mode/enforcement under that key to
    // gate its Apply button; without it a freeze/mode-flip here left the catalog stale for up to 30s.
    for (const p of ["settings:", "tgt-settings:", "policy-settings:", "policy-packs:", "tgt-packs:", "effective:", "hier-posture:"]) invalidateApiCache(p);
  };
  const setApply = async (m: "enforce" | "dry_run_only") => {
    if (!canMutate) { setModeMsg(blockedReason); return; }  // Belt-and-braces
    setSavingMode(true); setModeMsg(null);
    try {
      await saveSettings(namespace, { apply_mode: m });
      invalidatePostureCaches();
      await settings.refetch();
      refreshPosture();  // Refresh the GLOBAL posture (header chip + catalog badge), not just this page
      setModeMsg(`Change control: ${m === "enforce" ? "Live" : "Frozen"}`);
    }
    catch (e) { setModeMsg(`Failed: ${(e instanceof Error ? e.message : String(e)).replace(/^Error:\s*/, "")}`); }
    finally { setSavingMode(false); }
  };
  const setEnforcement = async (m: "block" | "audit") => {
    if (!canMutate) { setModeMsg(blockedReason); return; }  // TGT-POSTURE-01: never write the aggregate scope
    setSavingMode(true); setModeMsg(null);
    try {
      await saveSettings(namespace, { enforcement_mode: m });
      invalidatePostureCaches();
      await settings.refetch();
      refreshPosture();  // The Monitor↔Block flip must update the global "MONITOR·not blocking" chip live
      setModeMsg(`Enforcement mode: ${m === "audit" ? "Monitor" : "Block"}`);
    }
    catch (e) { setModeMsg(`Failed: ${(e instanceof Error ? e.message : String(e)).replace(/^Error:\s*/, "")}`); }
    finally { setSavingMode(false); }
  };

  const enabledPacks = (packs.data ?? []).filter((p) => p.enabled);
  // Bind the subtitle/working-scope label to the ACTUAL working scope — never "Namespace: all" over data.
  const scopeLabel = namespace === "all" ? "All namespaces" : `Namespace: ${namespace}`;
  const concrete = namespace !== "all";

  return (
    <div className="page-enter">
      <PageHead title="Namespace Governance" subtitle={scopeLabel} />

      <Panel title="Governance" sub="How this namespace is governed right now (server-enforced).">
        <div style={{ display: "flex", gap: 24, flexWrap: "wrap", alignItems: "flex-start" }}>
          <div>
            {/* TGT-POSTURE-01: the block-vs-observe axis is now an editable toggle (Block ⇄ Monitor). */}
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>Enforcement mode</div>
            <div className="tabs-kit" style={{ display: "flex" }}>
              {(["block", "audit"] as const).map((m) => (
                <button key={m} data-testid={`enforcement-mode-${m}`} className={`tab-kit${enforcementMode === m ? " active" : ""}`}
                  disabled={!isAdmin || savingMode || !canMutate}
                  title={blockedReason ?? undefined}
                  onClick={() => setEnforcement(m)}>
                  {m === "audit" ? "Monitor" : "Block"}
                </button>
              ))}
            </div>
            {isAdmin && !blockedReason && enforcementMode === "audit" && (
              <div data-testid="enforcement-monitor-note"
                title="Monitor — evaluate & log would-block, but allow (observe mode; live traffic is not blocked)."
                style={{ fontSize: 11, color: "var(--block, #ff5c7c)", marginTop: 4 }}>
                Monitor — evaluate & log would-block, but allow (live traffic is not blocked).
              </div>
            )}
            {!isAdmin && <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>Admin only</div>}
          </div>
          <div>
            {/* Change control (apply governance) — a policy-EDIT lock, not a traffic mode. Wire values enforce|dry_run_only. */}
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>Change control — policy edits</div>
            <div className="tabs-kit" style={{ display: "flex" }}>
              {(["enforce", "dry_run_only"] as const).map((m) => (
                <button key={m} data-testid={`apply-mode-${m}`} className={`tab-kit${applyMode === m ? " active" : ""}`}
                  disabled={!isAdmin || savingMode || !canMutate}
                  title={blockedReason ?? undefined}
                  onClick={() => setApply(m)}>
                  {m === "enforce" ? "Live" : "Frozen"}
                </button>
              ))}
            </div>
            {modeMsg && <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>{modeMsg}</div>}
            {/* Prompt for a concrete scope when an aggregate is selected. */}
            {isAdmin && blockedReason && <div data-testid="apply-mode-scope-prompt" style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>{blockedReason}</div>}
            {/* Make the frozen consequence explicit at the control that sets it. */}
            {isAdmin && !blockedReason && applyMode === "dry_run_only" && (
              <div data-testid="apply-mode-dryrun-note" title="Frozen freezes POLICY EDITS for this namespace; the live policy still enforces."
                style={{ fontSize: 11, color: "var(--block, #ff5c7c)", marginTop: 4 }}>
                Frozen — policy edits are frozen (live policy still enforces).
              </div>
            )}
            {!isAdmin && <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>Admin only</div>}
          </div>
          <div>
            <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>Sector packs applied</div>
            {/* Explicit APPLIED/NONE state tied to the concrete namespace, updates after enable/disable. */}
            {!concrete ? (
              <div data-testid="packs-applied-state" style={{ marginTop: 4, fontSize: 13, color: "var(--text-muted)" }}>Select a namespace to see applied packs</div>
            ) : enabledPacks.length === 0 ? (
              <div data-testid="packs-applied-state" data-count="0" style={{ marginTop: 4, fontSize: 13, color: "var(--text-muted)" }}>No packs applied</div>
            ) : (
              <div data-testid="packs-applied-state" data-count={enabledPacks.length} style={{ marginTop: 4 }}>
                <span style={{ fontSize: 13, color: "var(--good, #2ecc71)", fontWeight: 600 }}>
                  {enabledPacks.length} pack{enabledPacks.length === 1 ? "" : "s"} applied ✓
                </span>
                <div style={{ marginTop: 4, display: "flex", gap: 6, flexWrap: "wrap" }}>
                  {enabledPacks.map((p) => <span key={p.id} style={{ fontSize: 11, padding: "2px 8px", borderRadius: 6, border: "1px solid var(--border)" }}>{p.title}</span>)}
                </div>
              </div>
            )}
          </div>
        </div>
        {/* The resolved-stack view lives in the Catalog hierarchy — link with the namespace preserved. */}
        <div style={{ marginTop: 14 }}>
          <Link data-testid="see-how-resolves" to="/policies/catalog?tab=catalog"
            style={{ fontSize: 13, color: "var(--accent)", textDecoration: "none", fontWeight: 600 }}>
            See how this resolves →
          </Link>
          <span style={{ fontSize: 12, color: "var(--text-muted)", marginLeft: 8 }}>
            the full layer stack (cluster baseline → packs → overrides → agent-class) for {concrete ? namespace : "a namespace"}.
          </span>
        </div>
      </Panel>
    </div>
  );
}

export default TargetSettings;
