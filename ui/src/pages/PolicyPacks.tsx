import "../lib/monaco"; // Bundle Monaco locally (no cdn.jsdelivr fetch) — must precede <Editor>
import Editor from "@monaco-editor/react";
import { useEffect, useMemo, useState } from "react";
import {
  disablePolicyPack,
  enablePolicyPack,
  fetchMe,
  fetchPackOverride,
  fetchPackRego,
  fetchPolicyPacks,
  fetchSettings,
  revertPackOverride,
  savePackOverride,
  dryRunPolicy,
  PolicyPack
} from "../api/client";
import { ApplyResultPanel, type ApplyResult } from "../components/common/ApplyResultPanel";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApi, invalidateApiCache } from "../hooks/useApi";
import { useMutationScope } from "../hooks/useMutationScope";
import { registerRego } from "../lib/monaco-rego";
import { useApp } from "../store/AppContext";

// After a pack/override mutation, drop every cached read of pack + settings state (this page's own key AND
// Target Settings' distinct `tgt-*` keys) so a remount or a hop to Target Settings reflects the change immediately
// instead of serving a stale entry inside its staleTime window.
function bustPackCaches(): void {
  // Also bust the resolution-hierarchy caches so enabling/disabling a pack reflects its overlay layer in the
  // Catalog hierarchy with no reload.
  // Include `policy-settings:` so Policy Catalog's Apply-gate (apply_mode) reflects a pack change.
  for (const p of ["policy-packs:", "tgt-packs:", "settings:", "tgt-settings:", "policy-settings:", "effective:", "hier-classes:"]) invalidateApiCache(p);
}

const OVERRIDE_TEMPLATE = `# Tighten-only override for this namespace's sector pack(s).
# You can ADD stricter blocks — you can never weaken/remove a pack's block.
package norviq.packoverride

default decision = "allow"

# example: also block a tool the pack allows
decision = "block" { input.tool_name == "export_all" }
rule_id = "pack_override_block" { decision == "block" }
reason = "blocked by per-namespace pack override" { decision == "block" }
`;

const ON = "#00e5a0";
const GAP = "#ff5c7c";

export function PolicyPacks() {
  const { namespace } = useApp();
  const packs = useApi(() => fetchPolicyPacks(namespace), [namespace], {
    cacheKey: `policy-packs:${namespace}`,
    staleTimeMs: 15_000
  });
  const me = useApi(() => fetchMe(), []);
  const settings = useApi(() => fetchSettings(namespace), [namespace], {
    cacheKey: `settings:${namespace}`,
    staleTimeMs: 30_000
  });

  const [busyId, setBusyId] = useState<string | null>(null);
  // PACK-CONFIRM (audit #7): enabling/disabling a pack changes live enforcement for the selected
  // namespace with a single click and no target shown. Gate it behind a confirm that NAMES the
  // namespace + the direction + the composed rules.
  const [confirmPack, setConfirmPack] = useState<PolicyPack | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // View a pack's rego (read-only) + author a tighten-only per-namespace override.
  const [viewRego, setViewRego] = useState<{ title: string; rego: string } | null>(null);
  const [overrideRego, setOverrideRego] = useState("");
  const [overrideActive, setOverrideActive] = useState(false);
  const [overrideMsg, setOverrideMsg] = useState<string | null>(null);
  const [overrideBusy, setOverrideBusy] = useState(false);
  // The loud "Advanced: allow weakening this pack" opt-in + dry-run + apply-result transparency.
  const [allowWeaken, setAllowWeaken] = useState(false);
  const [packDryRun, setPackDryRun] = useState<{ would_block?: number; would_allow?: number; block_rate_pct?: number; recommendation?: string } | null>(null);
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null);
  useEffect(() => {
    // Switching namespace reloads THIS ns's override rego — the dry-run / apply-result / message
    // panels below describe the PREVIOUS ns's rego and must be cleared too (the onChange-only clear
    // doesn't fire on a namespace switch).
    setPackDryRun(null);
    setApplyResult(null);
    setOverrideMsg(null);
    fetchPackOverride(namespace)
      .then((o) => { setOverrideActive(o.active); setOverrideRego(o.rego_source || OVERRIDE_TEMPLATE); setAllowWeaken(o.mode === "weaken"); })
      .catch(() => { setOverrideActive(false); setOverrideRego(OVERRIDE_TEMPLATE); });
  }, [namespace]);

  const isAdmin = me.data?.role === "admin";
  const suggestedSector = (settings.data?.sector ?? "").toLowerCase();
  // Never let a namespace/cluster-scoped mutation target the phantom aggregate ("all"). Reflect the
  // namespace's apply-mode up-front so "dry-run-only — applies disabled" shows BEFORE a click.
  const { canMutate, blockedReason } = useMutationScope();
  const dryRunOnly = settings.data?.apply_mode === "dry_run_only";
  const mutationsDisabled = !canMutate || dryRunOnly;

  const bySector = useMemo(() => {
    const groups = new Map<string, PolicyPack[]>();
    for (const p of packs.data ?? []) {
      const list = groups.get(p.sector) ?? [];
      list.push(p);
      groups.set(p.sector, list);
    }
    return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [packs.data]);

  // An enable/disable write returning 200 is not proof the pack's `enabled` flag actually converged —
  // poll a fresh read of the pack list (same convergence idea as the policy-apply verify-by-poll) instead of
  // trusting the write alone. Best-effort: a poll failure just leaves the outcome text as "not yet confirmed",
  // it never blocks or reverts the mutation that already succeeded.
  const pollPackConverged = async (packId: string, wantEnabled: boolean, tries = 4, intervalMs = 1500): Promise<boolean> => {
    for (let i = 0; i < tries; i++) {
      try {
        const list = await fetchPolicyPacks(namespace);
        const row = list.find((p) => p.id === packId);
        if (row && row.enabled === wantEnabled) return true;
      } catch {
        // transient read failure — keep polling until the try budget is spent.
      }
      if (i < tries - 1) await new Promise((r) => setTimeout(r, intervalMs));
    }
    return false;
  };

  const toggle = async (pack: PolicyPack) => {
    // Belt-and-braces — never mutate under an aggregate scope even if a control slipped through.
    if (!canMutate) { setActionError(blockedReason); return; }
    setActionError(null);
    setBusyId(pack.id);
    const wantEnabled = !pack.enabled;
    const verb = wantEnabled ? "Enabled" : "Disabled";
    try {
      if (pack.enabled) await disablePolicyPack(pack.id, namespace);
      else await enablePolicyPack(pack.id, namespace);
      bustPackCaches();            // Cross-page/remount reads reflect the change immediately
      await packs.refetch();       // same-page card flips now (force)
      // The toggle surfaces an honest result beyond the card's badge flip and
      // verifies it by polling, instead of declaring success the instant the write's 200 comes back.
      const title = `${verb} "${pack.title}" — ${namespace}`;
      setApplyResult({
        kind: "local",
        title,
        ok: true,
        outcome: "Verifying — confirming the change is loaded…",
        manifest: { namespace, agent_class: `__pack__${pack.id}`, enforcement_mode: wantEnabled ? "enabled" : "disabled" },
        // No expectedVersion here (this toggle verifies via its OWN poll, below) — without pendingVerify
        // the panel's badge fell straight to APPLIED (green) while this outcome text still said "Verifying…",
        // a visible contradiction. Drive the badge from the same in-flight state as the text.
        pendingVerify: true
      });
      const converged = await pollPackConverged(pack.id, wantEnabled);
      // The immediate refetch above can race the eventually-consistent write and read back the
      // pre-flip flag, leaving the card badge/button stale ("Enable" when the pack is now on). Once
      // the poll confirms convergence, refetch once more so the card reflects the real state.
      if (converged) await packs.refetch();
      setApplyResult((prev) =>
        prev && prev.title === title
          ? {
              ...prev,
              outcome: converged
                ? `Confirmed via a live read — "${pack.title}" is now ${wantEnabled ? "enabled" : "disabled"} for ${namespace}. Effective on the next tool call.`
                : `The write succeeded but this connection hasn't confirmed the flip yet — it may still be propagating across replicas. Reopening this page will show the current state.`,
              pendingVerify: converged ? false : "stalled"
            }
          : prev
      );
    } catch (e) {
      // Surface the reason — a dry-run-only namespace returns 409 with a clear detail; show it, don't swallow.
      const msg = e instanceof Error ? e.message : "Action failed";
      setActionError(msg);
      setApplyResult({
        kind: "local",
        title: `Could not ${pack.enabled ? "disable" : "enable"} "${pack.title}"`,
        ok: false,
        outcome: msg,
        manifest: { namespace, agent_class: `__pack__${pack.id}` }
      });
    } finally {
      setBusyId(null);
    }
  };

  const openRego = async (pack: PolicyPack) => {
    setActionError(null);
    try {
      const { rego } = await fetchPackRego(pack.id);
      setViewRego({ title: pack.title, rego });
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Could not load pack rego");
    }
  };

  const runPackDryRun = async () => {
    setOverrideMsg(null);
    try {
      const r = await dryRunPolicy({ namespace, agent_class: "__pack_override__", rego_source: overrideRego });
      setPackDryRun(r);
    } catch (e) {
      setOverrideMsg(`Dry-run failed: ${(e instanceof Error ? e.message : String(e)).replace(/^Error:\s*/, "")}`);
    }
  };

  const saveOverride = async () => {
    setOverrideMsg(null);
    setOverrideBusy(true);
    try {
      const res = await savePackOverride(namespace, overrideRego, allowWeaken);
      bustPackCaches();  // Keep pack/settings reads fresh across pages after an override write
      setOverrideActive(true);
      setApplyResult({
        kind: "local",
        title: allowWeaken ? `Pack WEAKEN applied — ${namespace}` : `Pack override applied — ${namespace}`,
        ok: true,
        outcome: allowWeaken
          ? `Loaded as a WEAKEN overlay (audited). It may relax this pack's added blocks — but the engine still floors every decision at your comprehensive baseline, so it can never drop below your org policy.`
          : `Loaded as a tighten-only overlay. It can make the pack stricter, never weaker. Effective immediately for this namespace.`,
        manifest: { namespace, agent_class: allowWeaken ? "__pack_weaken__" : "__pack_override__", enforcement_mode: "block", rego: overrideRego }
      });
    } catch (e) {
      const msg = (e instanceof Error ? e.message : String(e)).replace(/^Error:\s*/, "");
      const codeMatch = msg.match(/NRVQ-[A-Z]+-\d+/);
      setApplyResult({
        kind: "local", title: "Override rejected", ok: false, outcome: msg, code: codeMatch ? codeMatch[0] : undefined,
        manifest: { namespace, agent_class: allowWeaken ? "__pack_weaken__" : "__pack_override__", rego: overrideRego }
      });
    } finally {
      setOverrideBusy(false);
    }
  };

  const revertOverride = async () => {
    setOverrideMsg(null);
    setOverrideBusy(true);
    try {
      await revertPackOverride(namespace);
      bustPackCaches();  // Reflect the revert everywhere immediately
      setOverrideActive(false);
      setOverrideRego(OVERRIDE_TEMPLATE);
      setAllowWeaken(false);
      setApplyResult(null);
      setPackDryRun(null);
      setOverrideMsg("Reverted — the original pack is restored.");
    } catch (e) {
      setOverrideMsg(`Revert failed: ${(e instanceof Error ? e.message : String(e)).replace(/^Error:\s*/, "")}`);
    } finally {
      setOverrideBusy(false);
    }
  };

  return (
    <div className="page-enter">
      <PageHead title="Policy Packs" subtitle={`Showing: ${namespace}`} />
      <Panel
        title="Sector Starter Packs"
        sub="Out-of-box coverage for your sector's flagship risk. Starter templates — tune verbs/thresholds after enabling."
      >
        {packs.loading && <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>Loading policy packs…</div>}
        {packs.error && (
          <div style={{ color: GAP, fontSize: 13 }}>Failed to load policy packs: {String(packs.error)}</div>
        )}
        {!packs.loading && !packs.error && (packs.data?.length ?? 0) === 0 && (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>No sector packs available.</div>
        )}
        {actionError && <div data-testid="pack-action-error" style={{ color: GAP, fontSize: 13, marginBottom: 8 }}>{actionError}</div>}

        {/* Under an aggregate scope ("All namespaces", or "All clusters" with fleet on) a write would target a
            phantom scope that enforces nothing — prompt for a concrete scope and disable every mutation below. */}
        {isAdmin && blockedReason && (
          <div data-testid="pack-scope-prompt" style={{ color: "var(--text-secondary)", fontSize: 13, marginBottom: 8, padding: "8px 12px", border: "1px solid var(--border)", borderRadius: 8 }}>
            {blockedReason}
          </div>
        )}
        {/* Reflect the namespace's apply-mode up-front — dry-run-only means applies are refused server-side. */}
        {isAdmin && !blockedReason && dryRunOnly && (
          <div data-testid="pack-dryrun-banner" style={{ color: GAP, fontSize: 13, marginBottom: 8, padding: "8px 12px", border: `1px solid ${GAP}`, borderRadius: 8 }}>
            This namespace is <span className="mono">dry-run-only</span> — pack applies are disabled. Switch it to Enforce in Target Settings to enable packs.
          </div>
        )}

        {/* A flat, side-by-side grid of ALL packs (~4 per row, wraps + collapses narrow), sector shown per
            card — packs do not stack one-per-sector. */}
        <div className="pack-rail" data-testid="pack-rail">
          {bySector.flatMap(([sector, list]) =>
            list.map((pack) => {
              const suggested = !!suggestedSector && sector.toLowerCase() === suggestedSector;
              return (
                  <div
                    key={pack.id}
                    className="panel"
                    style={{
                      padding: 14,
                      borderRadius: 10,
                      border: "1px solid var(--border)",
                      borderLeft: `3px solid ${pack.enabled ? ON : "var(--border)"}`
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                      <span style={{ fontSize: 10.5, fontWeight: 700, letterSpacing: "0.06em", color: "var(--text-muted)", textTransform: "uppercase" }}>
                        {sector}
                      </span>
                      {suggested && (
                        <span style={{ fontSize: 10, fontWeight: 600, color: ON, background: `${ON}1a`, padding: "1px 7px", borderRadius: 999 }}>
                          Suggested
                        </span>
                      )}
                    </div>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                      <span style={{ fontSize: 14, fontWeight: 600 }}>{pack.title}</span>
                      <span
                        style={{
                          fontSize: 11,
                          fontWeight: 600,
                          color: pack.enabled ? ON : "var(--text-muted)",
                          background: pack.enabled ? `${ON}1a` : "var(--border)",
                          padding: "2px 8px",
                          borderRadius: 999
                        }}
                      >
                        {pack.enabled ? "Enabled" : "Off"}
                      </span>
                    </div>
                    <div style={{ marginTop: 8, fontSize: 13, color: "var(--text-secondary)" }}>{pack.enforces}</div>
                    <div style={{ marginTop: 10, display: "flex", flexWrap: "wrap", gap: 6 }}>
                      {pack.categories.map((c) => (
                        <span key={c} style={{ fontSize: 11, padding: "2px 7px", borderRadius: 6, border: "1px solid var(--border)", color: "var(--text-secondary)" }}>
                          {c}
                        </span>
                      ))}
                      {pack.compliance.slice(0, 3).map((c) => (
                        <span key={c} className="mono" style={{ fontSize: 10.5, padding: "2px 7px", borderRadius: 6, color: "var(--text-muted)" }}>
                          {c}
                        </span>
                      ))}
                    </div>
                    {pack.composes.length > 0 && (
                      <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)" }}>
                        + composes canonical: <span className="mono">{pack.composes.join(", ")}</span>
                      </div>
                    )}
                    <div style={{ marginTop: 12, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <button
                        onClick={() => openRego(pack)}
                        style={{ fontSize: 11, color: "var(--text-secondary)", background: "transparent", border: "none", cursor: "pointer", padding: 0, textDecoration: "underline" }}
                      >
                        View rego ({pack.rule_ids.length} rule{pack.rule_ids.length === 1 ? "" : "s"})
                      </button>
                      {isAdmin ? (
                        <button
                          className="tab-kit"
                          data-testid={`pack-toggle-${pack.id}`}
                          disabled={busyId === pack.id || mutationsDisabled}
                          title={blockedReason ?? (dryRunOnly ? "Namespace is dry-run-only — applies disabled" : undefined)}
                          onClick={() => setConfirmPack(pack)}
                          style={{
                            fontSize: 12,
                            padding: "4px 12px",
                            border: `1px solid ${pack.enabled ? GAP : ON}`,
                            color: pack.enabled ? GAP : ON,
                            background: "transparent",
                            opacity: busyId === pack.id || mutationsDisabled ? 0.5 : 1,
                            cursor: mutationsDisabled ? "not-allowed" : "pointer"
                          }}
                        >
                          {busyId === pack.id ? "…" : pack.enabled ? "Disable" : "Enable"}
                        </button>
                      ) : (
                        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Admin only</span>
                      )}
                    </div>
                  </div>
              );
            })
          )}
        </div>
        {/* Shared with the override flow below (same `applyResult` state) — renders here too so an
            enable/disable toggle above shows its result without requiring a scroll to the second panel. */}
        <ApplyResultPanel result={applyResult} onClose={() => setApplyResult(null)} />
      </Panel>

      {/* Per-namespace tighten-only override — customize pack enforcement; revert restores the original. */}
      <Panel
        title="Customize pack enforcement (tighten-only)"
        sub="A per-namespace override that can ONLY add stricter blocks — it never weakens or removes a pack's block. Revert restores the original pack cleanly."
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <span style={{ fontSize: 11, fontWeight: 600, color: overrideActive ? ON : "var(--text-muted)", background: overrideActive ? `${ON}1a` : "var(--border)", padding: "2px 8px", borderRadius: 999 }}>
            {overrideActive ? "Override active" : "No override"}
          </span>
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>namespace: <span className="mono">{namespace}</span></span>
        </div>
        <div style={{ border: "1px solid var(--border)", borderRadius: 8, overflow: "hidden" }}>
          <Editor
            height="240px"
            defaultLanguage="rego"
            beforeMount={registerRego}
            theme="vs-dark"
            value={overrideRego}
            onChange={(v) => {
              setOverrideRego(v ?? "");
              // A dry-run readout no longer matches the edited rego about to ship — drop it so
              // "Apply override" can't be clicked next to stale numbers.
              setPackDryRun(null);
            }}
            options={{ minimap: { enabled: false }, fontSize: 12.5, readOnly: !isAdmin }}
          />
        </div>
        {isAdmin ? (
          <>
            <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <button className="tab-kit" data-testid="override-dryrun" disabled={overrideBusy || !canMutate} title={blockedReason ?? undefined} onClick={runPackDryRun}
                style={{ fontSize: 12, padding: "4px 12px", border: "1px solid var(--border)", color: "var(--text-secondary)", background: "transparent", opacity: canMutate ? 1 : 0.5, cursor: canMutate ? "pointer" : "not-allowed" }}>
                Dry-Run
              </button>
              <button className="tab-kit" data-testid="override-apply" disabled={overrideBusy || !canMutate || dryRunOnly} title={blockedReason ?? (dryRunOnly ? "Namespace is dry-run-only — applies disabled" : undefined)} onClick={saveOverride}
                style={{ fontSize: 12, padding: "4px 12px", border: `1px solid ${allowWeaken ? GAP : ON}`, color: allowWeaken ? GAP : ON, background: "transparent", opacity: (!canMutate || dryRunOnly) ? 0.5 : 1, cursor: (!canMutate || dryRunOnly) ? "not-allowed" : "pointer" }}>
                {overrideBusy ? "…" : allowWeaken ? "Apply (weaken)" : "Apply override"}
              </button>
              <button className="tab-kit" data-testid="override-revert" disabled={overrideBusy || !overrideActive || !canMutate} title={blockedReason ?? undefined} onClick={revertOverride}
                style={{ fontSize: 12, padding: "4px 12px", border: `1px solid ${GAP}`, color: GAP, background: "transparent", opacity: (overrideActive && canMutate) ? 1 : 0.5, cursor: canMutate ? "pointer" : "not-allowed" }}>
                Revert
              </button>
              {overrideMsg && <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{overrideMsg}</span>}
              {isAdmin && blockedReason && <span data-testid="override-scope-prompt" style={{ fontSize: 12, color: "var(--text-secondary)" }}>{blockedReason}</span>}
            </div>
            {/* The loud, audited Advanced opt-in. Default tighten-only; weaken is bounded by the comprehensive floor. */}
            <label style={{ marginTop: 10, display: "flex", alignItems: "flex-start", gap: 8, fontSize: 12, color: allowWeaken ? GAP : "var(--text-secondary)" }}>
              <input type="checkbox" checked={allowWeaken} onChange={(e) => setAllowWeaken(e.target.checked)} style={{ marginTop: 2 }} />
              <span>
                <strong>Advanced: allow weakening this pack.</strong> Lets an edit RELAX a pack's added block (not just tighten it).
                The comprehensive baseline still applies — a weaken can never drop below your org policy. This is audited
                (<span className="mono">NRVQ-API-7099</span>).
              </span>
            </label>
            {packDryRun && (
              <div style={{ marginTop: 10, padding: "8px 12px", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12.5 }}>
                <span style={{ fontWeight: 600 }}>Dry-Run: </span>
                would block {packDryRun.would_block ?? 0} ({packDryRun.block_rate_pct ?? 0}%), allow {packDryRun.would_allow ?? 0}
                {packDryRun.recommendation ? ` — ${packDryRun.recommendation}` : ""}
              </div>
            )}
          </>
        ) : (
          <div style={{ marginTop: 8, fontSize: 11, color: "var(--text-muted)" }}>Admin only</div>
        )}
      </Panel>

      {viewRego && (
        <>
          <div onClick={() => setViewRego(null)}
            style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,0.5)", zIndex: 30 }} />
          <div style={{ position: "fixed", right: 0, top: 0, bottom: 0, width: 620, maxWidth: "92vw", background: "var(--bg, #111)", borderLeft: "1px solid var(--border,#2a2a2a)", padding: 16, overflow: "auto", zIndex: 31 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <h3 style={{ fontSize: 14 }}>Pack rego — {viewRego.title} <span style={{ color: "var(--text-muted)", fontWeight: 400 }}>(read-only)</span></h3>
              <button onClick={() => setViewRego(null)}>✕</button>
            </div>
            <Editor height="80vh" defaultLanguage="rego" beforeMount={registerRego} theme="vs-dark"
              value={viewRego.rego} options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12 }} />
          </div>
        </>
      )}

      {/* PACK-CONFIRM: enabling/disabling changes live enforcement for THIS namespace — confirm with the
          target named + the composed canonical rules, so a pack can't be flipped by an accidental click. */}
      {confirmPack && (
        <>
          <div className="sheet-overlay" onClick={() => setConfirmPack(null)} />
          <div className="confirm-modal" data-testid="pack-confirm-modal">
            <div className="sheet-title">
              {confirmPack.enabled ? "Disable" : "Enable"} “{confirmPack.title}” for {namespace}?
            </div>
            <div style={{ fontSize: 13, color: "var(--text-secondary)", margin: "8px 0 14px", lineHeight: 1.5 }}>
              {confirmPack.enabled ? (
                <>This removes the pack's enforcing rules from namespace <b style={{ color: "var(--text-primary)" }}>{namespace}</b>. Agents in this namespace will no longer be blocked by these controls.</>
              ) : (
                <>This loads the pack's enforcing rules into namespace <b style={{ color: "var(--text-primary)" }}>{namespace}</b>, effective on the next tool call{confirmPack.composes?.length ? <> — composing canonical rules: <span className="mono">{confirmPack.composes.join(", ")}</span></> : null}.</>
              )}
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
              <KitButton variant="ghost" onClick={() => setConfirmPack(null)}>Cancel</KitButton>
              <KitButton
                variant="primary"
                data-testid="pack-confirm-apply"
                onClick={() => {
                  const p = confirmPack;
                  setConfirmPack(null);
                  void toggle(p);
                }}
              >
                {confirmPack.enabled ? "Disable pack" : "Enable pack"}
              </KitButton>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

export default PolicyPacks;
