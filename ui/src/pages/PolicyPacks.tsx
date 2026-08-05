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
  PolicyPack,
  type DryRunReplay
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

const OVERRIDE_TEMPLATE = `# Per-namespace override for this namespace's sector pack(s). DEFAULT MODE: tighten-only.
# In tighten-only mode you can ADD stricter blocks; you cannot weaken/remove a pack's block.
# Ticking "Advanced: allow weakening this pack" below stores this as a WEAKEN overlay instead —
# in THAT mode an edit CAN relax a block the pack adds (still floored by your comprehensive baseline).
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
  // A pack is enabled PER NAMESPACE. At the aggregate scope the API cannot answer that question and
  // does not try: `fetchPolicyPacks` omits `?namespace`, and the route defaults it to "default" — so
  // every row describes ONE namespace while the page header says "all". Everything that renders
  // enabled-state keys off this so the console never reports the default namespace's posture as the
  // estate's.
  const aggregateScope = namespace === "all";
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
  // Enabling/disabling a pack changes live enforcement for the selected
  // namespace with a single click and no target shown. Gate it behind a confirm that NAMES the
  // namespace + the direction + the composed rules.
  const [confirmPack, setConfirmPack] = useState<PolicyPack | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  // View a pack's rego (read-only) + author a per-namespace override — tighten-only by default, or a
  // WEAKEN overlay behind the audited Advanced opt-in below.
  const [viewRego, setViewRego] = useState<{ title: string; rego: string } | null>(null);
  const [overrideRego, setOverrideRego] = useState("");
  const [overrideActive, setOverrideActive] = useState(false);
  const [overrideMsg, setOverrideMsg] = useState<string | null>(null);
  const [overrideBusy, setOverrideBusy] = useState(false);
  // The loud "Advanced: allow weakening this pack" opt-in + dry-run + apply-result transparency.
  // NOTE: `allowWeaken` is the operator's PENDING intent for the next Apply (it follows the checkbox).
  // It is NOT a readout of what is currently enforced — `overrideMode` below is. Conflating the two would
  // let an unapplied tick claim a weaken overlay is live, or an untick hide one that is.
  const [allowWeaken, setAllowWeaken] = useState(false);
  // The LIVE overlay's mode exactly as the server reports it ("tighten-only" | "weaken"), or null when no
  // overlay is loaded. `undefined` mode on an ACTIVE overlay stays unknown — never silently "tighten-only".
  const [overrideMode, setOverrideMode] = useState<string | null>(null);
  // A failed override read is not "no override": it is "we could not tell". Kept separate so the status
  // pill can say so instead of rendering the confident absent state over an unread namespace.
  const [overrideLoadError, setOverrideLoadError] = useState<string | null>(null);
  // …and neither is an IN-FLIGHT read. A read that has not landed yet is exactly as unmeasured as one that
  // failed, and it starts true on mount: without this the pill rendered the confident "No override" over a
  // namespace whose overlay had not been read, which is the same claim the failed-read branch above exists
  // to prevent. It also stops the PREVIOUS namespace's `overrideActive` from being reinterpreted against
  // this namespace's freshly-cleared `overrideMode` (that combination printed "Override active — mode
  // unreported" plus an "an overlay is loaded for <ns>" banner for a namespace never read).
  const [overrideLoading, setOverrideLoading] = useState(true);
  const [packDryRun, setPackDryRun] = useState<DryRunReplay | null>(null);
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null);
  useEffect(() => {
    // Switching namespace reloads THIS ns's override rego — the dry-run / apply-result / message
    // panels below describe the PREVIOUS ns's rego and must be cleared too (the onChange-only clear
    // doesn't fire on a namespace switch).
    // `cancelled` guards the switch race: without it a slow read of ns A that lands after the operator has
    // moved to ns B writes A's active/mode/rego over B's, i.e. one namespace's enforcement posture shown as
    // another's — the same lie the pill states below, arriving by a different route.
    let cancelled = false;
    setPackDryRun(null);
    setApplyResult(null);
    setOverrideMsg(null);
    setOverrideMode(null);
    setOverrideLoadError(null);
    // Drop the previous namespace's ANSWER, not just its mode. Leaving `overrideActive` set while clearing
    // `overrideMode` is what manufactured "Override active — mode unreported" for an unread namespace.
    setOverrideActive(false);
    setAllowWeaken(false);
    setOverrideLoading(true);
    fetchPackOverride(namespace)
      .then((o) => {
        if (cancelled) return;
        setOverrideActive(o.active);
        setOverrideRego(o.rego_source || OVERRIDE_TEMPLATE);
        setAllowWeaken(o.mode === "weaken");
        // Mode is only meaningful while an overlay is actually loaded (packs.py returns the tighten-only
        // default even for the empty case), so drop it when nothing is active.
        setOverrideMode(o.active ? (o.mode ?? null) : null);
        setOverrideLoading(false);
      })
      .catch((e) => {
        if (cancelled) return;
        setOverrideActive(false);
        setOverrideMode(null);
        setAllowWeaken(false);
        setOverrideRego(OVERRIDE_TEMPLATE);
        setOverrideLoadError((e instanceof Error ? e.message : String(e)).replace(/^Error:\s*/, ""));
        setOverrideLoading(false);
      });
    return () => { cancelled = true; };
  }, [namespace]);

  const isAdmin = me.data?.role === "admin";
  const suggestedSector = (settings.data?.sector ?? "").toLowerCase();
  // Never let a namespace/cluster-scoped mutation target the phantom aggregate ("all"). Reflect the
  // namespace's apply-mode up-front so "dry-run-only — applies disabled" shows BEFORE a click.
  const { canMutate, blockedReason } = useMutationScope();
  const dryRunOnly = settings.data?.apply_mode === "dry_run_only";
  const mutationsDisabled = !canMutate || dryRunOnly;

  // What is ENFORCED right now, read off the server's reported mode — never off the Advanced checkbox.
  // packs.py's GET /policy-packs/override emits `"mode": "weaken" if weaken else "tighten-only"`.
  const weakenLive = overrideActive && overrideMode === "weaken";
  const tightenLive = overrideActive && overrideMode === "tighten-only";
  // Active overlay whose mode the server did not report: we know something is overlaid but not whether it
  // can relax a pack block. Say that, rather than defaulting the safer-sounding of the two.
  const overrideModeUnknown = overrideActive && !weakenLive && !tightenLive;

  // --- Dry-run readout, read strictly off what the server actually reported. -------------------------
  // Every count below is `number | null`: ABSENT IS NOT ZERO. `?? 0` on any of these paints a measured
  // zero-impact result out of a field the response never carried — the same defect the total_records_checked
  // branch exists to prevent, one line further down. (Same doctrine as BuilderSheet's newly-blocked count.)
  const asCount = (v: number | undefined): number | null => (typeof v === "number" ? v : null);
  const drTotal = asCount(packDryRun?.total_records_checked);
  const drBlock = asCount(packDryRun?.would_block);
  const drAllow = asCount(packDryRun?.would_allow);
  const drEscalate = asCount(packDryRun?.would_escalate);
  const drRatePct = asCount(packDryRun?.block_rate_pct);
  // `total_records_checked` is the number of audit rows FETCHED; `_replay_recent` then `continue`s past any
  // row that is synthetic identity traffic or whose per-record OPA call threw, so those rows land in the
  // total but in NONE of the three outcome buckets. Printing the total beside block/allow without naming
  // that gap leaves visible arithmetic that does not close, and an operator to guess which number is wrong.
  const drOutcomeSum = drBlock !== null && drAllow !== null && drEscalate !== null ? drBlock + drAllow + drEscalate : null;
  const drUnsimulated = drTotal !== null && drOutcomeSum !== null ? drTotal - drOutcomeSum : null;
  // A compile failure is NOT a fact about the namespace's traffic. The server answers an uncompilable rego
  // with valid:false + errors + a zeroed replay block; rendering that through the traffic branch told the
  // operator their namespace was idle when the truth was that their policy was broken.
  const drInvalid = packDryRun?.valid === false;

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
      const r = await dryRunPolicy({
        namespace,
        // Dry-run's `agent_class` selects WHICH RECORDS ARE REPLAYED — it is not the key the overlay is
        // stored under. The server's `_replay_recent` (norviq/api/routers/policies.py) adds
        // `where(AuditLogEntry.agent_class == agent_class)` only when the field is truthy, and its docstring
        // says "a class-less (namespace/workload) policy replays the whole namespace".
        // `__pack_override__` is the LOADER key this overlay is STORED under; no audit record ever carries it
        // as its calling agent's class, so sending it filtered EVERY namespace down to zero rows and the
        // server then answered "No recent real traffic for this scope" — blaming the namespace's traffic for
        // what was a malformed request. This overlay is namespace-scoped, so it must replay the whole
        // namespace: send "". Identical reasoning and identical fix to BuilderSheet's namespace/workload tiers.
        agent_class: "",
        rego_source: overrideRego
      });
      setPackDryRun(r);
    } catch (e) {
      // Never leave the previous run's numbers on screen underneath a failure notice — a stale readout next
      // to "Dry-run failed" reads as a measurement of the rego that is about to ship.
      setPackDryRun(null);
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
      // The status pill reads the LIVE mode — move it now, or a just-applied WEAKEN overlay would keep
      // advertising the previous (tighten-only / none) posture until a reload. Prefer the server's own
      // reported mode; fall back to the opt-in we just sent and it accepted.
      setOverrideLoadError(null);
      setOverrideMode(res.mode ?? (allowWeaken ? "weaken" : "tighten-only"));
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
      setOverrideMode(null);
      setOverrideLoadError(null);
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
      {/* The subtitle must not read "Showing: all" over per-namespace state it cannot show. */}
      <PageHead
        title="Policy Packs"
        subtitle={aggregateScope
          ? "Showing: all — a pack is enabled per namespace, so pick one to see which are on"
          : `Showing: ${namespace}`}
      />
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
                      borderLeft: `3px solid ${aggregateScope ? "var(--border)" : pack.enabled ? ON : "var(--border)"}`
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
                      {/*
                        AT THE AGGREGATE SCOPE THIS PILL CANNOT BE ANSWERED, so it does not pretend to be.
                        `fetchPolicyPacks` omits `?namespace` for "all", and the route declares
                        `namespace: str = Query("default")` — so the API answers for the DEFAULT namespace
                        and echoes it on every row. Rendering that as "Enabled"/"Off" under a header
                        reading "Showing: all" reports ONE namespace's posture as the estate's, on a
                        control surface, with nothing on screen naming the namespace it actually described.
                        The row already carries `pack.namespace`; nothing read it.
                        Fixed HERE and not in the client: sending `?namespace=all` is strictly worse
                        (scoped_namespace returns "all" verbatim for an admin, no rows match a namespace
                        literally named "all", and every live pack would render "Off" — a live control
                        shown as absent), and making the call throw would break TargetSettings, which calls
                        the same function at this scope and already guards correctly.
                      */}
                      <span
                        data-testid={`pack-state-${pack.id}`}
                        title={aggregateScope
                          ? "Enabled state is per namespace — pick one to see it"
                          : `In namespace ${pack.namespace ?? namespace}`}
                        style={{
                          fontSize: 11,
                          fontWeight: 600,
                          color: aggregateScope ? "var(--text-muted)" : pack.enabled ? ON : "var(--text-muted)",
                          background: aggregateScope ? "transparent" : pack.enabled ? `${ON}1a` : "var(--border)",
                          border: aggregateScope ? "1px solid var(--border)" : undefined,
                          padding: "2px 8px",
                          borderRadius: 999
                        }}
                      >
                        {aggregateScope ? "— per namespace" : pack.enabled ? "Enabled" : "Off"}
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

      {/* Per-namespace pack override — TWO modes. The default overlay is tighten-only, but the audited
          Advanced opt-in below authors a WEAKEN overlay that CAN relax a pack's added block
          (norviq/api/routers/packs.py `_WEAKEN_KEY`, norviq/engine/evaluator.py's `__pack_weaken__` candidate).
          The behaviour is deliberate and bounded by the comprehensive floor — it is the old blanket
          "it never weakens or removes a pack's block" COPY that was false, so the copy and the status pill
          are now driven by the mode the server reports for this namespace. */}
      <Panel
        title="Customize pack enforcement"
        sub={
          <>
            A per-namespace overlay on this namespace's sector pack(s). <b>By default it is tighten-only</b> — it can
            only ADD stricter blocks, and cannot weaken or remove a block the pack adds. The <b>Advanced</b> opt-in
            below instead authors a <b>WEAKEN</b> overlay, which <b>can relax a block the pack adds</b> (your
            comprehensive baseline still floors every decision, so it cannot drop below org policy). Revert restores
            the original pack cleanly.
          </>
        }
      >
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
          <span
            data-testid="override-status-pill"
            style={{
              fontSize: 11,
              fontWeight: 600,
              color: overrideLoading
                ? "var(--text-muted)"
                : overrideLoadError || overrideModeUnknown
                ? "var(--escalate)"
                : weakenLive
                ? GAP
                : tightenLive
                ? ON
                : "var(--text-muted)",
              background: !overrideLoading && weakenLive ? `${GAP}1a` : !overrideLoading && tightenLive ? `${ON}1a` : "var(--border)",
              padding: "2px 8px",
              borderRadius: 999
            }}
          >
            {/* Loading is checked FIRST: until the read lands this namespace's posture is unmeasured, and
                "No override" is a measurement claim. */}
            {overrideLoading
              ? "Reading override…"
              : overrideLoadError
              ? "Override state unknown"
              : weakenLive
              ? "WEAKEN overlay active"
              : overrideModeUnknown
              ? "Override active — mode unreported"
              : tightenLive
              ? "Tighten-only override active"
              : "No override"}
          </span>
          <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>namespace: <span className="mono">{namespace}</span></span>
        </div>
        {/* A live relaxation must be legible without scrolling past a 240px editor to read a checkbox. */}
        {weakenLive && (
          <div data-testid="override-weaken-live" style={{ color: GAP, fontSize: 12.5, marginBottom: 8, padding: "8px 12px", border: `1px solid ${GAP}`, borderRadius: 8, lineHeight: 1.5 }}>
            A <b>WEAKEN</b> overlay is live for <span className="mono">{namespace}</span>. Pack enforcement here is{" "}
            <b>not tighten-only</b> — this overlay can RELAX a block its sector pack(s) add. Your comprehensive
            baseline is still a floor. Revert to restore the pack unmodified.
          </div>
        )}
        {overrideModeUnknown && (
          <div data-testid="override-mode-unknown" style={{ color: "var(--escalate)", fontSize: 12.5, marginBottom: 8, padding: "8px 12px", border: "1px solid var(--border)", borderRadius: 8, lineHeight: 1.5 }}>
            An overlay is loaded for <span className="mono">{namespace}</span>, but this server did not report whether
            it is tighten-only or a WEAKEN overlay. Treat pack enforcement here as <b>unverified</b> — it may relax a
            pack's block.
          </div>
        )}
        {overrideLoadError && (
          <div data-testid="override-load-error" style={{ color: "var(--escalate)", fontSize: 12.5, marginBottom: 8, padding: "8px 12px", border: "1px solid var(--border)", borderRadius: 8, lineHeight: 1.5 }}>
            Could not read this namespace's pack override — {overrideLoadError}. This is <b>not</b> "no override":
            a tighten-only or WEAKEN overlay may be live and enforced. The editor below shows the blank template,
            not this namespace's current overlay. <b>Revert is unavailable</b> until this read succeeds — it is
            gated on a loaded overlay, so reload this page before trying to remove one.
          </div>
        )}
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
            {/* Always state HOW MANY records were replayed. Without it, "would block 0, allow 0" from a
                zero-record replay renders byte-identically to a real 0-of-500 zero-impact result — the reading
                an operator takes into "Apply (weaken)". A replay that measured nothing must say so. */}
            {packDryRun && (
              <div data-testid="override-dryrun-result" style={{ marginTop: 10, padding: "8px 12px", border: "1px solid var(--border)", borderRadius: 8, fontSize: 12.5, lineHeight: 1.5 }}>
                <span style={{ fontWeight: 600 }}>Dry-Run: </span>
                {drInvalid ? (
                  <span data-testid="override-dryrun-invalid" style={{ color: GAP }}>
                    the rego in the editor did <b>not compile</b>, so nothing was replayed — the zeros below the
                    fold are not impact numbers and say nothing about this namespace's traffic.
                    {(packDryRun.errors?.length ?? 0) > 0 && (
                      <> Errors: <span className="mono">{packDryRun.errors!.join(" · ")}</span></>
                    )}
                  </span>
                ) : drTotal === null ? (
                  <span style={{ color: "var(--escalate)" }}>
                    this server did not report how many recent calls were replayed, so this run's impact numbers are
                    not readable — not measured, not zero.
                  </span>
                ) : drTotal === 0 ? (
                  <span style={{ color: "var(--escalate)" }}>
                    replayed <b>0</b> recent calls in <span className="mono">{namespace}</span> — nothing was simulated.
                    This is <b>not</b> a zero-impact result.
                  </span>
                ) : (
                  <>
                    replayed {drTotal} recent call{drTotal === 1 ? "" : "s"} in <span className="mono">{namespace}</span> —{" "}
                    would block{" "}
                    {drBlock === null ? <span style={{ color: "var(--escalate)" }}>not reported</span> : drBlock} (
                    {drRatePct === null ? <span style={{ color: "var(--escalate)" }}>rate not reported</span> : `${drRatePct}%`}
                    ), escalate{" "}
                    {drEscalate === null ? <span style={{ color: "var(--escalate)" }}>not reported</span> : drEscalate}, allow{" "}
                    {drAllow === null ? <span style={{ color: "var(--escalate)" }}>not reported</span> : drAllow}
                    {drUnsimulated !== null && drUnsimulated !== 0 && (
                      <span data-testid="override-dryrun-unsimulated" style={{ color: "var(--escalate)" }}>
                        {drUnsimulated > 0 ? (
                          <>
                            {" "}— {drUnsimulated} of those {drTotal} produced no simulated decision (synthetic traffic,
                            or the engine skipped the record) and are counted in none of the three outcomes above.
                          </>
                        ) : (
                          // Buckets that exceed the total are a self-contradicting response. Rendering it without
                          // saying so would show an inconsistency as a measurement.
                          <>
                            {" "}— these do not reconcile: the outcomes above total {drOutcomeSum} against{" "}
                            {drTotal} records replayed. Do not read them as impact until the server is checked.
                          </>
                        )}
                      </span>
                    )}
                    {packDryRun.truncated === true && (
                      <span data-testid="override-dryrun-truncated" style={{ color: "var(--escalate)" }}>
                        {" "}The replay hit the server's record cap, so older calls in the window were never replayed —
                        these are lower bounds, not the full window.
                      </span>
                    )}
                  </>
                )}
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

      {/* Enabling/disabling changes live enforcement for THIS namespace — confirm with the
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
