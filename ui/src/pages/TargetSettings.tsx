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
import { BaselineControls } from "../components/policies/BaselineControls";
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

  // A posture we have not READ is not a posture. Both knobs used to resolve an absent `settings.data` to
  // their reassuring value (`?.x === "audit" ? "audit" : "block"`, `?.x === "dry_run_only" ? … : "enforce"`),
  // so a 5xx / 403 / offline API left this page highlighting "Block" and "Live" — the console stating, in
  // the same pixels it uses for a measured answer, that the namespace is enforcing and its policy is live.
  // `null` = not known yet: no tab is `active`, neither consequence sentence is asserted, and a failed read
  // says so in text. (The tabs stay rendered and keep their testids — they are the CONTROL, and an admin can
  // still set a posture from a page that could not read one.)
  const settingsKnown = settings.data != null;
  const applyMode = settingsKnown
    ? settings.data?.apply_mode === "dry_run_only"
      ? "dry_run_only"
      : "enforce"
    : null;
  // TGT-POSTURE-01: the enforcement axis (Block ⇄ Monitor). Wire value stays block|audit; "audit" is DISPLAYED
  // as "Monitor" so it doesn't collide with the `audit` decision or the Audit Log.
  const enforcementMode = settingsKnown ? (settings.data?.enforcement_mode === "audit" ? "audit" : "block") : null;
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

  // `.tab-kit` has NO disabled styling of its own (index.css gives `:disabled` opacity only to `.btn`), so a
  // read-only segmented control rendered byte-for-byte like a live one — a viewer had no way to tell that the
  // highlighted tab was a reading rather than a control they could work. Dim it inline; the reason itself is
  // visible text below (a disabled control can never surface a `title`).
  const tabsReadOnly = !isAdmin || !canMutate;
  const readOnlyTabStyle = tabsReadOnly ? { opacity: 0.55, cursor: "not-allowed" } : undefined;
  // "Admin only" is a fact about the CONTROL and is always true. "read-only for your ROLE" is a claim about
  // the reader, and `isAdmin` is false for three different reasons: they are not an admin, /me has not
  // answered yet, or /me FAILED — in which case telling an admin their role is read-only states, as fact,
  // something we could not read. Say only what is known in each case.
  const permissionNote = me.error
    ? "Admin only — your role could not be read, so these controls are disabled."
    : me.data
    ? "Admin only — read-only for your role."
    : "Admin only";
  // The posture read itself faulted (not merely in flight): the knobs below show no state at all, so say why
  // rather than leaving two un-highlighted toggles to be read as "nothing is set".
  const postureUnreadable = !settingsKnown && !!settings.error;

  const enabledPacks = (packs.data ?? []).filter((p) => p.enabled);
  // Bind the subtitle/working-scope label to the ACTUAL working scope — never "Namespace: all" over data.
  const scopeLabel = namespace === "all" ? "All namespaces" : `Namespace: ${namespace}`;
  const concrete = namespace !== "all";

  return (
    <div className="page-enter">
      <PageHead title="Namespace Governance" subtitle={scopeLabel} />

      <Panel title="Governance" sub="How this namespace is governed right now (server-enforced).">
        {/* GRID, not a wrapping flex. Each of these three knobs carries a variable amount of state
            text underneath it — a Monitor note here, a frozen note there, a pack list that grows with
            the namespace — so as flex items they sized to their own content and the columns landed at
            three different widths that moved every time the posture changed. An explicit track keeps
            the three reading as peers, and `alignItems: start` stops a tall column stretching the
            short ones. `auto-fit` collapses them to one column on a narrow viewport rather than
            letting the 300px note blocks overhang. */}
        <div style={{
          display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(clamp(240px, 30%, 320px), 1fr))",
          gap: 20, alignItems: "start",
        }}>
          <div style={{ minWidth: 0 }}>
            {/* TGT-POSTURE-01: the block-vs-observe axis is now an editable toggle (Block ⇄ Monitor). */}
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>Enforcement mode</div>
            <div className="tabs-kit" style={{ display: "flex" }}>
              {(["block", "audit"] as const).map((m) => (
                <button key={m} data-testid={`enforcement-mode-${m}`} className={`tab-kit${enforcementMode === m ? " active" : ""}`}
                  disabled={!isAdmin || savingMode || !canMutate}
                  title={blockedReason ?? undefined}
                  style={readOnlyTabStyle}
                  onClick={() => setEnforcement(m)}>
                  {m === "audit" ? "Monitor" : "Block"}
                </button>
              ))}
            </div>
            {/* TGT-POSTURE-01 — WHAT THE MODE MEANS IS STATE, NOT PERMISSION. This sentence used to be
                gated on `isAdmin`, so the reader most likely to be AUDITING posture — the one who cannot
                change it — got the bare words "Monitor" and "Admin only" and had to infer from them that
                nothing is being stopped. (From "Frozen" they were as likely to infer the opposite of the
                truth: that ENFORCEMENT, not policy editing, was frozen.) The global header chip is not a
                fallback — its visible text is the two words "Monitor mode", with the consequence only in a
                `title` tooltip — so this page is the only place in the console where the consequence exists
                as readable text. Permission is stated separately, at the control it applies to.
                The second line is the /settings caveat: `_effective` merges the CLUSTER-WIDE default
                (`row.enforcement_mode if row … else app_settings.enforcement_mode`) while the engine softens
                ONLY on an explicit per-namespace override (`_resolve_posture`: "a null/global mode does NO
                softening"), so "Monitor" here is not on its own proof that THIS namespace is softened. */}
            {enforcementMode === "audit" && (concrete ? (
              <div data-testid="enforcement-monitor-note"
                style={{ fontSize: 11, color: "var(--block, #ff5c7c)", marginTop: 4, maxWidth: 300 }}>
                Monitor — a matched rule logs a would-block instead of stopping the call.
                <div style={{ color: "var(--text-muted)", marginTop: 2 }}>
                  The engine softens calls only where this namespace sets Monitor itself; this reading also
                  reflects the cluster-wide default.
                </div>
              </div>
            ) : (
              // NOT "the cluster-wide default is Monitor". `fetchSettings("all")` DROPS the namespace param
              // (client.ts: `if (namespace && namespace !== "all")`), and the endpoint's own signature is
              // `namespace: str = Query("default")` — so an unscoped read resolves to the namespace literally
              // named `default` and returns THAT row merged with the global (`_effective`). Whenever `default`
              // carries its own enforcement_mode, "the cluster-wide default is Monitor" is a statement about a
              // value nothing on this page read. Name the reading instead of inventing a scope for it.
              <div data-testid="enforcement-monitor-note-aggregate"
                style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4, maxWidth: 300 }}>
                Monitor is what the unscoped Settings read returns — the <span className="mono">default</span>{" "}
                namespace merged with the cluster-wide default. It is not a posture for every namespace, and the
                engine softens traffic only where a namespace sets Monitor itself — pick a namespace to see its own.
              </div>
            ))}
            {postureUnreadable && (
              <div data-testid="enforcement-mode-unreadable" style={{ fontSize: 11, color: "var(--escalate)", marginTop: 4, maxWidth: 300 }}>
                This namespace&apos;s enforcement mode could not be read — <b>unknown, not Block</b>.
                <span style={{ color: "var(--text-muted)" }}> {settings.error}</span>
              </div>
            )}
            {!isAdmin && <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>{permissionNote}</div>}
          </div>
          <div style={{ minWidth: 0 }}>
            {/* Change control (apply governance) — a policy-EDIT lock, not a traffic mode. Wire values enforce|dry_run_only. */}
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>Change control — policy edits</div>
            <div className="tabs-kit" style={{ display: "flex" }}>
              {(["enforce", "dry_run_only"] as const).map((m) => (
                <button key={m} data-testid={`apply-mode-${m}`} className={`tab-kit${applyMode === m ? " active" : ""}`}
                  disabled={!isAdmin || savingMode || !canMutate}
                  title={blockedReason ?? undefined}
                  style={readOnlyTabStyle}
                  onClick={() => setApply(m)}>
                  {m === "enforce" ? "Live" : "Frozen"}
                </button>
              ))}
            </div>
            {modeMsg && <div style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>{modeMsg}</div>}
            {/* Prompt for a concrete scope when an aggregate is selected. */}
            {isAdmin && blockedReason && <div data-testid="apply-mode-scope-prompt" style={{ fontSize: 11, color: "var(--text-secondary)", marginTop: 4 }}>{blockedReason}</div>}
            {/* Make the frozen consequence explicit at the control that sets it — for EVERY reader, not just
                the one who can change it (see the enforcement note above). Unlike enforcement_mode there is
                no cluster-wide merge here: settings_router `_effective` reads apply_mode from the row alone
                (`row.apply_mode if row and row.apply_mode else "enforce"`), so this sentence is true of the
                namespace as written. */}
            {applyMode === "dry_run_only" && (
              <div data-testid="apply-mode-dryrun-note" title="Frozen freezes POLICY EDITS for this namespace; the live policy still enforces."
                style={{ fontSize: 11, color: "var(--block, #ff5c7c)", marginTop: 4 }}>
                Frozen — policy edits are frozen (live policy still enforces).
              </div>
            )}
            {postureUnreadable && (
              <div data-testid="apply-mode-unreadable" style={{ fontSize: 11, color: "var(--escalate)", marginTop: 4, maxWidth: 300 }}>
                Change control could not be read — <b>unknown, not Live</b>.
              </div>
            )}
            {!isAdmin && <div style={{ fontSize: 11, color: "var(--text-muted)", marginTop: 4 }}>{permissionNote}</div>}
          </div>
          <div style={{ minWidth: 0 }}>
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>Sector packs applied</div>
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
      {/* The baseline itself, control by control. Sits below the namespace knobs because those decide
          the POSTURE (does this namespace enforce at all) while these decide WHAT it enforces —
          reading top-down gives an operator the two questions in the order they actually ask them. */}
      <BaselineControls namespace={namespace} isAdmin={isAdmin} />
    </div>
  );
}

export default TargetSettings;
