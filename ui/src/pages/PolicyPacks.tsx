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
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApi } from "../hooks/useApi";
import { registerRego } from "../lib/monaco-rego";
import { useApp } from "../store/AppContext";

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
  const [actionError, setActionError] = useState<string | null>(null);

  // F-54: view a pack's rego (read-only) + author a tighten-only per-namespace override.
  const [viewRego, setViewRego] = useState<{ title: string; rego: string } | null>(null);
  const [overrideRego, setOverrideRego] = useState("");
  const [overrideActive, setOverrideActive] = useState(false);
  const [overrideMsg, setOverrideMsg] = useState<string | null>(null);
  const [overrideBusy, setOverrideBusy] = useState(false);
  // fleet-mgmt: the loud "Advanced: allow weakening this pack" opt-in + dry-run + apply-result transparency.
  const [allowWeaken, setAllowWeaken] = useState(false);
  const [packDryRun, setPackDryRun] = useState<{ would_block?: number; would_allow?: number; block_rate_pct?: number; recommendation?: string } | null>(null);
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null);
  useEffect(() => {
    fetchPackOverride(namespace)
      .then((o) => { setOverrideActive(o.active); setOverrideRego(o.rego_source || OVERRIDE_TEMPLATE); setAllowWeaken(o.mode === "weaken"); })
      .catch(() => { setOverrideActive(false); setOverrideRego(OVERRIDE_TEMPLATE); });
  }, [namespace]);

  const isAdmin = me.data?.role === "admin";
  const suggestedSector = (settings.data?.sector ?? "").toLowerCase();

  const bySector = useMemo(() => {
    const groups = new Map<string, PolicyPack[]>();
    for (const p of packs.data ?? []) {
      const list = groups.get(p.sector) ?? [];
      list.push(p);
      groups.set(p.sector, list);
    }
    return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [packs.data]);

  const toggle = async (pack: PolicyPack) => {
    setActionError(null);
    setBusyId(pack.id);
    try {
      if (pack.enabled) await disablePolicyPack(pack.id, namespace);
      else await enablePolicyPack(pack.id, namespace);
      await packs.refetch();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Action failed");
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
        {actionError && <div style={{ color: GAP, fontSize: 13, marginBottom: 8 }}>{actionError}</div>}

        {bySector.map(([sector, list]) => {
          const suggested = suggestedSector && sector.toLowerCase() === suggestedSector;
          return (
            <div key={sector} style={{ marginBottom: 18 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                <span style={{ fontSize: 12, fontWeight: 600, letterSpacing: "0.06em", color: "var(--text-secondary)", textTransform: "uppercase" }}>
                  {sector}
                </span>
                {suggested && (
                  <span style={{ fontSize: 11, fontWeight: 600, color: ON, background: `${ON}1a`, padding: "1px 8px", borderRadius: 999 }}>
                    Suggested for your sector
                  </span>
                )}
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))", gap: 12 }}>
                {list.map((pack) => (
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
                          disabled={busyId === pack.id}
                          onClick={() => toggle(pack)}
                          style={{
                            fontSize: 12,
                            padding: "4px 12px",
                            border: `1px solid ${pack.enabled ? GAP : ON}`,
                            color: pack.enabled ? GAP : ON,
                            background: "transparent",
                            opacity: busyId === pack.id ? 0.5 : 1
                          }}
                        >
                          {busyId === pack.id ? "…" : pack.enabled ? "Disable" : "Enable"}
                        </button>
                      ) : (
                        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Admin only</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </Panel>

      {/* F-54: per-namespace tighten-only override — customize pack enforcement; revert restores the original. */}
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
            onChange={(v) => setOverrideRego(v ?? "")}
            options={{ minimap: { enabled: false }, fontSize: 12.5, readOnly: !isAdmin }}
          />
        </div>
        {isAdmin ? (
          <>
            <div style={{ marginTop: 8, display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <button className="tab-kit" disabled={overrideBusy} onClick={runPackDryRun}
                style={{ fontSize: 12, padding: "4px 12px", border: "1px solid var(--border)", color: "var(--text-secondary)", background: "transparent" }}>
                Dry-Run
              </button>
              <button className="tab-kit" disabled={overrideBusy} onClick={saveOverride}
                style={{ fontSize: 12, padding: "4px 12px", border: `1px solid ${allowWeaken ? GAP : ON}`, color: allowWeaken ? GAP : ON, background: "transparent" }}>
                {overrideBusy ? "…" : allowWeaken ? "Apply (weaken)" : "Apply override"}
              </button>
              <button className="tab-kit" disabled={overrideBusy || !overrideActive} onClick={revertOverride}
                style={{ fontSize: 12, padding: "4px 12px", border: `1px solid ${GAP}`, color: GAP, background: "transparent", opacity: overrideActive ? 1 : 0.5 }}>
                Revert
              </button>
              {overrideMsg && <span style={{ fontSize: 12, color: "var(--text-secondary)" }}>{overrideMsg}</span>}
            </div>
            {/* fleet-mgmt: the loud, audited Advanced opt-in. Default tighten-only; weaken is bounded by the comprehensive floor. */}
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
        <ApplyResultPanel result={applyResult} onClose={() => setApplyResult(null)} />
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
    </div>
  );
}

export default PolicyPacks;
