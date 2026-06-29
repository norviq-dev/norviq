import { useMemo, useState } from "react";
import {
  disablePolicyPack,
  enablePolicyPack,
  fetchMe,
  fetchPolicyPacks,
  fetchSettings,
  PolicyPack
} from "../api/client";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";

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
                    <div style={{ marginTop: 12, display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                      <span className="mono" style={{ fontSize: 11, color: "var(--text-muted)" }}>
                        {pack.rule_ids.length} rule{pack.rule_ids.length === 1 ? "" : "s"}
                      </span>
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
    </div>
  );
}

export default PolicyPacks;
