import { useMemo } from "react";
import { fetchMitreCoverage } from "../api/client";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";

const COVERED = "#00e5a0";
const GAP = "#ff5c7c";

export function MITRECoverage() {
  const { namespace } = useApp();
  const coverage = useApi(() => fetchMitreCoverage(namespace), [namespace], {
    cacheKey: `mitre-coverage:${namespace}`,
    staleTimeMs: 30_000
  });

  const techniques = useMemo(() => coverage.data?.techniques ?? [], [coverage.data]);
  const covered = coverage.data?.covered ?? 0;
  const total = coverage.data?.total ?? 0;
  const pct = total > 0 ? Math.round((covered / total) * 100) : 0;

  return (
    <div className="page-enter">
      <PageHead title="MITRE Coverage" subtitle={`Showing: ${namespace}`} />
      <Panel
        title="ATLAS Coverage"
        sub="Adversarial ML techniques mapped to active Norviq policies"
        action={
          <span className="mono" style={{ fontSize: 13, color: covered > 0 ? COVERED : "var(--text-muted)" }}>
            {covered}/{total} covered · {pct}%
          </span>
        }
      >
        {coverage.loading && <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>Loading coverage…</div>}
        {coverage.error && (
          <div style={{ color: GAP, fontSize: 13 }}>Failed to load MITRE coverage: {String(coverage.error)}</div>
        )}
        {!coverage.loading && !coverage.error && techniques.length === 0 && (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>No ATLAS techniques mapped.</div>
        )}

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
            gap: 12
          }}
        >
          {techniques.map((t) => (
            <div
              key={t.technique_id}
              className="panel"
              style={{
                padding: 14,
                borderRadius: 10,
                border: "1px solid var(--border)",
                borderLeft: `3px solid ${t.covered ? COVERED : GAP}`
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                <span className="mono" style={{ fontSize: 12, color: "var(--text-muted)" }}>
                  {t.technique_id}
                </span>
                <span
                  style={{
                    fontSize: 11,
                    fontWeight: 600,
                    color: t.covered ? COVERED : GAP,
                    background: `${t.covered ? COVERED : GAP}1a`,
                    padding: "2px 8px",
                    borderRadius: 999
                  }}
                >
                  {t.covered ? "Covered" : "Gap"}
                </span>
              </div>
              <div style={{ marginTop: 8, fontSize: 14, fontWeight: 600 }}>{t.name}</div>
              <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 6 }}>
                {t.policies.map((p) => {
                  const active = t.covered_policies.includes(p);
                  return (
                    <span
                      key={p}
                      className="mono"
                      title={active ? "Active in this namespace" : "Mapped but not loaded here"}
                      style={{
                        fontSize: 11,
                        padding: "2px 7px",
                        borderRadius: 6,
                        border: "1px solid var(--border)",
                        color: active ? "var(--text-secondary)" : "var(--text-muted)",
                        opacity: active ? 1 : 0.6
                      }}
                    >
                      {p}
                    </span>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

export default MITRECoverage;
