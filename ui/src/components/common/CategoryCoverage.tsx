import { fetchCoverageByCategory } from "../../api/client";
import { useApi } from "../../hooks/useApi";
import { useApp } from "../../store/AppContext";
import { Panel } from "./Panel";

// Real policy coverage per risk category (F046) — fetched from /coverage-by-category for the active
// namespace. No fabricated default scores: an empty/zero-coverage namespace renders empty/zero.
export function CategoryCoverage() {
  const { namespace } = useApp();
  const coverage = useApi(() => fetchCoverageByCategory(namespace), [namespace]);
  const color = (s: number) => (s > 80 ? "#00e5a0" : s >= 60 ? "#ffb020" : "#ff3b5c");
  const items = coverage.data?.categories ?? [];

  return (
    <Panel title="Policy Coverage by Category" sub="Enforced rules per risk category in this namespace">
      {coverage.loading ? (
        <div style={{ color: "var(--text-secondary)", fontSize: 13, marginTop: 4 }}>Loading…</div>
      ) : coverage.error ? (
        <div style={{ color: "var(--block)", fontSize: 13, marginTop: 4 }}>Coverage unavailable.</div>
      ) : items.length === 0 ? (
        <div style={{ color: "var(--text-secondary)", fontSize: 13, marginTop: 4 }}>No coverage data.</div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12, marginTop: 4 }}>
          {items.map((c) => (
            <div key={c.category} style={{ display: "flex", alignItems: "center", gap: 12 }}>
              <span style={{ fontSize: 13, color: "var(--text-secondary)", width: 130, flex: "none" }}>
                {c.category}
              </span>
              <div style={{ flex: 1, height: 10, borderRadius: 3, background: "#1f1f1f", overflow: "hidden" }}>
                <div style={{ width: `${c.score}%`, height: "100%", background: color(c.score), borderRadius: 3 }} />
              </div>
              <span
                style={{ fontSize: 13, fontWeight: 600, color: color(c.score), width: 28, textAlign: "right", flex: "none" }}
                title={`${c.covered}/${c.total} rules enforced`}
              >
                {c.score}
              </span>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}
