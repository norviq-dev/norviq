// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { useState } from "react";
import { fetchRedteamCatalog, fetchRedteamTargets, runRedteamSuite, RedteamReport } from "../api/client";
import { useApi } from "../hooks/useApi";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

const RedTeam = () => {
  const { namespace } = useApp();
  const catalog = useApi(() => fetchRedteamCatalog(), []);
  // F-44: the namespace's real seeded agent classes — the suite runs against these (not a synthetic identity).
  const targets = useApi(() => fetchRedteamTargets(namespace), [namespace]);
  const [report, setReport] = useState<RedteamReport | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [target, setTarget] = useState<string>(""); // "" = all seeded classes

  const onRun = async () => {
    setRunning(true);
    setError(null);
    try {
      setReport(await runRedteamSuite(target || undefined, namespace));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Suite run failed");
    } finally {
      setRunning(false);
    }
  };

  const attacks = catalog.data ?? [];
  const seeded = targets.data?.targets ?? [];

  return (
    <div className="page-enter">
      <PageHead title="Red Team" subtitle={`Showing: ${namespace}`} />

      <Panel
        title="Automated Attack Suite"
        sub={
          catalog.loading
            ? "Loading catalog…"
            : `${attacks.length} attack scenarios run against the live policy evaluator`
        }
        action={
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            {/* F-44: choose one seeded class or "All seeded classes" (the suite iterates each). */}
            <select
              className="input"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={running}
              style={{ fontSize: 12, padding: "4px 8px" }}
              aria-label="Target agent class"
            >
              <option value="">All seeded classes{seeded.length ? ` (${seeded.length})` : ""}</option>
              {seeded.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
            <KitButton variant="outline" size="sm" onClick={onRun} disabled={running || catalog.loading}>
              {running ? "Running…" : "Run suite"}
            </KitButton>
          </div>
        }
      >
        {error && <div style={{ color: "var(--block)", fontSize: 13 }}>{error}</div>}
        {report ? (
          <div>
            <div style={{ display: "flex", gap: 18, marginBottom: 12, fontSize: 13 }}>
              <span>
                Passed: <strong style={{ color: "#00e5a0" }}>{report.passed}</strong>/{report.total}
              </span>
              <span>
                Failed: <strong style={{ color: report.failed ? "var(--block)" : "inherit" }}>{report.failed}</strong>
              </span>
              <span>
                Pass rate: <strong>{report.pass_rate}%</strong>
              </span>
              {report.targets?.length ? (
                <span className="muted">
                  Targets: <span className="mono">{report.targets.join(", ")}</span>
                </span>
              ) : null}
            </div>
            <table className="tbl">
              <thead>
                <tr>
                  <th>Attack</th>
                  <th>Agent</th>
                  <th>Category</th>
                  <th>Expected</th>
                  <th>Actual</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {report.results.map((r, i) => (
                  <tr key={`${r.attack_id}-${r.agent_class ?? i}`}>
                    <td>{r.attack_name}</td>
                    <td className="mono muted">{r.agent_class ?? "—"}</td>
                    <td className="mono muted">{r.category}</td>
                    <td className="mono">{r.expected}</td>
                    <td className="mono">{r.actual}</td>
                    <td style={{ color: r.passed ? "#00e5a0" : "var(--block)" }}>{r.passed ? "PASS" : "FAIL"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>
            {catalog.error
              ? "Could not load the attack catalog."
              : "Run the suite to evaluate every catalog attack against this namespace’s loaded policy."}
          </div>
        )}
      </Panel>
    </div>
  );
};

export default RedTeam;
