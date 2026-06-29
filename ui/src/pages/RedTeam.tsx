// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

import { useState } from "react";
import { fetchRedteamCatalog, runRedteamSuite, RedteamReport } from "../api/client";
import { useApi } from "../hooks/useApi";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

const RedTeam = () => {
  const { namespace } = useApp();
  const catalog = useApi(() => fetchRedteamCatalog(), []);
  const [report, setReport] = useState<RedteamReport | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onRun = async () => {
    setRunning(true);
    setError(null);
    try {
      setReport(await runRedteamSuite(undefined, namespace));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Suite run failed");
    } finally {
      setRunning(false);
    }
  };

  const attacks = catalog.data ?? [];

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
          <KitButton variant="outline" size="sm" onClick={onRun} disabled={running || catalog.loading}>
            {running ? "Running…" : "Run suite"}
          </KitButton>
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
            </div>
            <table className="tbl">
              <thead>
                <tr>
                  <th>Attack</th>
                  <th>Category</th>
                  <th>Expected</th>
                  <th>Actual</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {report.results.map((r) => (
                  <tr key={r.attack_id}>
                    <td>{r.attack_name}</td>
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
