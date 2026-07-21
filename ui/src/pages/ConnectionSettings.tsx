// Connection Settings — a live readiness view of the platform's real dependencies (API, Database,
// Redis, OPA) sourced from the /readyz probe.

import { useCallback, useEffect, useState } from "react";
import { fetchReadiness, Readiness } from "../api/client";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

// The real dependencies the API readiness probe reports on. `key` maps to a /readyz field; "api" is
// implicit (a JSON response means the API answered). No fabricated connection strings or statuses.
const SERVICES: Array<{ name: string; key: keyof Readiness | "api" }> = [
  { name: "API", key: "api" },
  { name: "Database", key: "db" },
  { name: "Redis", key: "redis" },
  { name: "OPA", key: "opa" }
];

type Phase = "loading" | "ready" | "error";

export function ConnectionSettings() {
  const { namespace } = useApp();
  const [readiness, setReadiness] = useState<Readiness | null>(null);
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [phase, setPhase] = useState<Phase>("loading");

  const probe = useCallback(async () => {
    setPhase("loading");
    const start = performance.now();
    try {
      const data = await fetchReadiness();
      setReadiness(data);
      setLatencyMs(Math.round(performance.now() - start));
      setPhase("ready");
    } catch {
      setReadiness(null);
      setLatencyMs(null);
      setPhase("error");
    }
  }, []);

  useEffect(() => {
    void probe();
  }, [probe]);

  // A dependency the probe doesn't report (e.g. opa in non-server mode) is "n/a", not a fabricated status.
  const statusOf = (key: keyof Readiness | "api"): { color: string; label: string } => {
    if (phase === "loading") return { color: "#ffb020", label: "Checking…" };
    if (phase === "error" || !readiness) return { color: "#ff3b5c", label: "Unreachable" };
    if (key === "api") return { color: "#00e5a0", label: "Connected" };
    const v = readiness[key];
    if (v === undefined) return { color: "#6b7280", label: "n/a" };
    return v ? { color: "#00e5a0", label: "Connected" } : { color: "#ff3b5c", label: "Disconnected" };
  };

  return (
    <div className="page-enter">
      <PageHead title="Connections" subtitle={`Showing: ${namespace}`} />
      <Panel
        title="System Connections"
        sub="Live readiness of the API and its dependencies (Database, Redis, OPA)"
        action={
          <KitButton variant="outline" size="sm" onClick={() => void probe()}>
            Re-check
          </KitButton>
        }
      >
        <div style={{ overflowX: "auto" }}>
          <table className="tbl">
            <tbody>
              {SERVICES.map((svc) => {
                const { color, label } = statusOf(svc.key);
                return (
                  <tr key={svc.name} style={{ cursor: "default" }}>
                    <td style={{ fontWeight: 500 }}>{svc.name}</td>
                    <td>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 7, color, fontSize: 13 }}>
                        <span style={{ width: 8, height: 8, borderRadius: 99, background: "currentColor" }} />
                        {label}
                      </span>
                    </td>
                    <td className="mono muted">
                      {svc.key === "api" && phase === "ready" && latencyMs !== null ? `${latencyMs}ms` : "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
