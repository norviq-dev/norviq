import { useState } from "react";
import { apiGet } from "../api/client";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

type ConnectionStatus = "ok" | "checking" | "offline";
type Connection = {
  name: string;
  conn: string;
  url: string;
  status: ConnectionStatus;
  ms?: string;
};
const INITIAL_CONNECTIONS: Connection[] = [
  { name: "API", conn: "http://localhost:8080", url: "/healthz", status: "checking" },
  { name: "Redis", conn: "redis://:****@127.0.0.1:6379", url: "/healthz", status: "checking", ms: "—" },
  { name: "PostgreSQL", conn: "postgresql://****@127.0.0.1:5432", url: "/healthz", status: "checking", ms: "—" },
  { name: "OTel", conn: "http://127.0.0.1:4317", url: "/healthz", status: "checking", ms: "—" }
];

export function ConnectionSettings() {
  const { namespace } = useApp();
  const [connections, setConnections] = useState<Connection[]>(INITIAL_CONNECTIONS);

  const testConnection = async (name: string) => {
    setConnections((prev) => prev.map((c) => (c.name === name ? { ...c, status: "checking" } : c)));
    const start = performance.now();
    try {
      await apiGet<{ status: string }>("/healthz");
      const ms = `${Math.round(performance.now() - start)}ms`;
      setConnections((prev) => prev.map((c) => (c.name === name ? { ...c, status: "ok", ms } : c)));
    } catch {
      setConnections((prev) => prev.map((c) => (c.name === name ? { ...c, status: "offline", ms: "—" } : c)));
    }
  };

  return (
    <div className="page-enter">
      <PageHead title="Connections" subtitle={`Showing: ${namespace}`} />
      <Panel title="System Connections" sub="Redis, PostgreSQL, and OTel status">
        <div style={{ overflowX: "auto" }}>
          <table className="tbl">
            <tbody>
              {connections.map((c) => {
                const color =
                  c.status === "ok" ? "#00e5a0" : c.status === "checking" ? "#ffb020" : "#ff3b5c";
                const label =
                  c.status === "ok" ? "Connected" : c.status === "checking" ? "Checking…" : "Disconnected";
                return (
                  <tr key={c.name} style={{ cursor: "default" }}>
                    <td style={{ fontWeight: 500 }}>{c.name}</td>
                    <td className="mono muted" style={{ fontSize: 12 }}>
                      {c.conn}
                    </td>
                    <td>
                      <span style={{ display: "inline-flex", alignItems: "center", gap: 7, color, fontSize: 13 }}>
                        <span style={{ width: 8, height: 8, borderRadius: 99, background: "currentColor" }} />
                        {label}
                      </span>
                    </td>
                    <td className="mono muted">{c.ms ?? "—"}</td>
                    <td>
                      <KitButton variant="outline" size="sm" onClick={() => testConnection(c.name)}>
                        Test
                      </KitButton>
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
