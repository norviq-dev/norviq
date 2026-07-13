import { useState } from "react";
import { createApiKey, fetchApiKeys, revokeApiKey } from "../api/client";
import { useApi } from "../hooks/useApi";
import { KitButton } from "../components/common/KitButton";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

const ROLES = ["viewer", "service", "admin"] as const;

export function APIKeys() {
  const { namespace } = useApp();
  const keys = useApi(() => fetchApiKeys(), []);
  const [name, setName] = useState("");
  const [role, setRole] = useState<(typeof ROLES)[number]>("viewer");
  const [created, setCreated] = useState<{ prefix: string; key: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onCreate = async () => {
    if (!name.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const k = await createApiKey({ name: name.trim(), namespace, role });
      setCreated({ prefix: k.prefix, key: k.key });
      setName("");
      keys.refetch();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not create key");
    } finally {
      setBusy(false);
    }
  };

  const onRevoke = async (id: string) => {
    try {
      await revokeApiKey(id);
      keys.refetch();
    } catch {
      setError("Could not revoke key");
    }
  };

  const rows = keys.data ?? [];

  return (
    <div className="page-enter">
      <PageHead title="API Keys" subtitle={`Showing: ${namespace}`} />

      <Panel title="Issue a Key" sub="Create a scoped API key. The secret is shown only once.">
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <input
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="key name"
            style={{ flex: 1, minWidth: 160 }}
          />
          <select className="input" value={role} onChange={(e) => setRole(e.target.value as (typeof ROLES)[number])}>
            {ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <KitButton variant="outline" size="sm" onClick={onCreate} disabled={busy || !name.trim()}>
            {busy ? "Creating…" : "Create key"}
          </KitButton>
        </div>
        {error && <div style={{ color: "var(--block)", fontSize: 13, marginTop: 10 }}>{error}</div>}
        {created && (
          <div
            style={{ marginTop: 12, padding: 12, borderRadius: 8, background: "var(--bg-elevated, #161616)", border: "1px solid var(--accent)" }}
          >
            <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 6 }}>
              Copy this secret now — it will not be shown again.
            </div>
            <code className="mono" style={{ fontSize: 13, wordBreak: "break-all", color: "#00e5a0" }}>
              {created.key}
            </code>
          </div>
        )}
      </Panel>

      <Panel title="Active Keys" sub="Issued keys (secrets are never stored or shown again)">
        {keys.loading ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>Loading…</div>
        ) : keys.error ? (
          <div style={{ color: "var(--block)", fontSize: 13 }}>Could not load keys.</div>
        ) : rows.length === 0 ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>No API keys issued.</div>
        ) : (
          <table className="tbl">
            <thead>
              <tr>
                <th>Prefix</th>
                <th>Name</th>
                <th>Role</th>
                <th>Namespace</th>
                <th>Last used</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((k) => (
                <tr key={k.id}>
                  <td className="mono">{k.prefix}…</td>
                  <td>{k.name || "—"}</td>
                  <td className="mono">{k.role}</td>
                  <td className="mono muted">{k.namespace}</td>
                  <td className="mono muted">{k.last_used_at ? new Date(k.last_used_at).toLocaleString() : "never"}</td>
                  <td style={{ color: k.revoked ? "var(--block)" : "#00e5a0" }}>{k.revoked ? "Revoked" : "Active"}</td>
                  <td>
                    {!k.revoked && (
                      <KitButton variant="outline" size="sm" onClick={() => onRevoke(k.id)}>
                        Revoke
                      </KitButton>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
