// Account Settings — a read-only profile card (the identity the server resolved for the session) plus
// a change-password form.

import { useState } from "react";
import { changePassword, fetchMe } from "../api/client";
import { useApi } from "../hooks/useApi";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

export function AccountSettings() {
  const { namespace } = useApp();
  const me = useApi(() => fetchMe(), []);

  const rows: Array<{ label: string; value: string | null | undefined }> = [
    { label: "Name", value: me.data?.name },
    { label: "Email", value: me.data?.email },
    { label: "Subject", value: me.data?.sub },
    { label: "Role", value: me.data?.role },
    { label: "Namespace", value: me.data?.namespace || "all" }
  ];

  return (
    <div className="page-enter">
      <PageHead title="Account Settings" subtitle={`Showing: ${namespace}`} />
      <Panel title="User Profile" sub="The identity the server resolved for your session">
        {me.loading ? (
          <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>Loading…</div>
        ) : me.error ? (
          <div style={{ color: "var(--block)", fontSize: 13 }}>Could not load your profile.</div>
        ) : (
          <table className="tbl">
            <tbody>
              {rows.map((r) => (
                <tr key={r.label} style={{ cursor: "default" }}>
                  <td className="muted" style={{ width: 160 }}>
                    {r.label}
                  </td>
                  <td style={{ fontWeight: 500 }}>{r.value || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      {/* Self-service password change, reachable outside the forced first-login flow. */}
      <ChangePasswordPanel />
    </div>
  );
}

function ChangePasswordPanel() {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ kind: "ok" | "err"; text: string } | null>(null);

  const canSubmit = cur.length > 0 && next.length >= 12 && next === confirm && next !== cur && !busy;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setMsg(null);
    try {
      await changePassword(cur, next);
      setMsg({ kind: "ok", text: "Password changed." });
      setCur("");
      setNext("");
      setConfirm("");
    } catch (err) {
      setMsg({ kind: "err", text: err instanceof Error && err.message ? err.message : "Could not change the password. Check your current one." });
    } finally {
      setBusy(false);
    }
  }

  const field: React.CSSProperties = { width: "100%", maxWidth: 340 };
  return (
    <Panel title="Change Password" sub="Set a new password of at least 12 characters (not your current or the default).">
      <form onSubmit={submit} style={{ display: "flex", flexDirection: "column", gap: 12, maxWidth: 340 }}>
        <div>
          <label className="field-label">Current password</label>
          <input className="input" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} style={field} />
        </div>
        <div>
          <label className="field-label">New password</label>
          <input className="input" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} style={field} />
          {next.length > 0 && next.length < 12 && (
            <div style={{ fontSize: 11.5, color: "var(--escalate)", marginTop: 4 }}>At least 12 characters.</div>
          )}
        </div>
        <div>
          <label className="field-label">Confirm new password</label>
          <input className="input" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} style={field} />
          {confirm.length > 0 && confirm !== next && (
            <div style={{ fontSize: 11.5, color: "var(--block)", marginTop: 4 }}>Passwords don't match.</div>
          )}
        </div>
        {msg && (
          <div style={{ fontSize: 12.5, fontWeight: 600, color: msg.kind === "ok" ? "var(--allow)" : "var(--block)" }}>{msg.text}</div>
        )}
        <button
          type="submit"
          disabled={!canSubmit}
          style={{
            alignSelf: "flex-start",
            height: 36,
            padding: "0 18px",
            borderRadius: 9,
            border: "none",
            background: canSubmit ? "var(--accent)" : "var(--bg-elevated)",
            color: canSubmit ? "var(--bg-void)" : "var(--text-muted)",
            fontFamily: "inherit",
            fontSize: 13,
            fontWeight: 700,
            cursor: canSubmit ? "pointer" : "default"
          }}
        >
          {busy ? "Changing…" : "Change Password"}
        </button>
      </form>
    </Panel>
  );
}
