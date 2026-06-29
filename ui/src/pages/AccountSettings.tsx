import { fetchMe } from "../api/client";
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
    </div>
  );
}
