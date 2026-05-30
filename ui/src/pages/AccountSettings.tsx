import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

export function AccountSettings() {
  const { namespace } = useApp();

  return (
    <div className="page-enter">
      <PageHead title="Account Settings" subtitle={`Showing: ${namespace}`} />
      <Panel title="User Profile" sub="Manage account profile and preferences">
        <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>Account settings page.</div>
      </Panel>
    </div>
  );
}
