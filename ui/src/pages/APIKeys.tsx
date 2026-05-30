import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

export function APIKeys() {
  const { namespace } = useApp();

  return (
    <div className="page-enter">
      <PageHead title="API Keys" subtitle={`Showing: ${namespace}`} />
      <Panel title="Key Management" sub="Create, rotate, and revoke API keys">
        <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>API key management page.</div>
      </Panel>
    </div>
  );
}
