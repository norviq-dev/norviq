import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

export function MITRECoverage() {
  const { namespace } = useApp();

  return (
    <div className="page-enter">
      <PageHead title="MITRE Coverage" subtitle={`Showing: ${namespace}`} />
      <Panel title="ATT&CK Mapping" sub="Coverage by tactic and technique">
        <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>
          MITRE ATT&CK coverage details coming soon.
        </div>
      </Panel>
    </div>
  );
}
