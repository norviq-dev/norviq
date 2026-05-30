import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

export function TargetSettings() {
  const { namespace } = useApp();

  return (
    <div className="page-enter">
      <PageHead title="Target Settings" subtitle={`Showing: ${namespace}`} />
      <Panel title="Policy Targeting" sub="Agent class, workload, and namespace targeting">
        <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>
          Target configuration UI coming soon.
        </div>
      </Panel>
    </div>
  );
}
