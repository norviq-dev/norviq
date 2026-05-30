import { Sparkles } from "lucide-react";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

export function AttackGraph() {
  const { namespace } = useApp();

  return (
    <div className="page-enter">
      <PageHead title="Attack Graph" subtitle={`Showing: ${namespace}`} />
      <Panel title="Threat Relationships" sub="Attack-path graph for selected namespace">
        <div style={{ color: "var(--text-secondary)", fontSize: 13 }}>Attack graph visualization coming soon.</div>
      </Panel>
      <div
        style={{
          marginTop: 16,
          background: "#171717",
          border: "1px dashed #2A2A2A",
          borderRadius: 12,
          padding: "14px 16px",
          display: "flex",
          alignItems: "flex-start",
          gap: 10
        }}
      >
        <Sparkles size={18} style={{ color: "#666666", marginTop: 1, flex: "none" }} />
        <div>
          <div style={{ color: "var(--text-primary)", fontSize: 14, fontWeight: 600 }}>Threat Predictions</div>
          <div style={{ color: "var(--text-secondary)", fontSize: 12, marginTop: 3 }}>
            AI-powered threat prediction coming in Phase 3
          </div>
        </div>
      </div>
    </div>
  );
}
