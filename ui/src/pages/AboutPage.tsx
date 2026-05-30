import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { useApp } from "../store/AppContext";

export function AboutPage() {
  const { namespace } = useApp();

  return (
    <div className="page-enter">
      <PageHead title="About Norviq" subtitle={`Showing: ${namespace}`} />
      <Panel title="Version and Links" sub="Product and licensing details">
        <div className="kv">
          <span className="k">Version</span>
          <span className="mono">0.1.0</span>
        </div>
        <div className="kv">
          <span className="k">License</span>
          <span>Apache 2.0</span>
        </div>
        <div className="kv">
          <span className="k">GitHub</span>
          <a
            href="https://github.com/norviq-dev/norviq"
            target="_blank"
            rel="noreferrer"
            style={{ color: "var(--accent)", textDecoration: "none" }}
          >
            github.com/norviq-dev/norviq ↗
          </a>
        </div>
        <div className="kv">
          <span className="k">Documentation</span>
          <a
            href="https://norviq.dev/docs"
            target="_blank"
            rel="noreferrer"
            style={{ color: "var(--accent)", textDecoration: "none" }}
          >
            norviq.dev/docs ↗
          </a>
        </div>
      </Panel>
    </div>
  );
}
