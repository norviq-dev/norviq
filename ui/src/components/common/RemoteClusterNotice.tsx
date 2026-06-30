// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// F-69 — the honest "this isn't at the fleet hub" surface. When a REMOTE cluster is selected, the hub only has
// KPI/trust rollups, not per-spoke detail — so instead of rendering the LOCAL cluster's data under the remote
// label, we show this notice with a deep-link to the remote cluster's OWN console (when its console_url is known).
//
//   - RemoteScopedPanel: a tile/panel placeholder (used for individual Overview tiles the hub can't fill).
//   - RemoteClusterPage:  a whole-page placeholder (used by <ClusterScoped> for per-cluster detail pages).

import { Panel } from "./Panel";
import { PageHead } from "./PageHead";

/** Shared inner body: the wording + the deep-link (or a non-dead fallback when console_url is unknown). */
function NoticeBody({ what, cluster, consoleUrl }: { what: string; cluster: string; consoleUrl?: string }) {
  return (
    <div style={{ color: "var(--text-muted)", fontSize: 13, lineHeight: 1.7, textAlign: "center" }}>
      {what} isn’t aggregated at the fleet hub for{" "}
      <span className="mono" style={{ color: "var(--text-secondary)" }}>{cluster}</span>.
      <div style={{ marginTop: 12 }}>
        {consoleUrl ? (
          <a
            href={consoleUrl}
            target="_blank"
            rel="noreferrer"
            className="btn btn-primary"
            style={{ textDecoration: "none" }}
          >
            Open {cluster}’s console →
          </a>
        ) : (
          <span style={{ color: "var(--text-secondary)" }}>
            Open <span className="mono">{cluster}</span>’s own console to view this.
          </span>
        )}
      </div>
    </div>
  );
}

/** Tile variant — drop-in for an Overview panel the hub can't fill for a remote cluster. */
export function RemoteScopedPanel({
  title,
  sub,
  cluster,
  consoleUrl
}: {
  title: string;
  sub?: string;
  cluster: string;
  consoleUrl?: string;
}) {
  return (
    <Panel title={title} sub={sub}>
      <div style={{ padding: "28px 12px" }}>
        <NoticeBody what="This" cluster={cluster} consoleUrl={consoleUrl} />
      </div>
    </Panel>
  );
}

/** Full-page variant — what <ClusterScoped> renders for a per-cluster detail page when a remote cluster is picked. */
export function RemoteClusterPage({
  page,
  cluster,
  consoleUrl
}: {
  page: string;
  cluster: string;
  consoleUrl?: string;
}) {
  return (
    <div className="page-enter">
      <PageHead title={page} subtitle={`Viewing ${cluster} — summary only at the fleet hub`} />
      <Panel title={page}>
        <div style={{ padding: "48px 16px" }}>
          <NoticeBody what={`Per-cluster ${page.toLowerCase()}`} cluster={cluster} consoleUrl={consoleUrl} />
        </div>
      </Panel>
    </div>
  );
}
