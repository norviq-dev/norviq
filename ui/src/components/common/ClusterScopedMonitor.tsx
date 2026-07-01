// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// fleet-mgmt Stage 3 — centralize MONITOR-class pages. Unlike <ClusterScoped> (which always deep-links a remote
// cluster), this wrapper renders the page from HUB-RELAYED data for a remote cluster — but only when that data is
// FRESH and the spoke is not residency-restricted. Otherwise it gracefully falls back to the F-69 deep-link, so the
// hub never shows stale/empty data as if it were live. Local selection renders the real page unchanged.

import { ReactNode, useEffect, useState } from "react";
import { useApp } from "../../store/AppContext";
import { fetchFleetClusters, type FleetCluster } from "../../api/fleet";
import { RemoteClusterPage } from "./RemoteClusterNotice";

// A spoke whose last heartbeat is older than this is treated as stale -> deep-link instead of showing old data.
const FRESH_WINDOW_S = 120;

export function freshnessLabel(lastHeartbeat: string | null): { fresh: boolean; text: string } {
  if (!lastHeartbeat) return { fresh: false, text: "no heartbeat yet" };
  const ageS = Math.max(0, (Date.now() - new Date(lastHeartbeat).getTime()) / 1000);
  const ago = ageS < 60 ? `${Math.round(ageS)}s` : `${Math.round(ageS / 60)}m`;
  return { fresh: ageS <= FRESH_WINDOW_S, text: `as of last heartbeat (${ago} ago)` };
}

export function FreshnessBadge({ lastHeartbeat }: { lastHeartbeat: string | null }) {
  const f = freshnessLabel(lastHeartbeat);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12, fontSize: 12, color: "var(--text-muted)" }}>
      <span style={{ width: 8, height: 8, borderRadius: 999, background: f.fresh ? "var(--success,#30a46c)" : "var(--warning,#f5a623)" }} />
      Relayed to the hub — {f.text}. Mutations + raw audit stay on the spoke's own console.
    </div>
  );
}

/**
 * page: title for the deep-link fallback. hubView(cluster): the hub-data render for a remote cluster.
 * children: the real (local) page.
 */
export function ClusterScopedMonitor({
  page,
  hubView,
  children
}: {
  page: string;
  hubView: (cluster: string, lastHeartbeat: string | null) => ReactNode;
  children: ReactNode;
}) {
  const { isRemote, scopeCluster, selectedCluster, selectedClusterConsoleUrl } = useApp();
  const [cluster, setCluster] = useState<FleetCluster | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (!isRemote) return;
    let live = true;
    fetchFleetClusters()
      .then((cs) => live && (setCluster(cs.find((c) => c.id === selectedCluster) ?? null), setLoaded(true)))
      .catch(() => live && setLoaded(true));
    return () => {
      live = false;
    };
  }, [isRemote, selectedCluster]);

  if (!isRemote) return <>{children}</>;
  if (!loaded) return <div style={{ padding: 24, color: "var(--text-secondary)" }}>Loading {scopeCluster}…</div>;

  // Graceful fallback: a stale/unreachable spoke, or a residency-restricted one (raw detail never leaves it), stays
  // on the honest deep-link — never show stale or empty data as if it were live.
  const fresh = cluster && freshnessLabel(cluster.last_heartbeat).fresh && cluster.status !== "stale";
  if (!fresh) {
    return <RemoteClusterPage page={page} cluster={scopeCluster} consoleUrl={selectedClusterConsoleUrl} />;
  }
  return <>{hubView(selectedCluster, cluster!.last_heartbeat)}</>;
}
