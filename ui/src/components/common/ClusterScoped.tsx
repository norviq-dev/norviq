// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// F-69 Stage 2 — per-cluster page gate. A per-cluster DETAIL page (Policy Catalog, Audit, Agents, graphs…) shows the
// data of the cluster this console SERVES. When a REMOTE cluster is selected, that data must NOT render under the
// remote label. This wrapper renders the page only when the selection is local; when remote it renders the honest
// deep-link page instead. Because the wrapped page only mounts when local, its data hooks/fetches and mutating
// controls never run for a remote selection (no rules-of-hooks issue, no local fetch, nothing to mutate).

import { ReactNode } from "react";
import { useApp } from "../../store/AppContext";
import { RemoteClusterPage } from "./RemoteClusterNotice";

export function ClusterScoped({ page, children }: { page: string; children: ReactNode }) {
  const { isRemote, scopeCluster, selectedClusterConsoleUrl } = useApp();
  if (isRemote) {
    return <RemoteClusterPage page={page} cluster={scopeCluster} consoleUrl={selectedClusterConsoleUrl} />;
  }
  return <>{children}</>;
}
