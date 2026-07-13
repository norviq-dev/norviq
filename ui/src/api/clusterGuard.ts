// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// F-69 Stage 1 — the P1 mutation BACKSTOP. The console can have a REMOTE cluster selected (a cluster other than the
// one this console's API actually serves, `servedCluster`). In that state a cluster-scoped WRITE to the LOCAL API
// would silently mutate the served cluster under the remote cluster's label. This module is the single source of
// truth the otherwise-stateless api client checks before sending any mutating request — independent of whatever the
// UI renders or disables. AppContext keeps `remoteContext` in sync with the selected/served cluster.

let remoteContext = false;
let selectedClusterId = "";

/** AppContext calls this whenever isRemote changes. */
export function setRemoteClusterContext(isRemote: boolean): void {
  remoteContext = isRemote;
}

/** AppContext keeps the operator's currently-selected cluster here so mutations can declare their intended target
 *  to the server (R2 backstop). "all"/empty means "no explicit target" → treated as local by the server. */
export function setSelectedClusterId(id: string): void {
  selectedClusterId = id === "all" ? "" : id;
}

/** The X-Nrvq-Target-Cluster header value the client sends on cluster-scoped mutations (R2). */
export function targetClusterHeader(): string {
  return selectedClusterId;
}

export function isRemoteClusterActive(): boolean {
  return remoteContext;
}

// Cluster-scoped MUTATING endpoints on the LOCAL api. A non-GET to any of these while a remote cluster is selected
// would change the served cluster under a remote label — refused. Reads, hub/fleet-api calls (separate fleet.ts
// client), and non-cluster user/account/api-key writes are NOT listed and are never blocked.
const GUARDED: RegExp[] = [
  /^\/api\/v1\/policies(\?|$)/, // create/update a policy
  /^\/api\/v1\/policies\/dry-run(\?|$)/, // dry-run that writes
  /^\/api\/v1\/policies\/[^/]+\/[^/]+\/apply(\?|$)/, // apply a policy to a target
  /^\/api\/v1\/policies\/[^/]+\/[^/]+\/rollback(\?|$)/, // restore a version
  /^\/api\/v1\/policy-packs\//, // enable / disable / F-54 override (POST/DELETE/PUT)
  /^\/api\/v1\/settings(\?|$)/, // apply-mode + other namespace-scoped settings
  /^\/api\/v1\/agents\/[^/]+\/trust(\?|$)/, // trust override
  /^\/api\/v1\/attack-paths\/compute(\?|$)/, // recompute (writes)
  /^\/api\/v1\/evaluate(\?|$)/ // policy-tester / attack simulate (writes an audit record)
];

export const REMOTE_MUTATION_CODE = "NRVQ-UI-4601";

/** True when a mutating call to `path` must be refused because a remote cluster is the active context. */
export function blockedByRemoteCluster(method: string, path: string): boolean {
  if (!remoteContext) return false;
  if (method.toUpperCase() === "GET") return false;
  return GUARDED.some((re) => re.test(path));
}

/** The error thrown by the api client (and shown to the user) when a remote-cluster mutation is refused. */
export function remoteMutationError(): Error {
  return new Error(
    `${REMOTE_MUTATION_CODE}: editing applies to the local cluster only. ` +
      `A remote cluster is selected — open that cluster's own console to change it.`
  );
}
