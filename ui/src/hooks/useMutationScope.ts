// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// B1-2: a namespace-scoped (and, under fleet, cluster-scoped) mutation must never target a phantom AGGREGATE scope.
// The console defaults the view to "All namespaces" (and, with fleet on, can select "All clusters") — writing a
// pack enable / override / apply-mode toggle under that aggregate stores a row literally namespaced "all", which
// enforces NOTHING (a concrete namespace's read never sees it). This hook is the single source of truth for
// "can this page apply a namespace/cluster-scoped change right now, and if not, why" — every mutating control gates
// on `canMutate` and shows `blockedReason`.

import { fleetEnabled } from "../api/fleet";
import { useApp } from "../store/AppContext";

export type MutationScope = {
  /** True only when a CONCRETE namespace (and, under fleet, a concrete non-remote cluster) is selected. */
  canMutate: boolean;
  /** Inline prompt to show at the disabled control when a mutation cannot target a concrete scope; else null. */
  blockedReason: string | null;
  /** The aggregate "All namespaces" sentinel is selected. */
  isAggregateNamespace: boolean;
  /** Fleet on AND the aggregate "All clusters" sentinel (or no concrete cluster) is selected. */
  isAggregateCluster: boolean;
};

export function useMutationScope(): MutationScope {
  const { namespace, selectedCluster, isRemote } = useApp();
  const isAggregateNamespace = !namespace || namespace === "all";
  // Fleet OFF (GA single-cluster): there is only the served cluster, so the cluster arm is always a no-op here.
  // Fleet ON: "all" (or an empty selection) is the aggregate "All clusters" sentinel and must not be written to.
  const isAggregateCluster = fleetEnabled && (!selectedCluster || selectedCluster === "all");

  let blockedReason: string | null = null;
  if (isAggregateNamespace && isAggregateCluster) blockedReason = "Select a namespace and a cluster to apply changes.";
  else if (isAggregateNamespace) blockedReason = "Select a namespace to apply changes.";
  else if (isAggregateCluster) blockedReason = "Select a cluster to apply changes.";

  // A remote (non-served) cluster already blocks local mutations (F-69); fold it in so the control stays disabled.
  const canMutate = !isAggregateNamespace && !isAggregateCluster && !isRemote;
  return { canMutate, blockedReason, isAggregateNamespace, isAggregateCluster };
}
