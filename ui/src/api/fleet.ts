// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Fleet-api client (F045). Talks to the multi-cluster hub at VITE_FLEET_API_URL, reusing the same
// bearer token as the single-cluster API. The Fleet view appears only when this is configured.

import { authHeaders } from "./client";

const FLEET_BASE = (import.meta.env.VITE_FLEET_API_URL ?? "").replace(/\/+$/, "");

/** True when a fleet hub is configured — gates the Fleet nav entry + page. */
export const fleetEnabled = Boolean(FLEET_BASE);

async function fleetGet<T>(path: string): Promise<T> {
  const res = await fetch(`${FLEET_BASE}${path}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`fleet request failed: ${res.status}`);
  return (await res.json()) as T;
}

export type FleetCluster = {
  id: string;
  name: string;
  region: string;
  endpoint: string;
  last_heartbeat: string | null;
  status: string;
};
export type FleetAgent = {
  cluster_id: string;
  spiffe_id: string;
  namespace: string;
  agent_class: string;
  trust_score: number;
  trust_category: string;
  last_seen: string | null;
};
export type FleetAuditSummary = {
  cluster_id: string;
  allow: number;
  block: number;
  escalate: number;
  audit: number;
  total: number;
};

const clusterParam = (cluster?: string) =>
  cluster && cluster !== "all" ? `cluster=${encodeURIComponent(cluster)}` : "";

export const fetchFleetClusters = () => fleetGet<FleetCluster[]>("/api/v1/fleet/clusters");

export const fetchFleetAgents = (cluster?: string) => {
  const q = clusterParam(cluster);
  return fleetGet<FleetAgent[]>(`/api/v1/fleet/agents${q ? `?${q}` : ""}`);
};

export const fetchFleetAuditSummary = (range = "24h", cluster?: string) => {
  const q = clusterParam(cluster);
  return fleetGet<FleetAuditSummary[]>(`/api/v1/fleet/audit/summary?range=${range}${q ? `&${q}` : ""}`);
};
