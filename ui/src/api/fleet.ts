// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Fleet-api client (F045). Talks to the multi-cluster hub at VITE_FLEET_API_URL, reusing the same
// bearer token as the single-cluster API. The Fleet view appears only when this is configured.

import { authHeaders } from "./client";

// F-25: build-time VITE_FLEET_API_URL OR the runtime-injected window.__NRVQ_CONFIG__.fleetApiUrl (config.js,
// written by the container entrypoint from FLEET_API_URL) — one built image, configured per cluster.
const FLEET_BASE = (
  import.meta.env.VITE_FLEET_API_URL ??
  (typeof window !== "undefined" ? window.__NRVQ_CONFIG__?.fleetApiUrl : "") ??
  ""
).replace(/\/+$/, "");

/** True when a fleet hub is configured — gates the Fleet nav entry + page. */
export const fleetEnabled = Boolean(FLEET_BASE);

async function fleetGet<T>(path: string): Promise<T> {
  const res = await fetch(`${FLEET_BASE}${path}`, { headers: authHeaders() });
  if (!res.ok) throw new Error(`fleet request failed: ${res.status}`);
  return (await res.json()) as T;
}

async function fleetSend<T>(path: string, method: string, body: unknown): Promise<T> {
  const res = await fetch(`${FLEET_BASE}${path}`, {
    method,
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body)
  });
  if (!res.ok) {
    // F-33: surface the server's validation detail instead of a bare status code.
    let detail = "";
    try {
      const j = (await res.json()) as { detail?: unknown };
      if (j?.detail) detail = `: ${typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail)}`;
    } catch { /* non-JSON body */ }
    throw new Error(`fleet request failed (${res.status})${detail}`);
  }
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

// --- P2: signed policy push + per-cluster rollout status ---
export type FleetRollout = {
  cluster_id: string;
  bundle_version: number;
  state: string; // pending | applied | failed | diverged
  applied_version: number;
  updated_at: string | null;
};

export type FleetPolicyAuthor = {
  name: string;
  namespace: string;
  agent_class: string;
  rego_source: string;
  priority?: number;
  enforcement_mode?: string;
  target_selector?: Record<string, string>;
  confirm_fleet_wide?: boolean; // F-40: required for a fleet-wide (no cluster_id) target
};

export const fetchFleetRollout = () => fleetGet<FleetRollout[]>("/api/v1/fleet/rollout");

export const authorFleetPolicy = (body: FleetPolicyAuthor) =>
  fleetSend<{ name: string; version: number }>("/api/v1/fleet/policies", "POST", body);

// --- P3: live drill-down into one cluster's audit (P4 residency may block it) ---
export type FleetAuditRecord = {
  timestamp: string;
  tool_name: string;
  decision: string;
  agent_class: string;
  namespace: string;
  rule_id: string;
};

export const fetchFleetDrilldown = (cluster: string, limit = 50) =>
  fleetGet<{ records: FleetAuditRecord[]; residency_blocked?: boolean }>(
    `/api/v1/fleet/clusters/${encodeURIComponent(cluster)}/audit/records?limit=${limit}`
  );
