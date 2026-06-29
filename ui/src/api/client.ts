// Base URL for the API. Default "" = relative paths (same-origin): the vite proxy in dev and the
// UI's nginx (`location /api/`) in prod both forward to the API — so the browser only ever talks to
// its own origin (always browser-reachable). Set VITE_API_BASE_URL to an absolute origin only for a
// split-origin deploy where the API has its own ingress (requires CORS on the API).
import { oidcEnabled, oidcLogout } from "../auth/oidc";

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/+$/, "");

/** Resolve an API path against the configured base (relative by default). */
export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

/**
 * Build request headers with the bearer token (when present). Shared by every fetch helper so
 * GETs authenticate exactly like POST/PUT/DELETE — without it, /api/v1/agents and other
 * auth-required GETs 401. Extra headers (e.g. Content-Type) are merged in.
 */
/** Clear the stored JWT and redirect home, forcing re-auth via the AppContext bootstrap. */
export function logout(): void {
  if (oidcEnabled) {
    void oidcLogout();
    return;
  }
  localStorage.removeItem("nrvq_token");
  window.location.href = "/";
}

export function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const token = localStorage.getItem("nrvq_token");
  return {
    ...(extra ?? {}),
    ...(token ? { Authorization: `Bearer ${token}` } : {})
  };
}

/** Resolve a WebSocket URL: derive ws/wss + host from API_BASE when set, else same-origin. */
export function wsUrl(path: string): string {
  if (API_BASE) {
    const u = new URL(API_BASE);
    return `${u.protocol === "https:" ? "wss:" : "ws:"}//${u.host}${path}`;
  }
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${window.location.host}${path}`;
}

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(apiUrl(path), { headers: authHeaders() });
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return (await response.json()) as T;
}

export async function apiSend<T>(path: string, method: "POST" | "PUT" | "DELETE", body?: unknown): Promise<T> {
  const response = await fetch(apiUrl(path), {
    method,
    headers: authHeaders({ "Content-Type": "application/json" }),
    body: body ? JSON.stringify(body) : undefined
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed: ${response.status}`);
  }
  return (await response.json()) as T;
}

export async function fetchAuditStats(
  range: string = "24h",
  namespace?: string
): Promise<{ total?: number; blocked?: number; allowed?: number; block_rate_pct?: number }> {
  const params = new URLSearchParams({ range });
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  return apiGet<{ total?: number; blocked?: number; allowed?: number; block_rate_pct?: number }>(
    `/api/v1/audit/stats?${params.toString()}`
  );
}

export async function fetchAuditRecords(filters: {
  range?: string;
  namespace?: string;
  decision?: string;
  tool_name?: string;
  limit?: number;
  offset?: number;
}): Promise<
  Array<{
    id?: string;
    timestamp: string;
    tool_name: string;
    decision: "allow" | "block" | "escalate" | "audit";
    rule_id?: string;
    namespace?: string;
    latency_ms?: number;
    agent_id?: string;
    agent_class?: string;
    reason?: string;
    session_id?: string;
    trust_score?: number;
  }>
> {
  const params = new URLSearchParams();
  Object.entries(filters).forEach(([key, value]) => {
    if (key === "namespace" && (value === "all" || value === "" || value === null || value === undefined)) return;
    if (value !== undefined && value !== null && value !== "") params.set(key, String(value));
  });
  return apiGet<
    Array<{
      id?: string;
      timestamp: string;
      tool_name: string;
      decision: "allow" | "block" | "escalate" | "audit";
      rule_id?: string;
      namespace?: string;
      latency_ms?: number;
      agent_id?: string;
      agent_class?: string;
      reason?: string;
      session_id?: string;
      trust_score?: number;
    }>
  >(`/api/v1/audit/records?${params.toString()}`);
}

export async function fetchTopBlocked(range: string = "24h", namespace?: string): Promise<Array<{ tool_name: string; count: number }>> {
  const params = new URLSearchParams({ range });
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  return apiGet<Array<{ tool_name: string; count: number }>>(`/api/v1/audit/top-blocked?${params.toString()}`);
}

export async function fetchVolume(
  range: string = "24h",
  namespace?: string
): Promise<Array<{ time: string; allow: number; block: number }>> {
  const params = new URLSearchParams({ range });
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  return apiGet<Array<{ time: string; allow: number; block: number }>>(`/api/v1/audit/volume?${params.toString()}`);
}

export type MitreTechnique = {
  technique_id: string;
  name: string;
  policies: string[];
  covered_policies: string[];
  covered: boolean;
};
export type MitreCoverage = {
  namespace: string;
  covered: number;
  total: number;
  techniques: MitreTechnique[];
};

export async function fetchMitreCoverage(namespace?: string): Promise<MitreCoverage> {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  const query = params.toString();
  return apiGet<MitreCoverage>(query ? `/api/v1/mitre/coverage?${query}` : "/api/v1/mitre/coverage");
}

export async function fetchAgents(namespace?: string): Promise<Array<{ category?: string }>> {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  const query = params.toString();
  return apiGet<Array<{ category?: string }>>(query ? `/api/v1/agents?${query}` : "/api/v1/agents");
}

export type SearchAuditRecord = { tool_name?: string; decision?: string; timestamp?: string };
export type SearchAgent = {
  spiffe_id?: string;
  agent_class?: string;
  score?: number;
  trust_score?: number;
  category?: string;
};
export type SearchPolicy = { namespace?: string; agent_class?: string; mode?: string };

async function apiGetWithSignal<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(apiUrl(path), { signal, headers: authHeaders() });
  if (!response.ok) throw new Error(`Request failed: ${response.status}`);
  return (await response.json()) as T;
}

export async function fetchAuditRecordsByTool(
  toolName: string,
  limit: number = 5,
  signal?: AbortSignal
): Promise<SearchAuditRecord[]> {
  return apiGetWithSignal<SearchAuditRecord[]>(
    `/api/v1/audit/records?tool_name=${encodeURIComponent(toolName)}&limit=${limit}`,
    signal
  );
}

export async function fetchAllAgents(signal?: AbortSignal): Promise<SearchAgent[]> {
  return apiGetWithSignal<SearchAgent[]>("/api/v1/agents", signal);
}

export async function fetchPolicies(signal?: AbortSignal): Promise<SearchPolicy[]> {
  return apiGetWithSignal<SearchPolicy[]>("/api/v1/policies", signal);
}

export async function dryRunPolicy(data: {
  namespace: string;
  agent_class: string;
  rego_source: string;
}): Promise<{
  total_records_checked?: number;
  would_block?: number;
  would_allow?: number;
  block_rate_pct?: number;
  recommendation?: string;
}> {
  return apiSend<{
    total_records_checked?: number;
    would_block?: number;
    would_allow?: number;
    block_rate_pct?: number;
    recommendation?: string;
  }>("/api/v1/policies/dry-run", "POST", data);
}

export async function applyPolicy(
  namespace: string,
  agentClass: string,
  data: {
    target_type: string;
    target_namespace: string;
    target_name?: string;
    target_kind?: string;
    enforcement_mode: string;
  }
): Promise<{ applied?: boolean }> {
  return apiSend<{ applied?: boolean }>(
    `/api/v1/policies/${encodeURIComponent(namespace)}/${encodeURIComponent(agentClass)}/apply`,
    "POST",
    data
  );
}
