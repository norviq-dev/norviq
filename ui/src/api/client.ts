// Base URL for the API. Default "" = relative paths (same-origin): the vite proxy in dev and the
// UI's nginx (`location /api/`) in prod both forward to the API — so the browser only ever talks to
// its own origin (always browser-reachable). Set VITE_API_BASE_URL to an absolute origin only for a
// split-origin deploy where the API has its own ingress (requires CORS on the API).
import { oidcEnabled, oidcLogout } from "../auth/oidc";
import { blockedByRemoteCluster, remoteMutationError, targetClusterHeader } from "./clusterGuard";

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

/** LOGIN-1: a 401 means the session is invalid/expired — clear it and route to the login screen (never a
 *  silent failure or a blank console). OIDC users re-auth via the login screen's SSO button. */
function handleUnauthorized(): void {
  localStorage.removeItem("nrvq_token");
  if (window.location.pathname !== "/login") {
    window.location.assign("/login");
  }
}

export async function apiGet<T>(path: string): Promise<T> {
  const response = await fetch(apiUrl(path), { headers: authHeaders() });
  if (response.status === 401) {
    handleUnauthorized();
    throw new Error("Unauthorized");
  }
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`);
  }
  return (await response.json()) as T;
}

export async function apiSend<T>(path: string, method: "POST" | "PUT" | "DELETE", body?: unknown): Promise<T> {
  // F-69 Stage 1: never send a cluster-scoped mutation to the LOCAL api while a REMOTE cluster is the active
  // context — it would change the served cluster under a remote label. Refuse before the fetch (hard backstop;
  // the UI also routes remote pages to a deep-link, but this guarantees it even if a control slips through).
  if (blockedByRemoteCluster(method, path)) throw remoteMutationError();
  // R2: declare the operator's intended target cluster so the SERVER can refuse a mutation aimed at another
  // cluster (X-Nrvq-Target-Cluster). The UI guard above already blocks remote mutations, so this header equals the
  // served cluster on any request that actually gets here — the server check is the backstop for non-SPA callers.
  const target = targetClusterHeader();
  const extra: Record<string, string> = { "Content-Type": "application/json" };
  if (target) extra["X-Nrvq-Target-Cluster"] = target;
  const response = await fetch(apiUrl(path), {
    method,
    headers: authHeaders(extra),
    body: body ? JSON.stringify(body) : undefined
  });
  if (response.status === 401) {
    handleUnauthorized();
    throw new Error("Unauthorized");
  }
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed: ${response.status}`);
  }
  return (await response.json()) as T;
}

export type ClusterInfo = { cluster_id: string; cluster_name: string; namespaces: string[] };

/** This deployment's live identity + the real namespaces observed in its data (F046). */
export async function fetchClusterInfo(): Promise<ClusterInfo> {
  return apiGet<ClusterInfo>("/api/v1/cluster-info");
}

export type RuntimeSettings = {
  namespace: string;
  enforcement_mode: "block" | "audit";
  trust_threshold: number;
  violation_penalty: number;
  rate_limit: number;
  sector?: string | null;
  apply_mode?: "enforce" | "dry_run_only"; // F-51: when dry_run_only the API rejects policy applies for this ns
};

/** Effective runtime settings (config defaults + persisted overrides) for a namespace (F046). */
export async function fetchSettings(namespace?: string): Promise<RuntimeSettings> {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  const query = params.toString();
  return apiGet<RuntimeSettings>(query ? `/api/v1/settings?${query}` : "/api/v1/settings");
}

/** Persist a per-namespace settings override (admin-only). */
export async function saveSettings(
  namespace: string,
  body: Partial<Pick<RuntimeSettings, "enforcement_mode" | "trust_threshold" | "violation_penalty" | "rate_limit" | "sector" | "apply_mode">>
): Promise<RuntimeSettings> {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  return apiSend<RuntimeSettings>(`/api/v1/settings?${params.toString()}`, "PUT", body);
}

// --- F047 sector policy packs ---
export type PolicyPack = {
  id: string;
  sector: string;
  title: string;
  enforces: string;
  rule_ids: string[];
  composes: string[]; // canonical horizontal rules composed in at enable-time (e.g. pci_card_numbers)
  categories: string[];
  compliance: string[];
  tunables: string[];
  enabled: boolean;
  namespace: string;
};

/** The sector-pack catalog with enabled-per-namespace state. */
export async function fetchPolicyPacks(namespace?: string): Promise<PolicyPack[]> {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  const query = params.toString();
  return apiGet<PolicyPack[]>(query ? `/api/v1/policy-packs?${query}` : "/api/v1/policy-packs");
}

export type PackActionResult = { namespace: string; pack_id: string; enabled: boolean; enabled_packs: string[] };

/** Enable a sector pack for a namespace (admin-only). */
export async function enablePolicyPack(packId: string, namespace: string): Promise<PackActionResult> {
  return apiSend<PackActionResult>(`/api/v1/policy-packs/${encodeURIComponent(packId)}/enable`, "POST", { namespace });
}

/** Disable a sector pack for a namespace (admin-only). */
export async function disablePolicyPack(packId: string, namespace: string): Promise<PackActionResult> {
  return apiSend<PackActionResult>(`/api/v1/policy-packs/${encodeURIComponent(packId)}/disable`, "POST", { namespace });
}

// F-54: view a pack's rego + author a per-namespace tighten-only override (revertable).
export async function fetchPackRego(packId: string): Promise<{ pack_id: string; rego: string }> {
  return apiGet(`/api/v1/policy-packs/${encodeURIComponent(packId)}/rego`);
}
export async function fetchPackOverride(namespace: string): Promise<{ namespace: string; rego_source: string; active: boolean; mode?: string }> {
  return apiGet(`/api/v1/policy-packs/override?namespace=${encodeURIComponent(namespace)}`);
}
// allowWeaken=true is the loud, audited "Advanced: allow weakening this pack" opt-in (stored as a weaken overlay,
// still floored by the comprehensive baseline). Default false = tighten-only (cannot weaken a pack block).
export async function savePackOverride(namespace: string, regoSource: string, allowWeaken = false): Promise<{ namespace: string; active: boolean; mode?: string }> {
  return apiSend(`/api/v1/policy-packs/override`, "PUT", { namespace, rego_source: regoSource, allow_weaken: allowWeaken });
}
export async function revertPackOverride(namespace: string): Promise<{ namespace: string; active: boolean; reverted: boolean }> {
  return apiSend(`/api/v1/policy-packs/override?namespace=${encodeURIComponent(namespace)}`, "DELETE", undefined);
}

// F-58: the effective policy stack governing a (namespace, agent_class) — derived from the real evaluator.
export type EffectiveLayer = { scope: string; label: string; priority: number; overlay: boolean };
export async function fetchEffectivePolicy(namespace: string, agentClass: string): Promise<{ namespace: string; agent_class: string; layers: EffectiveLayer[]; note?: string }> {
  return apiGet(`/api/v1/policies/effective?namespace=${encodeURIComponent(namespace)}&agent_class=${encodeURIComponent(agentClass)}`);
}

export type VersionInfo = { version: string; license: string };

/** The single-source product version + license (F046). */
export async function fetchVersion(): Promise<VersionInfo> {
  return apiGet<VersionInfo>("/api/v1/version");
}

export type ApiKey = {
  id: string;
  prefix: string;
  name: string;
  namespace: string;
  role: string;
  created_at: string | null;
  last_used_at: string | null;
  revoked: boolean;
};

/** List issued API keys (no secrets); admin-only (F046). */
export async function fetchApiKeys(): Promise<ApiKey[]> {
  return apiGet<ApiKey[]>("/api/v1/keys");
}

/** Issue a new API key — the returned `key` secret is shown ONCE. */
export async function createApiKey(body: { name: string; namespace?: string; role?: string }): Promise<ApiKey & { key: string }> {
  return apiSend<ApiKey & { key: string }>("/api/v1/keys", "POST", body);
}

/** Revoke (disable) an API key. */
export async function revokeApiKey(id: string): Promise<ApiKey> {
  return apiSend<ApiKey>(`/api/v1/keys/${encodeURIComponent(id)}`, "DELETE");
}

export type RedteamAttack = { id: string; name: string; category: string; description?: string; expected_decision?: string };
export type RedteamResult = {
  attack_id: string;
  attack_name: string;
  category: string;
  agent_class?: string; // F-44: the identity this scenario was evaluated against
  namespace?: string;
  expected: string;
  actual: string;
  rule_id: string;
  passed: boolean;
  latency_ms?: number;
  error?: string;
};
export type RedteamReport = {
  run_id?: string;
  namespace?: string;
  targets?: string[]; // F-44: the seeded agent classes the suite was run against
  total: number;
  passed: number;
  failed: number;
  pass_rate: number;
  results: RedteamResult[];
};

/** The red-team attack catalog (F017). */
export async function fetchRedteamCatalog(): Promise<RedteamAttack[]> {
  return apiGet<RedteamAttack[]>("/api/v1/redteam/catalog");
}

/** F-44: the real agent classes seeded in a namespace, for the target selector. */
export async function fetchRedteamTargets(namespace?: string): Promise<{ namespace: string; targets: string[] }> {
  const q = namespace && namespace !== "all" ? `?namespace=${encodeURIComponent(namespace)}` : "";
  return apiGet<{ namespace: string; targets: string[] }>(`/api/v1/redteam/targets${q}`);
}

/** Run the full red-team suite against the live evaluator and return the real report. */
export async function runRedteamSuite(targetAgent?: string, targetNamespace?: string): Promise<RedteamReport> {
  const params = new URLSearchParams();
  if (targetAgent) params.set("target_agent", targetAgent);
  if (targetNamespace && targetNamespace !== "all") params.set("target_namespace", targetNamespace);
  const query = params.toString();
  return apiSend<RedteamReport>(`/api/v1/redteam/suite${query ? `?${query}` : ""}`, "POST");
}

export type Me = { sub: string; role: string; namespace: string; email?: string | null; name?: string | null };

/** The server's normalized view of the authenticated caller (group mapping applied). */
export async function fetchMe(): Promise<Me> {
  return apiGet<Me>("/api/v1/me");
}

export type Readiness = { status: string; redis?: boolean; db?: boolean; opa?: boolean };

/** Live readiness probe: real redis/db/opa status (200 ready, 503 not-ready). Returns the JSON either way. */
export async function fetchReadiness(): Promise<Readiness> {
  const response = await fetch(apiUrl("/readyz"), { headers: authHeaders() });
  return (await response.json()) as Readiness; // 503 still carries the per-dependency body
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
  agent?: string; // F-53: SPIFFE/agent-id substring, filtered server-side over the range
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
  observed?: number; // F-39: observed attempts from audit
  blocked?: number; // F-39: blocked/escalated from audit
};
export type MitreCoverage = {
  namespace: string;
  covered: number;
  total: number;
  observed?: number; // F-39
  blocked?: number; // F-39
  range?: string;
  techniques: MitreTechnique[];
};

export async function fetchMitreCoverage(namespace?: string): Promise<MitreCoverage> {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  const query = params.toString();
  return apiGet<MitreCoverage>(query ? `/api/v1/mitre/coverage?${query}` : "/api/v1/mitre/coverage");
}

export type CategoryCoverageItem = {
  category: string;
  covered: number;
  total: number;
  score: number; // F-44/F-45: rules PRESENT (loaded), not efficacy
  observed?: number; // audit attempts touching this category's rules
  blocked?: number; // of those, how many were blocked/escalated
  effective?: boolean; // at least one rule in the category has actually blocked traffic
};
export type CoverageByCategory = {
  namespace: string;
  coverage_pct: number;
  basis?: string; // "rules_present" — score is presence, not a protection guarantee
  categories: CategoryCoverageItem[];
};

/** Policy coverage per risk category (F046): score = mapped rules PRESENT in the loaded rego (not efficacy;
 * F-44/F-45). observed/blocked/effective overlay real audit activity. */
export async function fetchCoverageByCategory(namespace?: string): Promise<CoverageByCategory> {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  const query = params.toString();
  return apiGet<CoverageByCategory>(query ? `/api/v1/coverage-by-category?${query}` : "/api/v1/coverage-by-category");
}

export type ToolUsage = { tool: string; count: number; blocked: number };
export type TrustHistoryPoint = { time: string; allow: number; block: number; trust_score: number | null };

/** Real per-tool call counts for one agent, aggregated from audit_log (F046). */
export async function fetchAgentToolUsage(spiffeId: string, namespace?: string, range = "7d"): Promise<ToolUsage[]> {
  const params = new URLSearchParams({ range });
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  return apiGet<ToolUsage[]>(`/api/v1/agents/${encodeURIComponent(spiffeId)}/tool-usage?${params.toString()}`);
}

/** Real per-day allow/block + average trust for one agent, aggregated from audit_log (F046). */
export async function fetchAgentTrustHistory(
  spiffeId: string,
  namespace?: string,
  range = "7d"
): Promise<TrustHistoryPoint[]> {
  const params = new URLSearchParams({ range });
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  return apiGet<TrustHistoryPoint[]>(`/api/v1/agents/${encodeURIComponent(spiffeId)}/trust-history?${params.toString()}`);
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
): Promise<{ applied?: boolean; policy?: string; target_type?: string; enforcement_mode?: string }> {
  return apiSend(
    `/api/v1/policies/${encodeURIComponent(namespace)}/${encodeURIComponent(agentClass)}/apply`,
    "POST",
    data
  );
}
