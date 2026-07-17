// Base URL for the API. Default "" = relative paths (same-origin): the vite proxy in dev and the
// UI's nginx (`location /api/`) in prod both forward to the API — so the browser only ever talks to
// its own origin (always browser-reachable). Set VITE_API_BASE_URL to an absolute origin only for a
// split-origin deploy where the API has its own ingress (requires CORS on the API).
import { oidcEnabled, oidcLogout } from "../auth/oidc";
import { clearSession, getToken } from "../auth/session";
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
/** Revoke the session server-side (AUTH-01), then clear the stored JWT and redirect home.
 *  The revocation call is best-effort with a hard timeout: a dead or hung API must never delay or
 *  trap the client-side logout, and the raw fetch (not apiSend) avoids the 401 handler double-redirect. */
export function logout(): void {
  if (oidcEnabled) {
    void oidcLogout();
    return;
  }
  const finish = (): void => {
    clearSession(); // LOGIN-2: token (either storage) + the forced-change flag go together
    window.location.href = "/";
  };
  const token = getToken();
  if (!token) {
    finish();
    return;
  }
  void fetch(apiUrl("/api/v1/auth/logout"), {
    method: "POST",
    headers: authHeaders(),
    signal: AbortSignal.timeout(2000)
  })
    .catch(() => undefined)
    .finally(finish);
}

export function authHeaders(extra?: Record<string, string>): Record<string, string> {
  const token = getToken();
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
  clearSession(); // LOGIN-2: the dead session's token + forced-change flag go together
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
  body: Partial<Pick<RuntimeSettings, "enforcement_mode" | "trust_threshold" | "rate_limit" | "sector" | "apply_mode">>
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

/** Cluster-wide data-retention limits (read-only; set via Helm values `config.*`). 0/negative = disabled (keep forever). */
export type RetentionSettings = {
  audit_retention_days: number;
  coverage_snapshot_retention_days: number;
  graph_snapshot_keep_per_namespace: number;
  agent_registry_retention_days: number;
  api_key_default_ttl_days: number;
  draft_ttl_days: number;
  draft_ttl_test_hours: number;
  draft_cap_per_namespace: number;
  policy_version_keep_count: number;
  policy_version_keep_days: number;
  redteam_detail_keep_runs: number;
  redteam_detail_keep_days: number;
  redteam_summary_keep_runs: number;
  redteam_summary_keep_days: number;
};

/** Fetch the cluster-wide retention limits for the read-only Settings card. */
export async function fetchRetentionSettings(): Promise<RetentionSettings> {
  return apiGet<RetentionSettings>("/api/v1/settings/retention");
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
  // Server-computed expiry (may be absent while the backend rollout is in flight; null = never expires).
  expires_at?: string | null;
};

/** List issued API keys (no secrets); admin-only (F046). */
export async function fetchApiKeys(): Promise<ApiKey[]> {
  return apiGet<ApiKey[]>("/api/v1/keys");
}

/** Issue a new API key — the returned `key` secret is shown ONCE.
 *  `expires_in_days` is optional: omit to use the server default TTL; 0 = never expires. */
export async function createApiKey(body: { name: string; namespace?: string; role?: string; expires_in_days?: number }): Promise<ApiKey & { key: string }> {
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
  // false = a sector-pack attack whose pack isn't enabled for this namespace — out of scope, NOT a real
  // miss; excluded from proven-blocking and rendered as "pack not enabled" rather than a red "got through".
  applicable?: boolean;
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

// B3/F1/F2 — efficacy roll-up + durable run history.
export type RedteamEfficacyBucket = { total: number; caught: number; got_through: number; proven_blocking_pct: number };
export type RedteamTechRow = RedteamEfficacyBucket & { technique_id: string; technique_name: string };
export type RedteamOwaspRow = RedteamEfficacyBucket & { control_id: string; control_name: string };
export type RedteamEfficacy = {
  overall: RedteamEfficacyBucket;
  by_technique: RedteamTechRow[];
  by_owasp: RedteamOwaspRow[];
  non_enforcement: number;
  excluded_synthetic: number;
};
export type RedteamRunResult = RedteamResult & {
  atlas_technique?: string;
  atlas_technique_name?: string;
  owasp_control?: string | null;
  owasp_control_name?: string | null;
};
export type RedteamLatest = {
  has_run: boolean;
  run_id?: string;
  created_at?: string;
  namespace?: string;
  targets?: string[];
  total?: number;
  passed?: number;
  failed?: number;
  pass_rate?: number;
  results?: RedteamRunResult[];
  efficacy?: RedteamEfficacy;
};
export type RedteamRunSummary = {
  run_id: string;
  created_at: string;
  namespace: string;
  targets: string[];
  total: number;
  passed: number;
  failed: number;
  pass_rate: number;
  proven_blocking_pct: number;
  caught: number;
  got_through: number;
};

/** B2/B3/F2: the most recent DURABLE run (results + efficacy), or {has_run:false} before the first run.
 *  STALE-4: pass a concrete namespace to scope the efficacy to the selected scope (omit/"all" = cluster-wide). */
export async function fetchRedteamLatest(namespace?: string): Promise<RedteamLatest> {
  const q = namespace && namespace !== "all" ? `?namespace=${encodeURIComponent(namespace)}` : "";
  return apiGet<RedteamLatest>(`/api/v1/redteam/results/latest${q}`);
}

/** B2/F1: recent run history (summaries only). STALE-4: optional namespace scope. */
export async function fetchRedteamHistory(limit = 15, namespace?: string): Promise<{ runs: RedteamRunSummary[]; total: number }> {
  const nsq = namespace && namespace !== "all" ? `&namespace=${encodeURIComponent(namespace)}` : "";
  return apiGet<{ runs: RedteamRunSummary[]; total: number }>(`/api/v1/redteam/results?limit=${limit}${nsq}`);
}

export type Me = { sub: string; role: string; namespace: string; email?: string | null; name?: string | null };

/** The server's normalized view of the authenticated caller (group mapping applied). */
export async function fetchMe(): Promise<Me> {
  return apiGet<Me>("/api/v1/me");
}

/** Self-service password change (the same endpoint the forced first-login flow uses). The server
 *  re-checks the current password and enforces the min-length / not-reused rules. */
export async function changePassword(current_password: string, new_password: string): Promise<{ ok?: boolean }> {
  return apiSend<{ ok?: boolean }>("/api/v1/auth/change-password", "POST", { current_password, new_password });
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
): Promise<{ total?: number; blocked?: number; allowed?: number; block_rate_pct?: number; engine_errors?: number; avg_latency_ms?: number }> {
  const params = new URLSearchParams({ range });
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  return apiGet<{ total?: number; blocked?: number; allowed?: number; block_rate_pct?: number; engine_errors?: number; avg_latency_ms?: number }>(
    `/api/v1/audit/stats?${params.toString()}`
  );
}

export async function fetchAuditRecords(filters: {
  range?: string;
  namespace?: string;
  decision?: string;
  tool_name?: string;
  agent?: string; // F-53: SPIFFE/agent-id substring, filtered server-side over the range
  rule_id?: string; // Compliance evidence-row deep-link: filter by enforcing rule
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
  description?: string;
  scope: "enforceable" | "out_of_scope";
  status: "enforced" | "gap" | "out_of_scope";
  // A gap is `generatable` only if it maps to a runtime-expressible rule; a bespoke control (no such rule)
  // escalates on generate, so the UI must not offer a "Generate" checkbox for it.
  generatable?: boolean;
  priority?: "high" | "medium" | "low" | null;
  also?: string | null;
  policies: string[];
  covered_policies: string[];
  covered: boolean;
  observed?: number;
  blocked?: number;
  affected_classes?: Array<{ class: string; blocked: number }>;
};
export type MitreCoverage = {
  namespace: string;
  range?: string;
  framework?: string;
  enforceable_total: number;
  enforced: number;
  gap: number;
  oos: number;
  coverage_pct: number;
  // back-compat headline
  covered: number;
  total: number;
  observed?: number;
  blocked?: number;
  agent_classes?: number;
  // COMP-EVIDENCE: count of synthetic/simulated + red-team events excluded from observed/blocked so the
  // evidence pack counts real traffic only (product decision) and can state the exclusion.
  synthetic_excluded?: number;
  last_exported?: string | null;
  techniques: MitreTechnique[];
};
export type MitreTrendPoint = { timestamp: string; enforced: number; coverage_pct: number; blocked: number };
export type MitreTrend = { namespace: string; range: string; framework: string; points: MitreTrendPoint[] };

// Compliance frameworks — both live, same real coverage machinery (atlas | owasp).
export type ComplianceFramework = "atlas" | "owasp";

// F3: the framework-neutral compliance surface — /api/v1/compliance/{framework}/* (the legacy /mitre/* routes
// remain as ATLAS-default back-compat aliases, unused by the client now).
export async function fetchMitreCoverage(namespace?: string, range = "24h", framework: ComplianceFramework = "atlas"): Promise<MitreCoverage> {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  params.set("range", range);
  return apiGet<MitreCoverage>(`/api/v1/compliance/${framework}/coverage?${params.toString()}`);
}

export async function fetchMitreTrend(namespace?: string, range = "30d", framework: ComplianceFramework = "atlas"): Promise<MitreTrend> {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  params.set("range", range);
  return apiGet<MitreTrend>(`/api/v1/compliance/${framework}/trend?${params.toString()}`);
}

// Evidence-pack export: returns the in-cluster download URL (json|pdf). The caller triggers the download via
// an authenticated fetch so no secret leaks into a plain href.
export function mitreExportPath(namespace: string | undefined, range: string, format: "json" | "pdf", framework: ComplianceFramework = "atlas"): string {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  params.set("range", range);
  params.set("format", format);
  return `/api/v1/compliance/${framework}/export?${params.toString()}`;
}

// COMP-GEN-01: the draft response carries status + control provenance + the CONTROL's mapped rule_ids.
// status="no_affected_classes" (draft_id null) when there is no real class to scope to; status="escalate"
// for a control with no runtime-expressible rule; status="error" only on a batch item.
export type GenerateResult = {
  status: "draft" | "no_affected_classes" | "escalate" | "error";
  draft_id: string | null;
  ns?: string;
  cls?: string | null;
  technique_id: string;
  control_name?: string;
  framework?: string;
  refinement?: string;
  mapped_rules?: string[];
  deeplink?: string;
  message?: string;
};

export async function generateMitrePolicy(technique_id: string, namespace: string, agent_class: string | undefined, framework: ComplianceFramework = "atlas"): Promise<GenerateResult> {
  // agent_class is optional — the backend derives the real affected/active class when omitted.
  const payload: Record<string, unknown> = { technique_id, namespace, framework };
  if (agent_class) payload.agent_class = agent_class;
  return apiSend(`/api/v1/compliance/${framework}/generate`, "POST", payload);
}

// COMP-GEN-01 multi-select: generate one CONTROL-SPECIFIC draft per (technique × class). class_mode:
// "affected" = the control's top affected class · "all" = every real affected class · any other value = that
// specific class. Returns a per-item result list + a rollup.
export type GenerateBatchResult = {
  framework: string;
  namespace: string;
  class_mode: string;
  requested: number;
  drafts_created: number;
  results: GenerateResult[];
};

export async function generateMitrePolicyBatch(
  technique_ids: string[], namespace: string, class_mode: string, framework: ComplianceFramework = "atlas"
): Promise<GenerateBatchResult> {
  return apiSend(`/api/v1/compliance/${framework}/generate-batch`, "POST",
    { technique_ids, namespace, class_mode, framework });
}

// CAP→POLICY: turn a source-capability finding into a DRY-RUN policy draft that blocks the target verbs on
// the source for one agent class. Empty `verbs` ⇒ block ALL the source's mutating verbs (make read-only).
// Lands in the same intent-drafts inbox as compliance/attack-graph drafts; never auto-enforces.
export type CapabilityDefendResult = {
  draft_id: string;
  deeplink: string;
  ns: string;
  cls: string;
  source_type: string;
  verbs: string[];
  blocked_tools: string[];
  // CAP-FIX: verbs the policy blocks by NAME PATTERN — a forward guard that catches destructive tools
  // appearing later, so the defense is real even when blocked_tools is empty.
  forward_guard_verbs?: string[];
  read_only: boolean;
  valid: boolean;
  errors: string[];
};

export async function defendCapability(
  ns: string, cls: string, source_type: string, verbs: string[] = []
): Promise<CapabilityDefendResult> {
  return apiSend("/api/v1/capability/defend", "POST", { ns, cls, source_type, verbs });
}

export type CategoryCoverageItem = {
  category: string;
  covered: number;
  total: number;
  score: number; // F-44/F-45: rules PRESENT (loaded), not efficacy
  observed?: number; // audit attempts touching this category's rules
  blocked?: number; // of those, how many were blocked/escalated
  effective?: boolean; // at least one rule in the category has actually blocked traffic
  in_scope?: boolean; // this category has ≥1 rule loaded (baseline/enabled pack) — NOT an un-enabled sector
};
/** An APPLIED per-agent-class policy (positive-security intent / capability / custom) + what it enforces
 *  and its real efficacy — the dimension the risk-category chart can't represent (keyed on the class). */
export type AgentClassPolicy = {
  cls: string;
  kind: "intent" | "capability" | "custom";
  allow_tools: string[]; // the intended allowlist (empty for a pure-refinement or custom policy)
  refinements: string[]; // enabled toggles: readonly | egress | scope | rate
  learned_verbs: string[]; // admin-promoted verbs baked in, "tool=verb"
  priority: number;
  enforcement_mode: string; // block | audit
  enforcing: boolean; // block-mode AND the namespace isn't in Monitor — else loaded-not-enforcing
  observed: number; // 30d governed calls for the class
  blocked: number; // of those, enforced blocks
  would_block: number; // Monitor-mode would-blocks (logged, not enforced)
  effective: boolean; // has actually blocked / would-block traffic (proven, not just loaded)
};
export type CoverageByCategory = {
  namespace: string;
  coverage_pct: number; // over IN-SCOPE categories only — not diluted by un-enabled sector packs
  basis?: string; // "rules_present" — score is presence, not a protection guarantee
  available?: number; // sector categories NOT enabled for this namespace ("available to add")
  categories: CategoryCoverageItem[];
  namespace_mode?: string; // "block" | "audit" (Monitor) — how the namespace actually enforces
  agent_class_policies?: AgentClassPolicy[];
};

/** Policy coverage per risk category (F046): score = mapped rules PRESENT in the loaded rego (not efficacy;
 * F-44/F-45). observed/blocked/effective overlay real audit activity. */
export async function fetchCoverageByCategory(namespace?: string): Promise<CoverageByCategory> {
  const params = new URLSearchParams();
  if (namespace && namespace !== "all") params.set("namespace", namespace);
  const query = params.toString();
  return apiGet<CoverageByCategory>(query ? `/api/v1/coverage-by-category?${query}` : "/api/v1/coverage-by-category");
}

export type ToolUsage = { tool: string; count: number; blocked: number; risk?: "low" | "medium" | "high" | "critical" };
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

export type SearchResults = { tools: SearchAuditRecord[]; agents: SearchAgent[]; policies: SearchPolicy[] };

/** P2-2: the ⌘K search — ONE server-scoped, bounded call. Replaces the old three-endpoint fan-out that
 *  pulled the entire agent + policy lists on every keystroke and matched client-side. The server pins a
 *  scoped tenant to its own namespace, so no namespace is passed from the UI. */
export async function fetchSearch(q: string, signal?: AbortSignal): Promise<SearchResults> {
  return apiGetWithSignal<SearchResults>(`/api/v1/search?q=${encodeURIComponent(q)}`, signal);
}

export type DryRunReplay = {
  total_records_checked?: number;
  would_block?: number;
  would_allow?: number;
  would_escalate?: number;
  newly_blocked?: number; // decision flips: currently-allowed calls this candidate would newly block
  newly_allowed?: number;
  newly_blocked_samples?: Array<{ tool_name?: string; was?: string; now?: string; rule_id?: string }>;
  block_rate_pct?: number;
  truncated?: boolean;
  scope?: { namespace?: string; agent_class?: string | null };
  recommendation?: string;
};

export async function dryRunPolicy(data: {
  namespace: string;
  agent_class: string;
  rego_source: string;
}): Promise<DryRunReplay> {
  return apiSend<DryRunReplay>("/api/v1/policies/dry-run", "POST", data);
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

// FIX B: a write returning 200 is not proof the policy is loaded on the read path — ApplyResultPanel polls
// this after a local create/apply/rollback to confirm current_version (and optionally enforcement_mode) has
// actually converged, the same way the fleet "kind" already polls rollout. Reuses the plain list endpoint
// (DB-authoritative — no session affinity across replicas) rather than adding a new server route.
export async function verifyPolicyApplied(
  namespace: string,
  agentClass: string,
  expectedVersion: number
): Promise<{ matched: boolean; current_version?: number; enforcement_mode?: string }> {
  const rows = await apiGet<Array<{ namespace?: string; agent_class?: string; current_version?: number; enforcement_mode?: string }>>(
    `/api/v1/policies?namespace=${encodeURIComponent(namespace)}`
  );
  const row = rows.find((r) => r.namespace === namespace && r.agent_class === agentClass);
  return {
    matched: !!row && row.current_version === expectedVersion,
    current_version: row?.current_version,
    enforcement_mode: row?.enforcement_mode
  };
}

// B-2: delete a policy from every layer (in-mem + Redis + Postgres + version history; durable across restart).
// Deleting a class flips it back to the namespace baseline / default. apiSend applies the remote-cluster guard.
// The server (B-3) refuses reserved/managed scopes with 422 even if a caller reaches this.
export async function deletePolicy(
  namespace: string,
  agentClass: string,
  // COMP-GEN-01/POLICY-RESERVED-01: an operator-authored reserved scope (`__guardrail__`, `__baseline__`, or a
  // per-class compliance remediation overlay "<class>__remediation__") requires this explicit admin-gated flag
  // to revert — a raw delete (no flag) is refused with a 422 even for these. Never set for an ordinary class.
  confirmManaged = false
): Promise<{ deleted?: boolean; namespace?: string; agent_class?: string; version?: number | null }> {
  const qs = confirmManaged ? "?confirm_managed=true" : "";
  return apiSend(
    `/api/v1/policies/${encodeURIComponent(namespace)}/${encodeURIComponent(agentClass)}${qs}`,
    "DELETE"
  );
}

// --- Attack Graph (feat/attack-graph) ---------------------------------------------------------------
import type {
  ThreatPathsResponse,
  IntentCoverage,
  IntentToggles,
  IntentDraft,
  IntentSuggest
} from "../components/attack-graph/types";

/** Enriched kill-chains for the Attack Graph. ns="all" unions the caller's namespaces (server-scoped). */
export async function fetchThreatPaths(
  ns: string,
  range: string,
  cls?: string,
  includeSynthetic = false
): Promise<ThreatPathsResponse> {
  const params = new URLSearchParams();
  params.set("ns", ns || "all");
  params.set("range", range || "24h");
  if (cls && cls !== "all") params.set("cls", cls);
  if (includeSynthetic) params.set("include_synthetic", "true"); // A1: default-hide probe-rooted kill-chains
  return apiGet<ThreatPathsResponse>(`/api/v1/threats/attack-paths?${params.toString()}`);
}

/** The class's OBSERVED tool surface (24h allow/block + attack-path tags) — the allowlist-builder source. */
export async function fetchIntentSuggest(ns: string, cls: string): Promise<IntentSuggest> {
  const params = new URLSearchParams();
  params.set("ns", ns || "all");
  params.set("cls", cls);
  return apiGet<IntentSuggest>(`/api/v1/threats/intent-suggest?${params.toString()}`);
}

/** PROMOTE an observed tool to a defined verb (admin) — the tool-classification lifecycle's final step:
 *  observe (Monitor logs its calls) → infer (params evidence) → promote (persisted verb override).
 *  The verb is the ADMIN'S call: it defaults to the inferred one but any of read/write/send/delete
 *  is accepted (risk always follows the canonical verb→risk map server-side). */
export async function promoteToolVerb(body: { ns: string; tool_name: string; verb: string }): Promise<{ promoted: boolean; verb: string; risk: string }> {
  return apiSend("/api/v1/threats/tool-verbs/promote", "POST", body);
}

/** DEMOTE a promoted tool back to the observation phase (admin) — deletes the override; the tool shows
 *  as observing again and keeps accruing evidence. */
export async function demoteToolVerb(ns: string, tool_name: string): Promise<{ demoted: boolean }> {
  return apiSend(`/api/v1/threats/tool-verbs?ns=${encodeURIComponent(ns)}&tool_name=${encodeURIComponent(tool_name)}`, "DELETE");
}

/** The classification-lifecycle state for a scope: promoted overrides + observation-phase candidates. */
export type ToolVerbOverride = {
  namespace: string; tool_name: string; verb: string; risk: string;
  promoted_by: string; evidence: { calls?: number; verbs?: Record<string, number> } | null; created_at: string;
};
export type ToolVerbCandidate = {
  tool_name: string; calls: number; verbs: Record<string, number>;
  inferred_verb: string | null; inferred_count: number; suggested_risk: string | null;
};
export async function fetchToolVerbs(ns: string): Promise<{ namespaces: string[]; overrides: ToolVerbOverride[]; candidates: ToolVerbCandidate[] }> {
  return apiGet(`/api/v1/threats/tool-verbs?ns=${encodeURIComponent(ns || "all")}`);
}

/** Generate a default-deny intent policy and dry-run it against the current paths (no enforcement). */
export async function fetchIntentCoverage(body: {
  ns: string;
  cls: string;
  allow_tools: string[];
  intent: IntentToggles;
}): Promise<IntentCoverage> {
  return apiSend<IntentCoverage>("/api/v1/threats/intent-coverage", "POST", body);
}

/** Create a DRY-RUN DRAFT of the generated policy + deep-link to Policies. Never enforces on its own. */
export async function createIntentDraft(body: {
  ns: string;
  cls: string;
  allow_tools: string[];
  intent: IntentToggles;
  path_ids?: string[];
}): Promise<IntentDraft> {
  return apiSend<IntentDraft>("/api/v1/threats/intent-draft", "POST", body);
}

/** List pending (non-enforcing) intent drafts — the Policies page surfaces these for review/apply. */
// F2: source_* fields are present for compliance-generated drafts (null for Attack-Graph drafts).
type DraftSourceFields = { source_framework?: string | null; source_control_id?: string | null; source_control_name?: string | null };
// COMP-GEN-01: for a compliance-remediation draft, `cls` is the compound persistence overlay key
// ("<class>__remediation__") — `affected_class` carries the real class for display. Null/absent for
// non-remediation drafts, where `cls` already is the real class.
export type IntentDraftItem = { draft_id: string; ns: string; cls: string; affected_class?: string | null; enabled: string[]; covered_count: number; total: number; created_at: string; expires_at?: string } & DraftSourceFields;
// Part B (B6): the drafts endpoint is BOUNDED + paginated — a page of drafts + the total count.
export type IntentDraftPage = { drafts: IntentDraftItem[]; total: number; returned: number; offset: number; limit: number };

export async function fetchIntentDrafts(ns?: string, offset = 0, limit?: number): Promise<IntentDraftPage> {
  const p = new URLSearchParams();
  if (ns && ns !== "all") p.set("ns", ns);
  if (offset) p.set("offset", String(offset));
  if (limit) p.set("limit", String(limit));
  const qs = p.toString();
  return apiGet(`/api/v1/threats/intent-drafts${qs ? `?${qs}` : ""}`);
}

/** Part B (B7): manually dismiss ONE non-enforcing draft. */
export async function dismissIntentDraft(draftId: string): Promise<{ dismissed: boolean; draft_id: string }> {
  return apiSend(`/api/v1/threats/intent-drafts/${encodeURIComponent(draftId)}`, "DELETE");
}

/** Part B (B7): bulk "Clear expired" — delete all expired non-enforcing drafts (optionally scoped to a ns). */
export async function gcIntentDrafts(ns?: string): Promise<{ cleared: number; namespace: string | null }> {
  const q = ns && ns !== "all" ? `?ns=${encodeURIComponent(ns)}` : "";
  return apiSend(`/api/v1/threats/intent-drafts/gc${q}`, "POST");
}

/** Fetch one intent draft in full (incl. generated rego) for the Policies review/apply flow. */
export async function fetchIntentDraft(draftId: string): Promise<{ draft_id: string; ns: string; cls: string; affected_class?: string | null; rego: string; enabled: string[]; covered_count: number; total: number; enforcement: string } & DraftSourceFields> {
  return apiGet(`/api/v1/threats/intent-drafts/${encodeURIComponent(draftId)}`);
}
