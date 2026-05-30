// ============================================================================
// NORVIQ UI KIT — data.js
// Mock data shaped like the product's /api/v1/* responses. Plain globals.
// ============================================================================

const TOOLS = ["read_file", "exec_shell", "send_email", "db_query", "http_request",
  "write_file", "list_secrets", "spawn_pod", "delete_record", "fetch_url"];
const NAMESPACES = ["prod", "payments", "support", "analytics", "platform", "ml-serving"];
const RULES = ["owasp-llm01", "data-exfil-02", "tool-safety-07", "rate-limit-11",
  "trust-floor-03", "secrets-guard-09", "shell-deny-01"];
const DECISIONS = ["allow", "allow", "allow", "allow", "block", "block", "escalate", "audit"];
const AGENT_CLASSES = ["checkout", "summarizer", "code-assistant", "data-loader",
  "support-bot", "scheduler", "report-gen"];

function pick(arr, i) { return arr[i % arr.length]; }
function seeded(seed) { let s = seed; return () => { s = (s * 9301 + 49297) % 233280; return s / 233280; }; }

const rng = seeded(42);

function makeRecords(n) {
  const now = Date.now();
  return Array.from({ length: n }, (_, i) => {
    const decision = pick(DECISIONS, Math.floor(rng() * 8));
    const ts = new Date(now - i * 47000 - Math.floor(rng() * 40000));
    const trust = decision === "block" ? rng() * 0.4 : decision === "escalate" ? 0.3 + rng() * 0.4 : 0.55 + rng() * 0.45;
    return {
      id: "evt_" + (100000 + i).toString(36),
      timestamp: ts,
      tool_name: pick(TOOLS, Math.floor(rng() * 10)),
      decision,
      rule_id: decision === "allow" ? "—" : pick(RULES, Math.floor(rng() * 7)),
      agent_class: pick(AGENT_CLASSES, Math.floor(rng() * 7)),
      agent_id: "spiffe://" + pick(NAMESPACES, Math.floor(rng() * 6)) + "/agent/" + pick(AGENT_CLASSES, Math.floor(rng() * 7)) + "-" + Math.floor(rng() * 9000 + 1000).toString(16),
      namespace: pick(NAMESPACES, Math.floor(rng() * 6)),
      session_id: "sess_" + Math.floor(rng() * 90000 + 10000).toString(36),
      trust_score: Number(trust.toFixed(2)),
      latency_ms: Math.floor(2 + rng() * 38),
      reason: decision === "allow" ? "Policy matched: default-allow" :
              decision === "block" ? "Blocked: sensitive keyword in payload" :
              decision === "escalate" ? "Escalated to human review queue" : "Audit-only: logged for review"
    };
  });
}

const AUDIT_RECORDS = makeRecords(120);

function fmtTime(d) {
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

const AUDIT_STATS = (() => {
  const total = AUDIT_RECORDS.length;
  const blocked = AUDIT_RECORDS.filter(r => r.decision === "block").length;
  const allowed = AUDIT_RECORDS.filter(r => r.decision === "allow").length;
  return { total: 12480, blocked: 318, allowed: 11842, block_rate_pct: 2.5,
           window_total: total, window_blocked: blocked, window_allowed: allowed };
})();

function trustCategory(score) {
  return score >= 0.7 ? "high" : score >= 0.4 ? "medium" : score > 0 ? "low" : "frozen";
}

const AGENTS = AGENT_CLASSES.flatMap((cls, ci) =>
  NAMESPACES.slice(0, 3).map((ns, ni) => {
    const score = Number((rng()).toFixed(2));
    return {
      spiffe_id: `spiffe://${ns}/agent/${cls}-${(ci * 3 + ni + 17).toString(16)}f`,
      agent_class: cls,
      namespace: ns,
      score,
      category: score === 0 ? "frozen" : trustCategory(score),
      violation_count: Math.floor(rng() * 14),
      last_seen: fmtTime(new Date(Date.now() - rng() * 3600000))
    };
  })
).slice(0, 14);

// Deployments discovered via the norviq=enabled label + agent-class label.
const DEPLOYMENTS = [
  { name: "smartsales-agent",   namespace: "chatbot-prod", agent_class: "customer-support", replicas: 4 },
  { name: "navigator-chatbot",  namespace: "chatbot-prod", agent_class: "customer-support", replicas: 2 },
  { name: "ledger-summarizer",  namespace: "payments",     agent_class: "summarizer",       replicas: 3 },
  { name: "copilot-reviewer",   namespace: "platform",     agent_class: "code-assistant",   replicas: 6 },
  { name: "etl-loader",         namespace: "analytics",    agent_class: "data-loader",      replicas: 2 },
  { name: "shift-scheduler",    namespace: "platform",     agent_class: "scheduler",        replicas: 1 },
  { name: "weekly-report-gen",  namespace: "analytics",    agent_class: "report-gen",       replicas: 1 },
  { name: "triage-bot",         namespace: "support",      agent_class: "support-bot",      replicas: 3 }
];

// Label-based policies. target_type: workload | class | namespace (most specific wins).
const PRIORITY = { workload: { rank: 1, label: "highest", color: "#00e5a0" },
                   class:    { rank: 2, label: "medium",  color: "#3b7bf7" },
                   namespace:{ rank: 3, label: "lowest",  color: "#8494b2" } };

const POLICIES = [
  { id: "pol_ws01", target_type: "workload",  target: "smartsales-agent", namespace: "chatbot-prod", agent_class: "customer-support", current_version: 5, rego_length: 1840, mode: "block",    matches: 1 },
  { id: "pol_ac01", target_type: "class",     target: "customer-support", agent_class: "customer-support", current_version: 7, rego_length: 1320, mode: "block",    matches: 2 },
  { id: "pol_ac02", target_type: "class",     target: "code-assistant",   agent_class: "code-assistant",   current_version: 4, rego_length: 2210, mode: "escalate", matches: 1 },
  { id: "pol_ac03", target_type: "class",     target: "summarizer",       agent_class: "summarizer",       current_version: 3, rego_length: 980,  mode: "audit",    matches: 1 },
  { id: "pol_ac04", target_type: "class",     target: "data-loader",      agent_class: "data-loader",      current_version: 6, rego_length: 1560, mode: "block",    matches: 1 },
  { id: "pol_ac05", target_type: "class",     target: "support-bot",      agent_class: "support-bot",      current_version: 2, rego_length: 720,  mode: "escalate", matches: 1 },
  { id: "pol_ns01", target_type: "namespace", target: "chatbot-prod",     namespace: "chatbot-prod",       current_version: 8, rego_length: 410,  mode: "audit",    matches: 2 },
  { id: "pol_ns02", target_type: "namespace", target: "analytics",        namespace: "analytics",          current_version: 4, rego_length: 360,  mode: "block",    matches: 2 }
];

const POLICY_VERSIONS = Array.from({ length: 6 }, (_, i) => ({
  version: 7 - i,
  saved_by: i === 0 ? "a.nakamura@norviq.io" : i === 1 ? "system" : pick(["r.singh@norviq.io", "m.okoro@norviq.io", "system"], i),
  saved_at: new Date(Date.now() - i * 86400000 * 2 - rng() * 86400000)
}));

const REGO_SAMPLE = [
  { t: "com", s: "# package: tool calls for the checkout agent class" },
  { t: "plain", s: "package norviq.checkout" },
  { t: "blank", s: "" },
  { t: "key", s: "import", x: " future.keywords.in" },
  { t: "blank", s: "" },
  { t: "com", s: "# default verdict is deny — fail closed" },
  { t: "mix", parts: [["key","default "],["plain","decision := "],["str","\"block\""]] },
  { t: "blank", s: "" },
  { t: "mix", parts: [["plain","decision := "],["str","\"allow\""],["plain"," {"]] },
  { t: "indent", parts: [["plain","input.tool "],["key","in"],["plain"," {"],["str","\"read_file\""],["plain",", "],["str","\"db_query\""],["plain","}"]] },
  { t: "indent", parts: [["plain","input.trust_score >= "],["num","0.7"]] },
  { t: "indent", parts: [["plain","not contains_secret(input.payload)"]] },
  { t: "plain", s: "}" },
  { t: "blank", s: "" },
  { t: "mix", parts: [["plain","decision := "],["str","\"escalate\""],["plain"," {"]] },
  { t: "indent", parts: [["plain","input.trust_score < "],["num","0.7"]] },
  { t: "indent", parts: [["plain","input.trust_score >= "],["num","0.4"]] },
  { t: "plain", s: "}" },
  { t: "blank", s: "" },
  { t: "mix", parts: [["fn","contains_secret"],["plain","(p) {"]] },
  { t: "indent", parts: [["plain","some k "],["key","in"],["plain"," ["],["str","\"secret\""],["plain",", "],["str","\"token\""],["plain",", "],["str","\"password\""],["plain","]"]] },
  { t: "indent", parts: [["plain","contains(lower(p.body), k)"]] },
  { t: "plain", s: "}" }
];

Object.assign(window, {
  AUDIT_RECORDS, AUDIT_STATS, AGENTS, POLICIES, POLICY_VERSIONS, REGO_SAMPLE,
  DEPLOYMENTS, PRIORITY, AGENT_CLASSES,
  TOOLS, NAMESPACES, fmtTime, trustCategory
});
