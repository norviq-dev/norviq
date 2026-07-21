# GENERATED FIXTURE — reproduce: python -c "from norviq.api.threat_intent import *; print(generate_intent_rego('customer-support', ['search_kb','get_order'], Intent(readonly=True)))"
package norviq.intent.customer_support

# Positive-security INTENT policy for agent class "customer-support" — GENERATED, DRY-RUN DRAFT.
# DEFAULT-DENY: a call is BLOCKED unless it is this class AND the tool is in the intended allowlist AND
# every enabled refinement toggle holds. The allowlist is matched evasion-normalized (lower + skeleton).
# TIGHTEN-ONLY at baseline priority (most-restrictive tie-break) — only ADDS denials, never weakens a block.
# Allowlist (2 tools): get_order, search_kb
# Refinements: readonly

default decision = "block"
default rule_id = "intent_default_deny"
default reason = "Blocked: tool is not in the intended allowlist for customer-support"

allow_names := {"get_order", "search_kb"}
allow_skeletons := {"get_order", "search_kb"}
read_verbs := {"read", "get", "list", "search", "fetch", "describe", "query", "lookup", "view", "find", "scan", "count"}
egress_tools := {"send_email", "send_sms", "send_message", "http_post", "http_request", "webhook", "post_webhook", "upload", "upload_file", "export", "export_data", "s3_put", "put_object", "publish", "smtp", "notify_external", "call_api", "fetch_url"}

# Allowlist membership — matched on BOTH the lower-cased name and the confusable skeleton (== the
# evaluator's input.tool_name_normalized), so homoglyph/zero-width/case evasion can't dodge the allow.
in_allowlist { allow_names[lower(input.tool_name)] }
in_allowlist { allow_skeletons[input.tool_name_normalized] }

tool_verb := split(lower(input.tool_name), "_")[0]
tool_verb_norm := split(lower(input.tool_name_normalized), "_")[0]
is_read { read_verbs[tool_verb] }
is_read { read_verbs[tool_verb_norm] }
is_egress { egress_tools[lower(input.tool_name)] }
is_egress { egress_tools[lower(input.tool_name_normalized)] }

# in_scope: any namespace-bearing tool_params field must equal the agent's own namespace (no cross-tenant).
in_scope { not _cross_namespace }
_cross_namespace {
    some k
    ns := input.tool_params[k]
    is_string(ns)
    _looks_like_namespace_key(k)
    ns != input.agent.namespace
}
_looks_like_namespace_key(k) { lower(k) == "namespace" }
_looks_like_namespace_key(k) { lower(k) == "ns" }
_looks_like_namespace_key(k) { lower(k) == "tenant" }

# rate_within: advisory only — a stateless policy cannot count calls/min; the real limiter is the stateful rate-limiter layer.
rate_within { input.call_depth <= 8 }


allow_intent {
    input.agent.agent_class == "customer-support"
    in_allowlist
    is_read           # read-only refinement: tool name is a read verb
}

# a class call that is NOT in the intended allowlist is denied
denied { input.agent.agent_class == "customer-support"; not allow_intent }

decision = "allow" { allow_intent }
rule_id = "intent_allow_customer_support" { allow_intent }
reason = "Allowed: tool in the intended allowlist for customer-support" { allow_intent }

# Explicit reachable block rule — semantically identical to the default-deny, but present as a rule so the
# policy validator accepts the draft on apply (it requires `decision = "block" { ... }`).
decision = "block" { denied }
rule_id = "intent_default_deny" { denied }
reason = "Blocked: tool is not in the intended allowlist for customer-support" { denied }
