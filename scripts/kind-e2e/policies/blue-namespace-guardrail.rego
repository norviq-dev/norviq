package norviq.custom

# GUARDRAIL OVERLAY — round-1 blue response to the composition finding.
#
# The round-1 red team showed that authoring the per-class allowlist (a BASE policy at priority 200)
# silently STRIPPED the namespace baseline's cross-tenant block: `_resolve_precedence` is
# highest-priority-wins, so the per-class `allow get_customer` beat the baseline's priority-1
# `cross_tenant_access` block. The baseline is a DEFAULT, not a FLOOR.
#
# A guardrail overlay is the product's designed answer: it is tighten-only and most-restrictive-wins,
# so no base policy's priority can override it. Protective INVARIANTS that must survive every per-class
# allowlist belong here, not in the base. This one re-asserts the tenant boundary the baseline drew,
# so it holds even for a tool the class is otherwise allowed to call.

default decision = "allow"
default rule_id = "guardrail_pass"

cross_tenant_detected {
    input.tool_params.tenant_id
    input.tool_params.tenant_id != input.agent.namespace
}
cross_tenant_detected {
    input.tool_params.namespace
    input.tool_params.namespace != input.agent.namespace
}
# A wildcard tenant/customer selector is a cross-tenant reach by construction — "*" is not this
# agent's own namespace, and a value-bound the base allowlist cannot express.
cross_tenant_detected {
    input.tool_params.tenant_id == "*"
}

decision = "block" {
    cross_tenant_detected
}
rule_id = "guardrail_cross_tenant" {
    cross_tenant_detected
}
reason = "cross-tenant access denied by a namespace guardrail that a per-class allowlist cannot override" {
    cross_tenant_detected
}

# EGRESS TO A NON-CORP DESTINATION as a floor. The red team proved allowlisting send_email stripped
# the baseline's llm02_data_leakage block and the exfil to collector@attacker.example went through.
#
# This floors on the DESTINATION, not on a secret detector, and that is deliberate: the engine's
# `derived.data_classes` was found to MISS the AWS secret-access-key value that the baseline's own
# inline scan catches (two detectors that disagree — a separate finding), so a guardrail built on
# `data_classes` would be weaker than the baseline it is meant to floor. `derived.destinations` is
# reliable and is the control that actually matters for exfiltration: an egress-verb call may only
# reach an approved recipient domain, whatever it carries. No per-class allow can remove this.
corp_domain = "acme.com"

egress_offsite {
    object.get(input.derived, "verb", "") == "send"
    email := input.derived.destinations.emails[_]
    not endswith(lower(email), sprintf("@%s", [corp_domain]))
}
egress_offsite {
    object.get(input.derived, "verb", "") == "send"
    host := input.derived.destinations.hosts[_]
    not endswith(lower(host), corp_domain)
}
egress_offsite {
    object.get(input.derived, "verb", "") == "send"
    url := input.derived.destinations.urls[_]
    not contains(lower(url), corp_domain)
}

decision = "block" {
    egress_offsite
}
rule_id = "guardrail_egress_offsite" {
    egress_offsite
}
reason = "egress to a destination outside acme.com — blocked by a namespace guardrail a per-class allowlist cannot override" {
    egress_offsite
}
