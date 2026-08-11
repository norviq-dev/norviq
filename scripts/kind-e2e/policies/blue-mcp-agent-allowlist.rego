package norviq.custom

# BLUE RESPONSE to the round-0 red team. The strict baseline stopped destruction, data-leakage,
# cross-tenant and SQL, but allows plain egress and money-movement to an arbitrary destination —
# because a NAMESPACE baseline cannot know which recipients a given agent is allowed to reach. That
# is this per-class policy's job.
#
# This agent is a support/analytics assistant. It reads; it does not move money and it does not email
# arbitrary recipients. Deny-by-default allowlist: the three round-0 breaches (send_email to
# collector@attacker.example, the homoglyph sеnd_email, wire_transfer) are all tools NOT on this list,
# so they are blocked for not being listed — no classifier or lexicon in the loop, so a renamed or
# homoglyph variant fails the list exactly as the plain name would.

default decision = "block"
default rule_id = "mcp_agent_allowlist"
default reason = "tool is not on this agent's approved list"

allowed_tools = {
    "search_docs",
    "read_file",
    "lookup_customer",
    "format_currency",
    "search_kb",
    "get_order",
    "get_customer",
}

decision = "allow" {
    allowed_tools[input.tool_name]
}

# Explicit block for any unlisted tool. The `default decision = "block"` above already denies these;
# stating it as a rule too is what makes the deny-by-default posture legible to the validator and to
# an operator reading the policy — the block is intended, not an accident of a missing allow.
decision = "block" {
    not allowed_tools[input.tool_name]
}

# What the denied call was trying to do — `send` on a denied call is an attempted egress the allowlist
# just stopped, `unknown` is probing with a novel/obscured name. Both are worth alerting on.
rule_id = "mcp_agent_allowlist_egress_blocked" {
    not allowed_tools[input.tool_name]
    input.derived.verb == "send"
}
reason = "unlisted egress tool blocked — an attempted send to an unapproved sink" {
    not allowed_tools[input.tool_name]
    input.derived.verb == "send"
}
rule_id = "mcp_agent_allowlist_unclassified" {
    not allowed_tools[input.tool_name]
    input.derived.verb == "unknown"
}
