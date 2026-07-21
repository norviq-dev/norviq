# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# OPT-IN, DEFAULT-OFF per-namespace tool allowlist (deny-by-default tool scope).
# Load this for a namespace as the additive guardrail target (ns, "__guardrail__") via the policy API.
# It is ABSENT by default — no namespace, the single-cluster path, or the attack suite is affected unless
# an operator explicitly materializes it. Resolved as an additive/tighten-only overlay (like sector packs):
#   - a tool NOT in allowed_tools  -> ESCALATE (human review)  [tightens a permissive baseline allow]
#   - a tool IN allowed_tools      -> allow (defers to your other policies)
# Because it is tighten-only, this guardrail can NEVER weaken a block from your baseline/pack policies — an
# out-of-scope tool that is ALSO dangerous (e.g. an injection) still hard-blocks via the baseline.
#
# EDIT allowed_tools to your agent class's approved tools. v0 (--v0-compatible) dialect.
package norviq.guardrail.tool_allowlist

# >>> EDIT: the approved tools for this namespace/agent class
allowed_tools = {"search_kb", "get_order_status", "list_tickets", "get_account_balance", "read_document"}

gtool = lower(input.tool_name)
gtool_norm = lower(input.tool_name_normalized)

g_allowed {
    allowed_tools[gtool]
}
# homoglyph parity: match the engine's confusable-skeleton fold of the tool name too
g_allowed {
    allowed_tools[gtool_norm]
}

g_unlisted {
    not g_allowed
}

# A listed tool defers (allow); an UNLISTED tool is escalated for review (deny-by-default tool scope).
# Conditional escalate rule (not a `default`) so it passes the policy validator AND, as a tighten-only
# overlay, can only raise allow->escalate — never weaken a baseline/pack block.
default decision = "allow"
default rule_id = "tool_allowlisted"
default reason = "Tool is in the approved allowlist"

decision = "escalate" {
    g_unlisted
}
rule_id = "tool_not_in_allowlist" {
    g_unlisted
}
reason = "Tool is not in this namespace's approved allowlist — escalated for review (opt-in deny-by-default)" {
    g_unlisted
}
