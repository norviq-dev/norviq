# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policies for the multi-MCP support-chatbot scenario.

Two agent CLASSES share the SAME four MCP integrations and get very different power. That is the
whole argument for a policy enforcement point rather than per-server configuration: the servers do
not know which bot is calling them, and could not enforce a difference if they did.

    faq-bot        public-facing, unauthenticated users
                   -> read the docs, read GitHub issues. Nothing else. It cannot reach the customer
                      database at all, cannot post anywhere, cannot write.

    support-agent  authenticated tier-2 human in the loop
                   -> may query the customer replica and post in Slack, but:
                        * arbitrary SQL (execute_sql) is refused outright — the read tool exists
                        * egress outside the corporate domain is refused
                        * writes to GitHub are ESCALATED, not blocked (a human approves)
                        * the runbook volume is readable; /etc, ~/.ssh, k8s secrets are not

Both are written against the engine's EXISTING vocabulary (tool_name / tool_params / derived.verb /
tool_params_normalized) plus the new `input.mcp` context. Nothing here is MCP-specific except the two
rules that consume `input.mcp` — which is the point: the proxy translates, the policy language did
not have to change.
"""

from __future__ import annotations

# ── shared preamble ─────────────────────────────────────────────────────────────────────────────
# Partial-set triggers + a deterministic resolver, matching the shipped presets' shape so that when
# an input matches several triggers exactly one decision binds.
_RESOLVER = """
block_fired { blocks[_] }
escalate_fired { escalates[_] }

decision = "block" { block_fired }
decision = "escalate" { escalate_fired; not block_fired }

rule_id = sort([id | blocks[id]])[0] { block_fired }
rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }

reason = reasons[rule_id]
"""

# Gate-A carry-over. These two rules are the reason `input.mcp` exists: the proxy already refuses a
# drifted or withheld definition, but an OPERATOR may want a different action per class — audit it
# for the FAQ bot, hard-block it for the one touching customer data — and only policy can express
# that. The values are cached from discovery, so the rules cost nothing per call.
_MCP_SUPPLY_CHAIN = """
# The served tool definition no longer matches the one that was approved (rug pull).
blocks["mcp_supply_chain_drift"] {
  input.mcp.pin_status == "drift"
}

# The definition was withheld from the model by the Gate-A scanner, yet a call arrived for it —
# meaning the model learned the name somewhere other than the catalog it was shown.
blocks["mcp_withheld_tool_called"] {
  input.mcp.pin_status == "quarantined"
}
"""

FAQ_BOT = """package norviq.mcp.chatbot.faq

# A public-facing bot gets an ALLOWLIST, not a denylist: a denylist is a promise to have thought of
# everything, and this bot talks to strangers.
#
# Written as an explicit `blocks[...]` trigger rather than `default decision = "block"` plus an allow
# rule. Both enforce identically, but only this shape names WHY a call was refused — the audit row
# and the console show `faq_not_allowlisted` instead of a bare default. The API's policy validator
# requires it for exactly that reason, and it is the right requirement.

default decision = "allow"
default rule_id = "faq_allowlisted"
default reason = "allowed for the FAQ bot"

allowed_tools = {"search_issues", "get_issue", "read_file", "list_directory"}

blocks["faq_not_allowlisted"] {
  not allowed_tools[input.tool_name]
}

# Even an allowlisted read is refused if it escapes the runbook volume. `read_file` is a read
# PRIMITIVE, not a docs tool — the path is what makes it safe, and the path is attacker-influenced.
blocks["faq_path_outside_runbooks"] {
  some k
  v := input.tool_params_normalized[k]
  is_string(v)
  contains(v, "/")
  not startswith(v, "/runbooks/")
}

""" + _MCP_SUPPLY_CHAIN + """
reasons = {
  "faq_not_allowlisted": "not on the FAQ bot's allowlist",
  "faq_path_outside_runbooks": "filesystem access outside the runbook volume",
  "mcp_supply_chain_drift": "this MCP server changed a tool definition after it was approved",
  "mcp_withheld_tool_called": "the tool definition was withheld from the model and is not approved",
  "faq_allowlisted": "allowed for the FAQ bot",
}

escalates["__never__"] { false }
""" + _RESOLVER

SUPPORT_AGENT = """package norviq.mcp.chatbot.support

default decision = "allow"
default rule_id = "support_default_allow"
default reason = "allowed"

# --- the crown jewels -------------------------------------------------------------------------
# Arbitrary SQL is refused even though this class may read the database. `run_query` is the
# supported path; `execute_sql` is a capability nobody approved, and it exists on the server whether
# or not anyone meant to enable it.
blocks["support_no_arbitrary_sql"] {
  input.tool_name == "execute_sql"
}

# Destructive verbs, whatever the tool is called. Classified by the engine, so a renamed tool is
# still caught.
blocks["support_no_destructive_verb"] {
  input.derived.verb == "delete"
}

# Write-shaped SQL smuggled through the read tool.
blocks["support_no_write_sql"] {
  input.tool_name == "run_query"
  sql := lower(input.tool_params_normalized.sql)
  write_keyword(sql)
}
write_keyword(s) { contains(s, "insert ") }
write_keyword(s) { contains(s, "update ") }
write_keyword(s) { contains(s, "delete ") }
write_keyword(s) { contains(s, "drop ") }
write_keyword(s) { contains(s, "alter ") }
write_keyword(s) { contains(s, "truncate ") }

# --- egress -------------------------------------------------------------------------------------
# The composition risk: this class can read the customer replica AND send messages. The boundary is
# the DESTINATION, which is the only place the composition is visible.
blocks["support_no_external_egress"] {
  some k
  v := input.tool_params_normalized[k]
  is_string(v)
  contains(v, "@")
  not endswith(v, "@corp.internal")
}

# --- filesystem ---------------------------------------------------------------------------------
blocks["support_no_sensitive_path"] {
  some k
  v := input.tool_params_normalized[k]
  is_string(v)
  sensitive(v)
}
sensitive(v) { contains(v, "/etc/") }
sensitive(v) { contains(v, ".ssh/") }
sensitive(v) { contains(v, ".aws/") }
sensitive(v) { contains(v, "/var/run/secrets") }
sensitive(v) { contains(v, "..") }

# --- prompt injection in arguments ---------------------------------------------------------------
blocks["support_prompt_injection"] {
  some k
  v := input.tool_params_normalized[k]
  is_string(v)
  injection(v)
}
injection(v) { contains(v, "ignore previous instructions") }
injection(v) { contains(v, "disregard your instructions") }

# --- supply chain (Gate-A carry-over) -------------------------------------------------------------
""" + _MCP_SUPPLY_CHAIN + """
# --- human in the loop ----------------------------------------------------------------------------
# Writing to a public surface is permitted but ESCALATED — this is where "escalate" earns its place
# as a distinct decision rather than a softer block.
escalates["support_review_public_write"] {
  input.tool_name == "create_issue"
}
escalates["support_review_public_write"] {
  input.tool_name == "add_issue_comment"
}

reasons = {
  "support_no_arbitrary_sql": "arbitrary SQL execution is not an approved capability for this class",
  "support_no_destructive_verb": "destructive operations are not permitted",
  "support_no_write_sql": "the read-only query tool was given a write statement",
  "support_no_external_egress": "message destination is outside the corporate domain",
  "support_no_sensitive_path": "filesystem access outside the runbook volume",
  "support_prompt_injection": "prompt-injection payload in tool arguments",
  "mcp_supply_chain_drift": "this MCP server changed a tool definition after it was approved",
  "mcp_withheld_tool_called": "the tool definition was withheld from the model and is not approved",
  "support_review_public_write": "writing to a public surface requires human approval",
  "support_default_allow": "allowed",
}
""" + _RESOLVER


POLICIES = {
    "faq-bot": FAQ_BOT,
    "support-agent": SUPPORT_AGENT,
}
