# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# OPT-IN, DEFAULT-OFF MCP integration guardrail. Load it for a namespace as the additive guardrail
# target (ns, "__guardrail__") via the policy API; absent by default, so no existing namespace changes
# behaviour unless an operator materializes it.
#
# ── WHY A TEMPLATE AT ALL ──────────────────────────────────────────────────────────────────────────
# MCP traffic is ALREADY governed by every policy you have: the proxy maps MCP `arguments` onto
# `tool_params` verbatim, so a rule written for the SDK or the injected sidecar applies unchanged
# (tests/mcp/test_firewall.py::test_tools_call_maps_one_to_one_onto_tool_call_event). Nothing here is
# needed to police a dangerous tool call.
#
# What it adds is the two facts only the MCP proxy knows:
#
#   input.mcp        Gate-A state for THIS tool, computed at DISCOVERY and cached — pin_status,
#                    scan_severity, which server served it, over which transport. Reading it costs a
#                    dict lookup, which is what makes it affordable on every call.
#   input.direction  which PLANE the decision is on: "call" (the agent acting) or "answer" (the agent
#                    replying to a question the SERVER composed — the 2026-07-28 MRTR pattern).
#
# Neither is expressible with tool names alone: "escalate on drift for the payments class but block it
# elsewhere", "this integration is read-only", "never answer a server with a credential".
#
# ── THIS IS A GUARDRAIL, NOT A PERIMETER ───────────────────────────────────────────────────────────
# It defaults to ALLOW and blocks specific conditions, so a tool it says nothing about falls through
# to your baseline. That is deliberate — an MCP-shaped rule must not silently govern unrelated
# traffic — but it means this file cannot keep an unknown tool out. Pair it with a deny-by-default
# perimeter (tool-allowlist-perimeter.rego), which is registration-based and therefore holds against
# a name nobody has seen before.
#
# ── TRUST BOUNDARY ─────────────────────────────────────────────────────────────────────────────────
# `input.mcp` is PEP-REPORTED, exactly like `input.tool_name`. It is a POLICY input and never a TRUST
# input: identity comes from the caller's attested SVID and is never read from an MCP message. Do not
# use `input.mcp.server` to decide WHO is calling — only WHAT they are calling.
#
# v0 (--v0-compatible) dialect, matching every other shipped policy.
package norviq.guardrail.mcp_integration

# >>> EDIT: integrations this namespace may WRITE through. Everything else is read-only.
#     Server ids are the `--server-id` the proxy was started with, and they key the definition pins.
writable_servers = {"postgres-prod", "mailer"}

# >>> EDIT: the Gate-A severity at which a flagged definition should stop being usable.
#     "high" blocks a tool whose definition scanned high or critical; "medium" is stricter.
blocking_scan_severity = {"high", "critical"}

default decision = "allow"

default rule_id = "default_allow"

default reason = "Allowed"

# Only govern calls that actually arrived over MCP. A non-MCP caller carries no `input.mcp`, and this
# guardrail must not change its decision — that is what keeps it additive.
is_mcp {
	input.mcp.server
}

verb = v {
	v := input.derived.verb
}

# ── 1. Gate A: a definition that is not approved ───────────────────────────────────────────────────
# In `strict` pin mode a tool is quarantined until an operator approves its definition. The proxy
# already withholds it from the model; this makes the same fact available to policy, so an operator
# can decide per class rather than accepting the proxy's built-in action.
quarantined {
	is_mcp
	input.mcp.pin_status == "quarantined"
}

decision = "block" {
	quarantined
}

rule_id = "mcp_tool_not_approved" {
	quarantined
}

reason = "this MCP tool definition has not been approved" {
	quarantined
}

# ── 2. Gate A: a definition that CHANGED after approval (rug pull) ─────────────────────────────────
# Escalate rather than block: adopting a changed definition is a legitimate operator action, and the
# safe default is a human looking at the diff — not a silently broken agent.
drifted {
	is_mcp
	input.mcp.pin_status == "drift"
	not quarantined
}

decision = "escalate" {
	drifted
}

rule_id = "mcp_definition_drift" {
	drifted
}

reason = "this MCP tool definition changed after it was approved (possible rug pull)" {
	drifted
}

# ── 3. Gate A: a definition the scanner flagged ────────────────────────────────────────────────────
flagged {
	is_mcp
	blocking_scan_severity[input.mcp.scan_severity]
	not quarantined
	not drifted
}

decision = "block" {
	flagged
}

rule_id = "mcp_definition_flagged" {
	flagged
}

reason = "this MCP tool definition matched an instruction-injection pattern" {
	flagged
}

# ── 4. Per-integration scope: writes only through approved servers ─────────────────────────────────
# The same tool NAME served by a different MCP server is a different action against a different
# system. This is the rule a tool-name policy cannot express at all.
unapproved_write {
	is_mcp
	not writable_servers[input.mcp.server]
	verb != "read"
	verb != "unknown"
	not quarantined
	not drifted
	not flagged
}

decision = "block" {
	unapproved_write
}

rule_id = "mcp_unapproved_write_server" {
	unapproved_write
}

reason = "writes are not permitted through this MCP integration" {
	unapproved_write
}

# ── 5. The ANSWER plane (2026-07-28 MRTR) ──────────────────────────────────────────────────────────
# A server may answer a call with `resultType: "input_required"` and ask the CLIENT for more input.
# The client's reply is data leaving the trust boundary in response to a question the server composed
# — the confused-deputy vector with a specification behind it. A credential must never be the answer,
# whatever the server claims to need it for.
answer_carries_secret {
	input.direction == "answer"
	input.derived.data_classes[_] == "secret"
}

decision = "block" {
	answer_carries_secret
}

rule_id = "mcp_answer_carries_secret" {
	answer_carries_secret
}

reason = "a credential may not be sent back to an MCP server" {
	answer_carries_secret
}
