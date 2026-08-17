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

# >>> EDIT: every MCP server this namespace may reach AT ALL, read or write.
#     A server absent from this set is one nobody registered, and a tool served by it is the
#     rogue-server vector: the definition can look perfectly ordinary — `lookup_record`, "Looks up an
#     account record by id" — because the finding is not the tool, it is WHO is serving it. Gate A has
#     nothing to say about it (the description is clean, so scan_severity is "none" and tofu pins it on
#     first sight) and `writable_servers` below deliberately exempts reads, so before this set existed
#     a read from an unregistered server passed every rule in this file.
#     Ids are the `--server-id` the proxy was started with.
#
#     This is a SUPERSET of `writable_servers`: `reporting-kb` below is registered and read-only, which
#     is the ordinary shape for a knowledge base. The two sets answer different questions — "may I
#     reach it at all" and "may I write through it" — and collapsing them into one is what left reads
#     from an unregistered server ungoverned.
known_servers = {"postgres-prod", "mailer", "reporting-kb"}

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

# ── 0. The server itself is not registered ─────────────────────────────────────────────────────────
# Highest precedence, because it is the strongest statement available: not "this call is wrong" but
# "you should not be talking to this server at all". Everything below asks whether a TOOL is safe,
# which already concedes the server is one you meant to reach.
#
# This is the rogue-server vector, and it is invisible to every other rule in this file: the tool's
# description is clean, so the scanner says "none"; tofu pins it on first sight, so pin_status says
# "pinned"; and it is a read, which `unapproved_write` exempts by design. Live, `lookup_record` on an
# unregistered server returned its record through all four rules untouched.
unknown_server {
	is_mcp
	not known_servers[input.mcp.server]
}

decision = "block" {
	unknown_server
}

rule_id = "mcp_unregistered_server" {
	unknown_server
}

reason = "this MCP server is not registered for this namespace" {
	unknown_server
}

# ── 0b. Gate A never saw this definition ───────────────────────────────────────────────────────────
# `scan_severity` is "unknown" and `definition_seen` is false when the proxy has no catalog entry for
# the tool — a call that arrived without a mediated `tools/list` (a stateless client, or a proxy
# restarted since discovery). Every Gate-A rule below tests for a SPECIFIC bad state, so a tool in no
# state at all satisfies none of them and falls through to allow: the checks are armed and the thing
# they protect was never inspected.
#
# Measured live: a raw stateless call sequence produced pin_status "unknown", definition_seen false,
# scan_severity "unknown", and no rule fired.
#
# Escalate, not block. A cold start is ordinary and legitimate; what is not ordinary is acting on a
# definition nobody has read. A human deciding once is the proportionate response, and it matches how
# drift is handled two rules down.
unscanned {
	is_mcp
	not unknown_server
	not input.mcp.definition_seen
}

decision = "escalate" {
	unscanned
}

rule_id = "mcp_definition_never_scanned" {
	unscanned
}

reason = "this MCP tool definition was never inspected by Gate A" {
	unscanned
}

# ── 1. Gate A: a definition that is not approved ───────────────────────────────────────────────────
# In `strict` pin mode a tool is quarantined until an operator approves its definition. The proxy
# already withholds it from the model; this makes the same fact available to policy, so an operator
# can decide per class rather than accepting the proxy's built-in action.
quarantined {
	is_mcp
	not unknown_server
	not unscanned
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
	not unknown_server
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
	not unknown_server
	not unscanned
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
	not unknown_server
	not unscanned
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
