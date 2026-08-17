# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Tests for the MCP integration guardrail. Two properties matter and pull in opposite directions:
# it must act on the Gate-A and plane facts only the proxy knows, and it must leave everything else
# exactly as it found it — a guardrail that governs unrelated traffic is not additive, and an
# operator who discovers that switches it off.
#
# Run: opa test --v0-compatible policies/templates/mcp_integration_guardrail.rego \
#                              policies/templates/mcp_integration_guardrail_test.rego
package norviq.guardrail.mcp_integration_test

import data.norviq.guardrail.mcp_integration as g

# A call as the proxy reports one. `derived` mirrors the evaluator's own input document.
#
# `definition_seen` is true here because that is what a DISCOVERED tool carries — the proxy sets it on
# every context it builds, so a fixture omitting it describes an input the PEP cannot emit. The false
# case is a real state (a call with no mediated tools/list behind it) and gets its own fixture below,
# not a silent default.
_mcp(server, pin, sev, verb) := {
	"tool_name": "some_tool",
	"mcp": {
		"server": server, "transport": "stdio", "surface": "tools/call",
		"pin_status": pin, "scan_severity": sev, "definition_seen": true,
	},
	"direction": "call",
	"derived": {"verb": verb, "data_classes": []},
}

# The same call for a tool Gate A never saw: no catalog entry, so no pin and no scan verdict.
_unseen(server) := {
	"tool_name": "some_tool",
	"mcp": {
		"server": server, "transport": "stdio", "surface": "tools/call",
		"pin_status": "unknown", "scan_severity": "unknown", "definition_seen": false,
	},
	"direction": "call",
	"derived": {"verb": "read", "data_classes": []},
}

# ── it must not touch non-MCP traffic ──────────────────────────────────────────────────────────────

test_a_non_mcp_call_is_untouched {
	# No `input.mcp` at all: the SDK and sidecar paths. A guardrail that decided here would be
	# changing the behaviour of every policy the operator already has.
	g.decision == "allow" with input as {"tool_name": "send_email", "derived": {"verb": "send", "data_classes": []}}
	g.rule_id == "default_allow" with input as {"tool_name": "send_email", "derived": {"verb": "send", "data_classes": []}}
}

test_an_ordinary_approved_mcp_call_is_allowed {
	g.decision == "allow" with input as _mcp("postgres-prod", "pinned", "none", "read")
}

# ── Gate A state ───────────────────────────────────────────────────────────────────────────────────

test_a_quarantined_definition_blocks {
	g.decision == "block" with input as _mcp("reporting-kb", "quarantined", "none", "read")
	g.rule_id == "mcp_tool_not_approved" with input as _mcp("reporting-kb", "quarantined", "none", "read")
}

test_a_drifted_definition_escalates_rather_than_blocks {
	# Adopting a changed definition is a legitimate operator action; the safe default is a human
	# looking at the diff, not a silently broken agent.
	g.decision == "escalate" with input as _mcp("postgres-prod", "drift", "none", "read")
	g.rule_id == "mcp_definition_drift" with input as _mcp("postgres-prod", "drift", "none", "read")
}

test_a_flagged_definition_blocks {
	g.decision == "block" with input as _mcp("postgres-prod", "pinned", "critical", "read")
	g.rule_id == "mcp_definition_flagged" with input as _mcp("postgres-prod", "pinned", "critical", "read")
}

test_a_low_severity_finding_does_not_block {
	# The scanner is a heuristic; blocking on every finding would make it unusable.
	g.decision == "allow" with input as _mcp("postgres-prod", "pinned", "low", "read")
}

test_quarantine_wins_over_drift_so_one_call_gets_one_reason {
	# Both facts can be true at once. Without an explicit precedence the complete rules conflict and
	# the whole evaluation errors, which fails closed but tells the operator nothing.
	g.rule_id == "mcp_tool_not_approved" with input as _mcp("reporting-kb", "quarantined", "critical", "delete")
}

# ── per-integration scope ──────────────────────────────────────────────────────────────────────────

test_a_write_through_a_read_only_integration_blocks {
	g.decision == "block" with input as _mcp("reporting-kb", "pinned", "none", "write")
	g.rule_id == "mcp_unapproved_write_server" with input as _mcp("reporting-kb", "pinned", "none", "write")
}

test_a_read_through_the_same_read_only_integration_is_allowed {
	# The point of scoping by integration rather than by tool name: the SAME tool against a different
	# system is a different action.
	g.decision == "allow" with input as _mcp("reporting-kb", "pinned", "none", "read")
}

test_a_write_through_an_approved_integration_is_allowed {
	g.decision == "allow" with input as _mcp("mailer", "pinned", "none", "send")
}

test_an_unclassified_verb_is_not_treated_as_a_write {
	# `unknown` means the classifier could not tell, and a tool NAME is chosen by the agent side —
	# so treating unknown as a write would block on a rename rather than on an action. The perimeter
	# allowlist is what catches an unrecognised tool; see the template header.
	g.decision == "allow" with input as _mcp("reporting-kb", "pinned", "none", "unknown")
}

# ── the ANSWER plane (2026-07-28 MRTR) ─────────────────────────────────────────────────────────────

test_answering_a_server_with_a_credential_blocks {
	inp := {
		"tool_name": "read_file",
		"mcp": {"server": "postgres-prod", "pin_status": "pinned", "scan_severity": "none", "definition_seen": true},
		"direction": "answer",
		"derived": {"verb": "read", "data_classes": ["secret"]},
	}

	g.decision == "block" with input as inp
	g.rule_id == "mcp_answer_carries_secret" with input as inp
}

test_answering_a_server_without_a_credential_is_allowed {
	# Refusing every answer would break MRTR entirely — a roots/list reply is ordinary.
	inp := {
		"tool_name": "read_file",
		"mcp": {"server": "postgres-prod", "pin_status": "pinned", "scan_severity": "none", "definition_seen": true},
		"direction": "answer",
		"derived": {"verb": "read", "data_classes": []},
	}

	g.decision == "allow" with input as inp
}

test_the_same_credential_on_the_CALL_plane_is_not_this_rule {
	# This guardrail governs the ANSWER plane; a credential in an outbound call is the data-leakage
	# rules' job in the baseline. Overlapping here would double-report one event.
	inp := {
		"tool_name": "send_email",
		"mcp": {"server": "mailer", "pin_status": "pinned", "scan_severity": "none", "definition_seen": true},
		"direction": "call",
		"derived": {"verb": "send", "data_classes": ["secret"]},
	}

	g.rule_id != "mcp_answer_carries_secret" with input as inp
}

# ── contract ───────────────────────────────────────────────────────────────────────────────────────

test_every_non_allow_decision_carries_a_named_rule_and_a_real_reason {
	# A block whose rule_id is "default_allow", or whose reason is "Allowed", is unattributable in the
	# audit log — the operator sees a denial and cannot tell which clause produced it.
	inp := _mcp("reporting-kb", "quarantined", "none", "delete")
	g.decision == "block" with input as inp
	g.rule_id != "default_allow" with input as inp
	g.reason != "Allowed" with input as inp
}

# ── the server registry (rogue-server vector) ──────────────────────────────────────────────────────

test_any_call_to_an_unregistered_server_blocks {
	# The finding is WHO is serving the tool, not what the tool is. Nothing about this call looks
	# wrong: clean description, pinned on first sight, and a read.
	inp := _mcp("rogue-lab", "pinned", "none", "read")
	g.decision == "block" with input as inp
	g.rule_id == "mcp_unregistered_server" with input as inp
}

test_a_read_from_an_unregistered_server_is_not_exempt {
	# `unapproved_write` exempts reads by design, which is why the rogue-server vector walked through
	# every rule in this file before the registry existed. Reading a canary record out of a server
	# nobody registered is the whole attack.
	g.decision == "block" with input as _mcp("rogue-lab", "pinned", "none", "read")
}

test_registration_outranks_every_gate_a_state {
	# "You should not be talking to this server" is a stronger statement than any verdict about the
	# tool, and one call must get one reason. Drift alone escalates; drift on an unregistered server
	# must still block, or the weaker outcome wins.
	inp := _mcp("rogue-lab", "drift", "critical", "delete")
	g.decision == "block" with input as inp
	g.rule_id == "mcp_unregistered_server" with input as inp
}

test_a_registered_server_is_unaffected_by_the_registry_rule {
	g.rule_id != "mcp_unregistered_server" with input as _mcp("postgres-prod", "pinned", "none", "read")
}

# ── a definition Gate A never inspected ────────────────────────────────────────────────────────────

test_a_tool_gate_a_never_saw_escalates {
	# Measured live: a stateless call with no mediated tools/list behind it reports pin_status
	# "unknown", scan_severity "unknown", definition_seen false. Every Gate-A rule tests for a
	# SPECIFIC bad state, so a tool in no state at all satisfied none of them and was allowed.
	g.decision == "escalate" with input as _unseen("postgres-prod")
	g.rule_id == "mcp_definition_never_scanned" with input as _unseen("postgres-prod")
}

test_unknown_severity_is_not_read_as_clean {
	# "unknown" means nobody looked; "none" means someone looked and it was fine. A guardrail that
	# cannot tell them apart is the fail-open shape this codebase keeps hitting.
	g.decision != "allow" with input as _unseen("postgres-prod")
}

test_an_unscanned_tool_on_an_unregistered_server_still_blocks {
	# Precedence again: escalate must not soften a block.
	inp := _unseen("rogue-lab")
	g.decision == "block" with input as inp
	g.rule_id == "mcp_unregistered_server" with input as inp
}

test_a_discovered_clean_tool_does_not_trip_the_unscanned_rule {
	# The rule must fire on absence of inspection, never on ordinary discovered traffic.
	g.decision == "allow" with input as _mcp("postgres-prod", "pinned", "none", "read")
}

test_a_non_mcp_call_is_untouched_by_both_new_rules {
	# The additive property, restated against the rules most likely to break it: neither reads a field
	# a non-MCP caller has, and `is_mcp` must keep them off that path entirely.
	inp := {"tool_name": "send_email", "derived": {"verb": "send", "data_classes": []}}
	g.decision == "allow" with input as inp
	g.rule_id == "default_allow" with input as inp
}
