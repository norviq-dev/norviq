# OPA tests for the usage-driven intent ALLOWLIST policy (feat/intent-allowlist).
# The generated fixture (policies/threat_intent_sample.rego) is: allow_tools=[search_kb, get_order], readOnly.
# Proves default-deny + allowlist match (evasion-normalized) + read-only refinement + other-class deny.
# tests/api/test_threat_intent.py generates + evaluates live to catch drift; test_intent_tighten_only.py
# proves non-weakening vs the comprehensive baseline.

package norviq.intent.customer_support

_read := {"tool_name": "search_kb", "tool_name_normalized": "search_kb", "tool_params": {}, "agent": {"namespace": "default", "agent_class": "customer-support"}, "call_depth": 0}

test_allowlisted_read_allowed {
    decision == "allow" with input as _read
}

test_allowlisted_get_order_allowed {
    decision == "allow" with input as {"tool_name": "get_order", "tool_name_normalized": "get_order", "tool_params": {}, "agent": {"namespace": "default", "agent_class": "customer-support"}, "call_depth": 0}
}

test_non_allowlisted_delete_blocked {
    decision == "block" with input as {"tool_name": "delete_record", "tool_name_normalized": "delete_record", "tool_params": {}, "agent": {"namespace": "default", "agent_class": "customer-support"}, "call_depth": 0}
}

test_non_allowlisted_egress_blocked {
    decision == "block" with input as {"tool_name": "send_email", "tool_name_normalized": "send_email", "tool_params": {}, "agent": {"namespace": "default", "agent_class": "customer-support"}, "call_depth": 0}
}

test_homoglyph_of_allowlisted_allowed {
    # Cyrillic 'ѕ' in search_kb → skeleton == search_kb → still matches the allowlist.
    decision == "allow" with input as {"tool_name": "ѕearch_kb", "tool_name_normalized": "search_kb", "tool_params": {}, "agent": {"namespace": "default", "agent_class": "customer-support"}, "call_depth": 0}
}

test_other_class_default_denied {
    decision == "block" with input as {"tool_name": "search_kb", "tool_name_normalized": "search_kb", "tool_params": {}, "agent": {"namespace": "default", "agent_class": "batch"}, "call_depth": 0}
}
