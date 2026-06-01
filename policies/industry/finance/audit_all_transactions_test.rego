# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.industry.finance.audit_all_transactions_test

import rego.v1
import data.norviq.industry.finance.audit_all_transactions

test_triggers_expected_decision if {
    result := audit_all_transactions.decision with input as {
        "tool_name": "transaction_tool",
        "tool_params": {"query": "transaction detected"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.3,
        "call_count": 101,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "audit"
}

test_allows_safe_input if {
    result := audit_all_transactions.decision with input as {
        "tool_name": "safe_tool",
        "tool_params": {"query": "normal request"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.9,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "allow"
}

test_sets_rule_id_and_reason if {
    trigger_input := {
        "tool_name": "transfer_tool",
        "tool_params": {"query": "transfer use"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.5,
        "call_count": 10,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    rid := audit_all_transactions.rule_id with input as trigger_input
    rsn := audit_all_transactions.reason with input as trigger_input
    rid == "audit_all_transactions"
    contains(rsn, "triggered")
}
