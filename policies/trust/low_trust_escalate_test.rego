# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.trust.low_trust_escalate_test

import rego.v1
import data.norviq.trust.low_trust_escalate

test_triggers_expected_decision if {
    result := low_trust_escalate.decision with input as {
        "tool_name": "low_trust_tool",
        "tool_params": {"query": "low_trust detected"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.3,
        "call_count": 101,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "escalate"
}

test_allows_safe_input if {
    result := low_trust_escalate.decision with input as {
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
        "tool_name": "trust_score_tool",
        "tool_params": {"query": "trust_score use"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.5,
        "call_count": 10,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    rid := low_trust_escalate.rule_id with input as trigger_input
    rsn := low_trust_escalate.reason with input as trigger_input
    rid == "low_trust_escalate"
    contains(rsn, "triggered")
}
