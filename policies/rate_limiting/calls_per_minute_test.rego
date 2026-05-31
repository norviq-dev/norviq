# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.rate_limiting.calls_per_minute_test

import rego.v1
import data.norviq.rate_limiting.calls_per_minute

test_triggers_expected_decision if {
    result := calls_per_minute.decision with input as {
        "tool_name": "calls_per_minute_tool",
        "tool_params": {"query": "calls_per_minute detected"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.3,
        "call_count": 101,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "escalate"
}

test_allows_safe_input if {
    result := calls_per_minute.decision with input as {
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
        "tool_name": "limit_tool",
        "tool_params": {"query": "limit use"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.5,
        "call_count": 10,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    rid := calls_per_minute.rule_id with input as trigger_input
    rsn := calls_per_minute.reason with input as trigger_input
    rid == "calls_per_minute"
    contains(rsn, "triggered")
}
