# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.rate_limiting.burst_detection_test

import rego.v1
import data.norviq.rate_limiting.burst_detection

test_triggers_expected_decision if {
    result := burst_detection.decision with input as {
        "tool_name": "burst_tool",
        "tool_params": {"query": "burst detected"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.3,
        "call_count": 101,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "escalate"
}

test_allows_safe_input if {
    result := burst_detection.decision with input as {
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
        "tool_name": "spike_tool",
        "tool_params": {"query": "spike use"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.5,
        "call_count": 10,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    rid := burst_detection.rule_id with input as trigger_input
    rsn := burst_detection.reason with input as trigger_input
    rid == "burst_detection"
    contains(rsn, "triggered")
}
