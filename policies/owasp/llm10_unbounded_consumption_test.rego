# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.owasp.llm10_unbounded_consumption_test

import rego.v1
import data.norviq.owasp.llm10_unbounded_consumption

test_blocks_over_session_limit if {
    result := llm10_unbounded_consumption.decision with input as {
        "tool_name": "search_kb",
        "tool_params": {"query": "normal request"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-a",
        "trust_score": 0.7,
        "call_count": 101,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_escalates_burst_for_low_trust if {
    result := llm10_unbounded_consumption.decision with input as {
        "tool_name": "search_kb",
        "tool_params": {"query": "normal request"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-b",
        "trust_score": 0.3,
        "call_count": 25,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "escalate"
}

test_allows_normal_rate if {
    trigger_input := {
        "tool_name": "search_kb",
        "tool_params": {"query": "normal request"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-c",
        "trust_score": 0.9,
        "call_count": 10,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    llm10_unbounded_consumption.decision with input as trigger_input == "allow"
    llm10_unbounded_consumption.rule_id with input as trigger_input == "default_allow"
}
