# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.tool_safety.deny_file_system_access_test

import rego.v1
import data.norviq.tool_safety.deny_file_system_access

test_triggers_expected_decision if {
    result := deny_file_system_access.decision with input as {
        "tool_name": "/etc/passwd_tool",
        "tool_params": {"query": "/etc/passwd detected"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.3,
        "call_count": 101,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_allows_safe_input if {
    result := deny_file_system_access.decision with input as {
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
        "tool_name": ".._tool",
        "tool_params": {"query": ".. use"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.5,
        "call_count": 10,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    rid := deny_file_system_access.rule_id with input as trigger_input
    rsn := deny_file_system_access.reason with input as trigger_input
    rid == "deny_file_system_access"
    contains(rsn, "triggered")
}
