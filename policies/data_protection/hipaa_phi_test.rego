# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.data_protection.hipaa_phi_test

import rego.v1
import data.norviq.data_protection.hipaa_phi

test_triggers_expected_decision if {
    result := hipaa_phi.decision with input as {
        "tool_name": "diagnosis_tool",
        "tool_params": {"query": "diagnosis detected"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.3,
        "call_count": 101,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_allows_safe_input if {
    result := hipaa_phi.decision with input as {
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
        "tool_name": "patient_id_tool",
        "tool_params": {"query": "patient_id use"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.5,
        "call_count": 10,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    rid := hipaa_phi.rule_id with input as trigger_input
    rsn := hipaa_phi.reason with input as trigger_input
    rid == "hipaa_phi"
    contains(rsn, "triggered")
}
