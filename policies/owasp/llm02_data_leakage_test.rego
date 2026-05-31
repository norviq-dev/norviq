# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.owasp.llm02_data_leakage_test

import rego.v1
import data.norviq.owasp.llm02_data_leakage

test_blocks_sensitive_external_tool_call if {
    result := llm02_data_leakage.decision with input as {
        "tool_name": "send_email",
        "tool_params": {"api_key": "abc123", "to": "a@example.com"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-a",
        "trust_score": 0.7,
        "call_count": 3,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_audits_non_sensitive_external_tool_call if {
    result := llm02_data_leakage.decision with input as {
        "tool_name": "post_webhook",
        "tool_params": {"event": "order.created"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-b",
        "trust_score": 0.7,
        "call_count": 4,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "audit"
}

test_allows_internal_tool_call if {
    trigger_input := {
        "tool_name": "fetch_kb",
        "tool_params": {"query": "faq"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-c",
        "trust_score": 0.9,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    llm02_data_leakage.decision with input as trigger_input == "allow"
    llm02_data_leakage.rule_id with input as trigger_input == "default_allow"
}
