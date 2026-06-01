# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.owasp.llm06_excessive_agency_test

import rego.v1
import data.norviq.owasp.llm06_excessive_agency

test_blocks_destructive_operation if {
    result := llm06_excessive_agency.decision with input as {
        "tool_name": "drop_table",
        "tool_params": {"table": "users"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-a",
        "trust_score": 0.8,
        "call_count": 5,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_escalates_high_impact_operation if {
    result := llm06_excessive_agency.decision with input as {
        "tool_name": "grant_access",
        "tool_params": {"user": "alice"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-b",
        "trust_score": 0.8,
        "call_count": 2,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "escalate"
}

test_blocks_wildcard_edge_case if {
    trigger_input := {
        "tool_name": "list_files",
        "tool_params": {"path": "*"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-c",
        "trust_score": 0.8,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    llm06_excessive_agency.decision with input as trigger_input == "block"
    llm06_excessive_agency.rule_id with input as trigger_input == "llm06_wildcard_param"
}
