# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.trust.frozen_agent_block_test

import rego.v1
import data.norviq.trust.frozen_agent_block

test_blocks_when_trust_is_zero if {
    result := frozen_agent_block.decision with input as {
        "tool_name": "search_kb",
        "tool_params": {"query": "help"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-a",
        "trust_score": 0,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_allows_when_trust_is_positive if {
    result := frozen_agent_block.decision with input as {
        "tool_name": "search_kb",
        "tool_params": {"query": "help"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-b",
        "trust_score": 0.2,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "allow"
}

test_sets_reason_for_frozen_agent if {
    trigger_input := {
        "tool_name": "search_kb",
        "tool_params": {"query": "help"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-c",
        "trust_score": 0,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    rid := frozen_agent_block.rule_id with input as trigger_input
    rsn := frozen_agent_block.reason with input as trigger_input
    rid == "frozen_agent_block"
    contains(rsn, "frozen")
}
