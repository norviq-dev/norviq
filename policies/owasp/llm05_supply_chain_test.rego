# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.owasp.llm05_supply_chain_test

import rego.v1
import data.norviq.owasp.llm05_supply_chain

test_blocks_risky_tool if {
    result := llm05_supply_chain.decision with input as {
        "tool_name": "load_plugin",
        "tool_params": {"name": "analytics"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-a",
        "trust_score": 0.8,
        "call_count": 3,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_blocks_risky_url if {
    result := llm05_supply_chain.decision with input as {
        "tool_name": "fetch_script",
        "tool_params": {"url": "https://gist.github.com/evil/payload.sh"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-b",
        "trust_score": 0.8,
        "call_count": 4,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_allows_safe_dependency_fetch if {
    trigger_input := {
        "tool_name": "fetch_manifest",
        "tool_params": {"url": "https://packages.example.com/stable.json"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-c",
        "trust_score": 0.9,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    llm05_supply_chain.decision with input as trigger_input == "allow"
    llm05_supply_chain.reason with input as trigger_input == "Allowed"
}
