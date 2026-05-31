# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.industry.finance.deny_trading_tools_test

import rego.v1
import data.norviq.industry.finance.deny_trading_tools

test_triggers_expected_decision if {
    result := deny_trading_tools.decision with input as {
        "tool_name": "trade_tool",
        "tool_params": {"query": "trade detected"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.3,
        "call_count": 101,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_allows_safe_input if {
    result := deny_trading_tools.decision with input as {
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
        "tool_name": "buy_tool",
        "tool_params": {"query": "buy use"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-test",
        "trust_score": 0.5,
        "call_count": 10,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    rid := deny_trading_tools.rule_id with input as trigger_input
    rsn := deny_trading_tools.reason with input as trigger_input
    rid == "deny_trading_tools"
    contains(rsn, "triggered")
}
