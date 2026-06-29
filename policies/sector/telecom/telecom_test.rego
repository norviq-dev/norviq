# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.sector.telecom_test

import data.norviq.sector.telecom

test_sim_swap_without_strong_auth_escalates {
    d := telecom.decision with input as {"tool_name": "sim_swap", "tool_params": {"msisdn": "555"}}
    d == "escalate"
    telecom.rule_id == "sim_swap_escalate" with input as {"tool_name": "sim_swap", "tool_params": {}}
}

test_sim_swap_with_strong_auth_allowed {
    d := telecom.decision with input as {"tool_name": "sim_swap", "tool_params": {"msisdn": "555", "strong_auth": true}}
    d == "allow"
}

test_bulk_cpni_read_blocked {
    d := telecom.decision with input as {"tool_name": "list_call_records", "tool_params": {"limit": 1000}}
    d == "block"
    telecom.rule_id == "cpni_bulk_blocked" with input as {"tool_name": "list_call_records", "tool_params": {"limit": 1000}}
}

test_small_cpni_read_allowed {
    d := telecom.decision with input as {"tool_name": "get_cpni", "tool_params": {"limit": 1}}
    d == "allow"
}

test_benign_plan_lookup_allowed {
    d := telecom.decision with input as {"tool_name": "get_plan_details", "tool_params": {"plan": "p1"}}
    d == "allow"
}
