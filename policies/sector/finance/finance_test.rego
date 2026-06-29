# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.sector.finance_test

import data.norviq.sector.finance

test_wire_over_threshold_escalates {
    d := finance.decision with input as {"tool_name": "wire_transfer", "tool_params": {"amount": 25000}}
    d == "escalate"
    finance.rule_id == "wire_over_threshold_escalate" with input as {"tool_name": "wire_transfer", "tool_params": {"amount": 25000}}
}

test_wire_under_threshold_allowed {
    d := finance.decision with input as {"tool_name": "wire_transfer", "tool_params": {"amount": 500}}
    d == "allow"
}

test_new_beneficiary_escalates {
    d := finance.decision with input as {"tool_name": "send_payment", "tool_params": {"amount": 100, "beneficiary_known": false}}
    d == "escalate"
}

test_sod_self_approval_blocked {
    d := finance.decision with input as {"tool_name": "approve_transfer", "tool_params": {"initiator": "alice", "approver": "alice"}}
    d == "block"
    finance.rule_id == "sod_violation" with input as {"tool_name": "approve_transfer", "tool_params": {"initiator": "alice", "approver": "alice"}}
}

test_sod_distinct_approver_allowed {
    d := finance.decision with input as {"tool_name": "approve_transfer", "tool_params": {"initiator": "alice", "approver": "bob"}}
    d == "allow"
}

test_benign_balance_read_allowed {
    d := finance.decision with input as {"tool_name": "get_account_balance", "tool_params": {"account": "123"}}
    d == "allow"
}
