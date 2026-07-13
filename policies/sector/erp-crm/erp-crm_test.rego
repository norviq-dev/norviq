# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.sector.erp_crm_test

import data.norviq.sector.erp_crm as erp

test_financial_posting_escalates {
    erp.decision == "escalate" with input as {"tool_name": "post_journal_entry", "tool_params": {}}
    erp.rule_id == "erp_financial_posting_escalate" with input as {"tool_name": "post_journal_entry", "tool_params": {}}
}

test_vendor_master_change_escalates {
    erp.decision == "escalate" with input as {"tool_name": "update_vendor_master", "tool_params": {}}
}

test_bank_detail_change_blocked {
    erp.decision == "block" with input as {"tool_name": "change_bank_account", "tool_params": {}}
    erp.rule_id == "erp_bank_detail_change_blocked" with input as {"tool_name": "change_bank_account", "tool_params": {}}
}

test_privileged_txn_blocked {
    erp.decision == "block" with input as {"tool_name": "grant_role", "tool_params": {}}
}

test_sod_self_create_and_approve_blocked {
    erp.decision == "block" with input as {"tool_name": "approve_payment", "tool_params": {"created_by": "alice", "approver": "alice"}}
    erp.rule_id == "erp_sod_violation" with input as {"tool_name": "approve_payment", "tool_params": {"created_by": "alice", "approver": "alice"}}
}

test_mass_export_blocked {
    erp.decision == "block" with input as {"tool_name": "bulk_export", "tool_params": {"count": 5000}}
}

test_small_export_allowed {
    erp.decision == "allow" with input as {"tool_name": "export_report", "tool_params": {"count": 1}}
}

test_benign_read_allowed {
    erp.decision == "allow" with input as {"tool_name": "get_sales_order", "tool_params": {"id": "1"}}
}
