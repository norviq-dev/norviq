# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.sector.ecommerce_test

import data.norviq.sector.ecommerce as ecom

test_refund_over_threshold_escalates {
    ecom.decision == "escalate" with input as {"tool_name": "issue_refund", "tool_params": {"amount": 5000}}
    ecom.rule_id == "ecom_refund_over_threshold_escalate" with input as {"tool_name": "issue_refund", "tool_params": {"amount": 5000}}
}

test_small_refund_allowed {
    ecom.decision == "allow" with input as {"tool_name": "issue_refund", "tool_params": {"amount": 20}}
}

test_mass_refund_blocked {
    ecom.decision == "block" with input as {"tool_name": "process_refund", "tool_params": {"count": 500}}
    ecom.rule_id == "ecom_mass_refund_blocked" with input as {"tool_name": "process_refund", "tool_params": {"count": 500}}
}

test_price_to_zero_blocked {
    ecom.decision == "block" with input as {"tool_name": "update_price", "tool_params": {"price": 0}}
    ecom.rule_id == "ecom_price_manipulation_blocked" with input as {"tool_name": "update_price", "tool_params": {"price": 0}}
}

test_full_discount_blocked {
    ecom.decision == "block" with input as {"tool_name": "create_coupon", "tool_params": {"percent": 100}}
}

test_bulk_pii_export_blocked {
    ecom.decision == "block" with input as {"tool_name": "export_customers", "tool_params": {"count": 10000}}
}

test_account_takeover_escalates {
    ecom.decision == "escalate" with input as {"tool_name": "disable_2fa", "tool_params": {}}
}

test_benign_order_lookup_allowed {
    ecom.decision == "allow" with input as {"tool_name": "get_order_status", "tool_params": {"id": "1"}}
}
