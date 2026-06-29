# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.sector.government_test

import data.norviq.sector.government

test_rights_impacting_escalates {
    d := government.decision with input as {"tool_name": "deny_benefit", "tool_params": {"case": "c1"}}
    d == "escalate"
    government.rule_id == "rights_impacting_escalate" with input as {"tool_name": "deny_benefit", "tool_params": {}}
}

test_cui_field_egress_blocked {
    d := government.decision with input as {"tool_name": "export_dataset", "tool_params": {"ssn": "111-22-3333"}}
    d == "block"
    government.rule_id == "cui_fti_egress_blocked" with input as {"tool_name": "export_dataset", "tool_params": {"ssn": "1"}}
}

test_cui_marking_in_value_blocked {
    d := government.decision with input as {"tool_name": "send_email", "tool_params": {"body": "Classification CUI//SP-TAX attached"}}
    d == "block"
}

test_internal_read_allowed {
    d := government.decision with input as {"tool_name": "get_case_status", "tool_params": {"case": "c1"}}
    d == "allow"
}
