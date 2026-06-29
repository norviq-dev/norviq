# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.sector.healthcare_test

import data.norviq.sector.healthcare

test_clinical_action_escalates {
    d := healthcare.decision with input as {"tool_name": "order_medication", "tool_params": {"drug": "x"}}
    d == "escalate"
    healthcare.rule_id == "clinical_action_escalate" with input as {"tool_name": "order_medication", "tool_params": {}}
}

test_bulk_phi_read_blocked {
    d := healthcare.decision with input as {"tool_name": "query_patients", "tool_params": {"limit": 500}}
    d == "block"
    healthcare.rule_id == "phi_min_necessary" with input as {"tool_name": "query_patients", "tool_params": {"limit": 500}}
}

test_small_phi_read_allowed {
    d := healthcare.decision with input as {"tool_name": "get_patient", "tool_params": {"limit": 1}}
    d == "allow"
}

test_phi_identifier_egress_blocked {
    d := healthcare.decision with input as {"tool_name": "export_report", "tool_params": {"mrn": "12345"}}
    d == "block"
}

test_benign_schedule_read_allowed {
    d := healthcare.decision with input as {"tool_name": "get_appointment", "tool_params": {"date": "today"}}
    d == "allow"
}
