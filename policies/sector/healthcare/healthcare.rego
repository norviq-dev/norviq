# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Sector starter pack: HEALTHCARE & PUBLIC HEALTH.
# Flagship risk (SECTOR-RECON): injection -> autonomous medication order, or bulk-PHI exfil
# (minimum-necessary violation). HIPAA §164.312 (audit/access) + §164.514(d) min-necessary + FDA HITL.
#   - clinical action tool (order/prescribe/modify chart) -> ESCALATE (clinical_action_escalate)
#   - bulk PHI read over threshold                         -> BLOCK    (phi_min_necessary)
#   - PHI identifier on an egress tool                     -> BLOCK    (phi_identifier_egress)
# Builds on data_protection/hipaa_phi. STARTER: hc_phi_fields is a representative subset of the 18
# HIPAA identifiers — extend toward the full set for production. Tune verbs/threshold below.
package norviq.sector.healthcare

# >>> PACK-CONTRIB-BEGIN healthcare
hc_tool = lower(input.tool_name)
hc_clinical_verbs = [
    "order_medication", "prescribe", "place_order", "modify_chart", "administer_med",
    "discontinue_med", "update_problem_list", "sign_order",
]
hc_phi_read_verbs = ["get_patient", "query_patients", "list_patients", "fetch_records", "search_charts", "export_phi"]
hc_egress_verbs = ["export", "send", "email", "upload", "share", "transmit"]
# Clinical-specific PHI field names only — generic PII (SSN values, dates) is composed in from the
# canonical shared pii rule via the pack's `requires: ["pii"]`, not re-listed here.
hc_phi_fields = ["mrn", "medical_record", "patient_id", "diagnosis", "icd", "health_plan", "patient_name"]
hc_bulk_threshold = 50

escalates["clinical_action_escalate"] {
    contains(hc_tool, hc_clinical_verbs[_])
}
reasons["clinical_action_escalate"] = "Healthcare: clinical action requires clinician sign-off (human-in-the-loop; FDA HITL)"

blocks["phi_min_necessary"] {
    contains(hc_tool, hc_phi_read_verbs[_])
    to_number(input.tool_params.limit) > hc_bulk_threshold
}
reasons["phi_min_necessary"] = "Healthcare: bulk PHI read exceeds minimum-necessary (HIPAA §164.514(d))"

blocks["phi_identifier_egress"] {
    contains(hc_tool, hc_egress_verbs[_])
    input.tool_params[k]
    contains(lower(k), hc_phi_fields[_])
}
reasons["phi_identifier_egress"] = "Healthcare: PHI identifier on an egress tool blocked (HIPAA §164.312)"

# F-21: destination-based egress guard (complements phi_identifier_egress, which keys on a PHI field name). An
# export tool to an EXTERNAL destination is PHI exfil even when no PHI field is in the params (the record body
# carries it) → block; to no/internal destination → escalate. Block precedence means a PHI-key egress still blocks.
hc_dest_keys = {"destination", "dest", "target", "url", "endpoint", "bucket", "recipient", "to", "sink", "upload_url", "callback", "webhook"}
# Narrow DATA-EXPORT verbs for the destination-based rule (general send/email/share stay governed by the
# existing PHI-key phi_identifier_egress, so benign patient messaging is not over-escalated).
hc_data_export_verbs = ["export", "upload", "dump", "extract", "backup", "sync", "sftp", "ftp", "publish", "download", "transmit"]

hc_external_destination {
    some k
    hc_dest_keys[lower(k)]
    v := input.tool_params[k]
    is_string(v)
    hc_external_pattern(lower(v))
}
hc_external_pattern(v) { startswith(v, "s3://") }
hc_external_pattern(v) { startswith(v, "http://") }
hc_external_pattern(v) { startswith(v, "https://") }
hc_external_pattern(v) { startswith(v, "ftp://") }
hc_external_pattern(v) { startswith(v, "sftp://") }
hc_external_pattern(v) { startswith(v, "gs://") }
hc_external_pattern(v) { startswith(v, "azure://") }
hc_external_pattern(v) { contains(v, "external") }
hc_external_pattern(v) { contains(v, "@") }

blocks["phi_export_exfil_blocked"] {
    contains(hc_tool, hc_data_export_verbs[_])
    hc_external_destination
}
reasons["phi_export_exfil_blocked"] = "Healthcare: PHI export routed to an external destination — blocked (HIPAA §164.312)"

escalates["phi_export_review_escalate"] {
    contains(hc_tool, hc_data_export_verbs[_])
    not hc_external_destination
}
reasons["phi_export_review_escalate"] = "Healthcare: PHI-export tool — hold for review (no/internal destination)"
# >>> PACK-CONTRIB-END healthcare

# >>> RESOLVER-BEGIN
default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

blocks["__never__"] { false }
escalates["__never__"] { false }
audits["__never__"] { false }
reasons["__never__"] = "" { false }

block_fired { blocks[_] }
escalate_fired { escalates[_] }
audit_fired { audits[_] }

decision = "block" { block_fired }
decision = "escalate" { escalate_fired; not block_fired }
decision = "audit" { audit_fired; not block_fired; not escalate_fired }

rule_id = sort([id | blocks[id]])[0] { block_fired }
rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
rule_id = sort([id | audits[id]])[0] { audit_fired; not block_fired; not escalate_fired }

reason = reasons[sort([id | blocks[id]])[0]] { block_fired }
reason = reasons[sort([id | escalates[id]])[0]] { escalate_fired; not block_fired }
reason = reasons[sort([id | audits[id]])[0]] { audit_fired; not block_fired; not escalate_fired }
# >>> RESOLVER-END
