# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Sector starter pack: ERP / CRM (SAP-like business suites).
# Flagship risk: an agent posts financials, changes vendor BANK details (fraud), runs privileged
# transactions, violates segregation-of-duties, or mass-exports customer/employee PII.
#   - financial posting / payment-run / PO approval -> ESCALATE (erp_financial_posting_escalate)
#   - vendor master-data change                     -> ESCALATE (erp_master_data_change_escalate)
#   - vendor BANK-account change                    -> BLOCK    (erp_bank_detail_change_blocked)
#   - privileged transaction / admin verb           -> BLOCK    (erp_privileged_txn_blocked)
#   - SoD: same identity creates vendor AND approves payment -> BLOCK (erp_sod_violation)
#   - mass export over threshold                    -> BLOCK    (erp_mass_export_blocked)
# Composes canonical PII (requires: pii). STARTER — tune verbs/thresholds. v0 (--v0-compatible).
package norviq.sector.erp_crm

# >>> PACK-CONTRIB-BEGIN erp-crm
erp_tool = lower(input.tool_name)
erp_posting_verbs = ["post_journal", "payment_run", "approve_po", "post_invoice", "release_payment", "post_document", "run_payment", "approve_payment"]
erp_vendor_verbs = ["change_vendor", "update_vendor_master", "edit_vendor", "modify_supplier", "update_customer_master"]
erp_bank_verbs = ["change_bank", "update_bank_details", "change_bank_account", "modify_bank", "update_iban"]
erp_priv_verbs = ["grant_role", "assign_profile", "change_authorization", "create_user", "unlock_user", "debug_session", "table_edit", "se16", "su01"]
erp_export_verbs = ["export", "download", "extract", "bulk_export", "data_export"]
erp_export_threshold = 100

escalates["erp_financial_posting_escalate"] {
    contains(erp_tool, erp_posting_verbs[_])
}
reasons["erp_financial_posting_escalate"] = "ERP: financial posting / payment run / PO approval requires human approval (SOX ITGC)"

escalates["erp_master_data_change_escalate"] {
    contains(erp_tool, erp_vendor_verbs[_])
}
reasons["erp_master_data_change_escalate"] = "ERP: vendor/customer master-data change — hold for review"

blocks["erp_bank_detail_change_blocked"] {
    contains(erp_tool, erp_bank_verbs[_])
}
reasons["erp_bank_detail_change_blocked"] = "ERP: vendor bank-account change blocked — agents must not alter payment destinations (fraud vector)"

blocks["erp_privileged_txn_blocked"] {
    contains(erp_tool, erp_priv_verbs[_])
}
reasons["erp_privileged_txn_blocked"] = "ERP: privileged transaction / authorization change blocked"

blocks["erp_sod_violation"] {
    contains(erp_tool, "approve")
    input.tool_params.created_by == input.tool_params.approver
}
reasons["erp_sod_violation"] = "ERP: segregation-of-duties — the same identity must not create a vendor AND approve its payment"

blocks["erp_mass_export_blocked"] {
    contains(erp_tool, erp_export_verbs[_])
    to_number(input.tool_params.count) > erp_export_threshold
}
reasons["erp_mass_export_blocked"] = "ERP: mass export over threshold blocked (minimum necessary)"
# >>> PACK-CONTRIB-END erp-crm

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
