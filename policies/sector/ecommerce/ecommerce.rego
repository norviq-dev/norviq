# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Sector starter pack: E-COMMERCE / RETAIL.
# Flagship risk: an agent issues large/mass refunds, manipulates pricing (price->0, unlimited coupon),
# bulk-exports customer PII/order history, takes over accounts, or leaks card data.
#   - refund/payment over a configurable threshold -> ESCALATE (ecom_refund_over_threshold_escalate)
#   - mass refunds over a threshold                -> BLOCK    (ecom_mass_refund_blocked)
#   - price/discount manipulation (price->0, 100%+ / unlimited coupon) -> BLOCK (ecom_price_manipulation_blocked)
#   - bulk customer PII / order-history export     -> BLOCK    (ecom_bulk_pii_export_blocked)
#   - account-takeover action                      -> ESCALATE (ecom_account_takeover_escalate)
# Composes canonical PCI + PII (requires: pci, pii). STARTER — tune verbs/thresholds. v0 (--v0-compatible).
package norviq.sector.ecommerce

# >>> PACK-CONTRIB-BEGIN ecommerce
ecom_tool = lower(input.tool_name)
ecom_refund_verbs = ["refund", "issue_refund", "process_refund", "reverse_payment", "chargeback"]
ecom_price_verbs = ["set_price", "update_price", "change_price"]
ecom_promo_verbs = ["coupon", "discount", "promo"]
ecom_export_verbs = ["export", "download", "extract", "bulk_export"]
ecom_ato_verbs = ["disable_2fa", "disable_mfa", "change_email", "change_recovery", "reset_password_admin", "change_phone"]
ecom_refund_threshold = 1000
ecom_mass_threshold = 50
ecom_export_threshold = 100

escalates["ecom_refund_over_threshold_escalate"] {
    contains(ecom_tool, ecom_refund_verbs[_])
    to_number(input.tool_params.amount) > ecom_refund_threshold
}
reasons["ecom_refund_over_threshold_escalate"] = "E-commerce: refund/payment over threshold requires approval"

blocks["ecom_mass_refund_blocked"] {
    contains(ecom_tool, ecom_refund_verbs[_])
    to_number(input.tool_params.count) > ecom_mass_threshold
}
reasons["ecom_mass_refund_blocked"] = "E-commerce: mass refunds over threshold blocked"

blocks["ecom_price_manipulation_blocked"] {
    contains(ecom_tool, ecom_price_verbs[_])
    to_number(input.tool_params.price) == 0
}
blocks["ecom_price_manipulation_blocked"] {
    contains(ecom_tool, ecom_promo_verbs[_])
    to_number(input.tool_params.percent) >= 100
}
blocks["ecom_price_manipulation_blocked"] {
    contains(ecom_tool, ecom_promo_verbs[_])
    input.tool_params.unlimited == true
}
reasons["ecom_price_manipulation_blocked"] = "E-commerce: price/discount manipulation blocked (price->0 / 100%+ / unlimited coupon)"

blocks["ecom_bulk_pii_export_blocked"] {
    contains(ecom_tool, ecom_export_verbs[_])
    to_number(input.tool_params.count) > ecom_export_threshold
}
reasons["ecom_bulk_pii_export_blocked"] = "E-commerce: bulk customer PII / order-history export over threshold blocked"

escalates["ecom_account_takeover_escalate"] {
    contains(ecom_tool, ecom_ato_verbs[_])
}
reasons["ecom_account_takeover_escalate"] = "E-commerce: account-takeover action (2FA/email/recovery change) requires verification"
# >>> PACK-CONTRIB-END ecommerce

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
