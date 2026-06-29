# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Sector starter pack: FINANCIAL SERVICES.
# Flagship risk (SECTOR-RECON): injection -> unauthorized wire/transfer on irreversible rails
# (FedNow/RTP/Fedwire/SWIFT); weak segregation of duties. SOX §404 / PCI Req.7-8-10 / GLBA / SR 11-7.
#   - money movement over threshold        -> ESCALATE (wire_over_threshold_escalate)
#   - transfer to a new/unverified payee   -> ESCALATE (new_beneficiary_escalate)
#   - same principal initiates AND approves-> BLOCK    (sod_violation)
# Reuse pci_card_numbers for cardholder data. Tune fin_money_verbs / fin_threshold below.
# STARTER template: fin_threshold + the SoD heuristic (in-params initiator==approver) are starting
# points — true SoD needs workflow state from your approval system.
package norviq.sector.finance

# >>> PACK-CONTRIB-BEGIN finance
fin_tool = lower(input.tool_name)
fin_money_verbs = [
    "wire_transfer", "ach_transfer", "payment", "fedwire", "fednow", "rtp_transfer",
    "swift_transfer", "send_payment", "initiate_transfer", "move_funds",
]
fin_threshold = 10000

fin_is_money_move {
    contains(fin_tool, fin_money_verbs[_])
}

escalates["wire_over_threshold_escalate"] {
    fin_is_money_move
    to_number(input.tool_params.amount) > fin_threshold
}
reasons["wire_over_threshold_escalate"] = "Finance: money movement over threshold requires human approval (SOX §404 / SR 11-7)"

escalates["new_beneficiary_escalate"] {
    fin_is_money_move
    input.tool_params.beneficiary_known == false
}
reasons["new_beneficiary_escalate"] = "Finance: transfer to a new/unverified beneficiary — hold for review"

blocks["sod_violation"] {
    contains(fin_tool, "approve")
    input.tool_params.initiator == input.tool_params.approver
}
reasons["sod_violation"] = "Finance: segregation-of-duties — the same identity must not initiate AND approve"
# >>> PACK-CONTRIB-END finance

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
