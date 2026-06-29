# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Sector starter pack: GOVERNMENT / PUBLIC SECTOR.
# Flagship risk (SECTOR-RECON): rights-impacting agent decisions on millions (benefit deny/approve,
# adjudication) without human oversight; CUI/FTI (IRS Pub 1075) exfil. OMB M-25-21 high-impact AI;
# NIST 800-53 AC-3/AU-12/SI-4; AI RMF MANAGE.
#   - rights-impacting decision -> ESCALATE (rights_impacting_escalate)  [human-in-the-loop]
#   - CUI/FTI markings on egress -> BLOCK    (cui_fti_egress_blocked)
# STARTER: gov_cui_fields/markings are representative — align with your CUI registry / Pub 1075 scope.
package norviq.sector.government

# >>> PACK-CONTRIB-BEGIN government
gov_tool = lower(input.tool_name)
gov_rights_verbs = [
    "deny_benefit", "approve_benefit", "benefit.deny", "benefit.approve", "adjudicate",
    "deny_claim", "approve_claim", "issue_determination", "terminate_benefit",
]
gov_egress_verbs = ["export", "send", "email", "upload", "share", "transmit", "publish"]
gov_cui_fields = ["ssn", "social_security", "fti", "tax_return", "taxpayer_id", "cui", "1040"]

escalates["rights_impacting_escalate"] {
    contains(gov_tool, gov_rights_verbs[_])
}
reasons["rights_impacting_escalate"] = "Government: rights-impacting decision requires human review (OMB M-25-21; AI RMF)"

blocks["cui_fti_egress_blocked"] {
    contains(gov_tool, gov_egress_verbs[_])
    input.tool_params[k]
    contains(lower(k), gov_cui_fields[_])
}
blocks["cui_fti_egress_blocked"] {
    contains(gov_tool, gov_egress_verbs[_])
    v := input.tool_params[_]
    is_string(v)
    contains(lower(v), "cui//")
}
reasons["cui_fti_egress_blocked"] = "Government: CUI/FTI on an egress tool blocked (NIST 800-53 SI-4/AU-12; IRS Pub 1075)"
# >>> PACK-CONTRIB-END government

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
