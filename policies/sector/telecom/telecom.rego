# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Sector starter pack: TELECOMMUNICATIONS.
# Flagship risk (SECTOR-RECON): injection -> unauthorized SIM-swap / number-port (account takeover,
# 2FA bypass) or bulk CPNI/location exfil. CPNI 47 CFR §64.2010(h) requires secure auth BEFORE a
# SIM change; 47 USC §222 location.
#   - SIM-swap / port without a strong-auth flag -> ESCALATE (sim_swap_escalate)
#   - bulk CPNI / location read over threshold    -> BLOCK    (cpni_bulk_blocked)
# STARTER: pass tool_params.strong_auth=true once your auth-before-action check (§64.2010(h)) has
# run. Tune verbs / tel_bulk_threshold below.
package norviq.sector.telecom

# >>> PACK-CONTRIB-BEGIN telecom
tel_tool = lower(input.tool_name)
tel_simswap_verbs = ["sim_swap", "swap_sim", "port_number", "number_port", "provision_sim", "esim_transfer", "activate_sim"]
tel_cpni_read_verbs = ["get_cpni", "list_call_records", "query_location", "get_location", "export_cpni", "call_detail_records"]
tel_bulk_threshold = 50

tel_strong_auth {
    input.tool_params.strong_auth == true
}

escalates["sim_swap_escalate"] {
    contains(tel_tool, tel_simswap_verbs[_])
    not tel_strong_auth
}
reasons["sim_swap_escalate"] = "Telecom: SIM-swap/number-port without verified strong auth — hold (CPNI §64.2010(h))"

blocks["cpni_bulk_blocked"] {
    contains(tel_tool, tel_cpni_read_verbs[_])
    to_number(input.tool_params.limit) > tel_bulk_threshold
}
reasons["cpni_bulk_blocked"] = "Telecom: bulk CPNI/location read blocked (47 USC §222; §64.2011)"
# >>> PACK-CONTRIB-END telecom

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
