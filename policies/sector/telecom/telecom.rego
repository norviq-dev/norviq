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

# F-17: CPNI exfil via a RENAMED export tool — the bulk rule keys on known read tool NAMES, so
# `export_customer_data {call_records:true, location:true, destination:"s3://external"}` slips through.
# Detect the exfil SEMANTICS: CPNI-typed data in params heading to an egress tool / external destination,
# or a CPNI-named tool pointed at an external destination. Param keys + destinations matched, not just names.
tel_cpni_param_keys = {"cpni", "call_records", "call_detail_records", "cdr", "location", "geolocation", "subscriber_data", "imsi", "imei", "msisdn", "sim", "billing_records", "phone_records", "tower_data", "call_history", "location_history"}
tel_cpni_keywords = ["cpni", "call_record", "call_detail", "cdr", "location", "subscriber", "imsi", "imei", "msisdn", "billing_record", "phone_record", "geolocation"]
tel_egress_name_verbs = ["export", "send", "upload", "transfer", "sync", "push", "email", "post", "sftp", "ftp", "backup", "share", "dump", "extract", "forward", "publish"]
tel_dest_keys = {"destination", "dest", "target", "url", "endpoint", "bucket", "recipient", "to", "sink", "upload_url", "callback", "webhook"}

tel_cpni_in_params {
    some k
    tel_cpni_param_keys[lower(k)]
    input.tool_params[k]
}
tel_is_egress_tool {
    contains(tel_tool, tel_egress_name_verbs[_])
}
tel_external_destination {
    some k
    tel_dest_keys[lower(k)]
    v := input.tool_params[k]
    is_string(v)
    tel_external_pattern(lower(v))
}
tel_external_pattern(v) { startswith(v, "s3://") }
tel_external_pattern(v) { startswith(v, "http://") }
tel_external_pattern(v) { startswith(v, "https://") }
tel_external_pattern(v) { startswith(v, "ftp://") }
tel_external_pattern(v) { startswith(v, "sftp://") }
tel_external_pattern(v) { startswith(v, "gs://") }
tel_external_pattern(v) { startswith(v, "azure://") }
tel_external_pattern(v) { contains(v, "external") }
tel_external_pattern(v) { contains(v, "@") }

tel_cpni_in_scope {
    tel_cpni_in_params
}
tel_cpni_in_scope {
    contains(tel_tool, tel_cpni_keywords[_])
}

# CPNI/location data + an EXTERNAL destination = exfil -> BLOCK
blocks["cpni_exfil_blocked"] {
    tel_cpni_in_scope
    tel_external_destination
}
reasons["cpni_exfil_blocked"] = "Telecom: CPNI/location data routed to an external destination — blocked (47 USC §222; §64.2011)"

# CPNI in params routed through an egress tool without a clear external destination = review -> ESCALATE
escalates["cpni_egress_review_escalate"] {
    tel_cpni_in_params
    tel_is_egress_tool
    not tel_external_destination
}
reasons["cpni_egress_review_escalate"] = "Telecom: CPNI/location routed through an export/egress tool — hold for review (47 USC §222)"
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
