# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Sector starter pack: ENERGY / UTILITIES (OT/IT segmentation) — the load-bearing control.
# Flagship risk (SECTOR-RECON): an injected/over-agentic LLM agent issues an operational CONTROL
# command at or near OT (SCADA/EMS/DMS), or writes to an OT-ADJACENT system (OMS/ADMS at L3.5).
#
# Posture = FAIL-SAFE on the OT surface (not a finite blocklist):
#   - explicit control verb in tool_name OR tool_params (incl. protocol writes: modbus write_register/
#     write_coil/force_coil, DNP3 direct_operate, 61850 operate) -> HARD BLOCK (ot_control_command_blocked)
#   - OT-adjacent OMS/ADMS write                                  -> ESCALATE (ot_adjacent_write_escalate)
#   - any OTHER OT-surface tool that is not a clear read          -> ESCALATE (ot_surface_review_escalate)
#     (so nothing on the OT surface ever silently allows)
#   - clear reads (get_/read_/..., *_status) and non-OT tools     -> allow
# Params are scanned in input.tool_params AND input.tool_params_normalized (homoglyph parity with
# comprehensive.rego). STARTER template — tune the verb/surface lists to your fleet's tool names.
#
# v0 (--v0-compatible) dialect to match the engine's OPA + comprehensive.rego. Composable: defines
# the shared partial rules blocks/escalates/audits/reasons; the shared RESOLVER below is identical
# across packs and is included once when multiple packs are combined into one (ns,__pack__) module.
package norviq.sector.energy

# >>> PACK-CONTRIB-BEGIN energy
energy_tool = lower(input.tool_name)

# Distinctive multi-token control verbs (low read false-positive; word-order variants included).
energy_control_verbs = [
    "open_breaker", "close_breaker", "breaker_open", "breaker_close", "trip_breaker", "breaker_trip", "breaker_control",
    "open_relay", "close_relay", "relay_open", "relay_close", "trip_relay", "relay_trip",
    "open_recloser", "close_recloser", "recloser_open", "recloser_close", "recloser_control",
    "set_setpoint", "write_setpoint", "setpoint_write", "adjust_setpoint", "change_setpoint",
    "write_register", "register_write", "write_coil", "coil_write", "force_coil", "write_holding", "preset_register",
    "direct_operate", "select_before_operate", "operate_device", "device_operate",
    "tap_change", "raise_tap", "lower_tap", "change_tap",
    "shed_load", "load_shed", "field_switching", "execute_switching", "apply_switching",
    "der_dispatch", "agc_dispatch", "dispatch_control",
    "open_valve", "close_valve", "start_pump", "stop_pump", "start_generator", "start_motor", "stop_motor", "start_turbine",
    "energize", "deenergize", "de_energize",
    "remote_open", "remote_close", "remote_trip", "remote_control", "send_control", "issue_control",
    "issue_command", "send_command", "control_command",
]

# OT protocol/system surface — nouns/prefixes that mean "this touches grid OT".
energy_ot_surface = [
    "scada", "ems_", "dms_", "adms", "oms_", "rtu", "ied_", "plc", "hmi_", "agc_",
    "modbus", "dnp3", "iec61850", "iec104", "iec_104", "opcua", "opc_ua", "goose",
    "breaker", "relay", "recloser", "sectionalizer", "switchgear", "substation", "feeder",
    "busbar", "setpoint", "tap_changer", "capacitor_bank", "transformer", "rtac",
]

energy_read_prefixes = ["get_", "read_", "list_", "query_", "fetch_", "describe_", "view_", "monitor_", "poll_", "report_"]

# control verb directly in the tool name
energy_control_in_name {
    contains(energy_tool, energy_control_verbs[_])
}

# control verb in any tool_params key or value (param-based protocol calls: modbus/dnp3/61850)
energy_control_in_params {
    some k
    v := input.tool_params[k]
    s := lower(sprintf("%v %v", [k, v]))
    contains(s, energy_control_verbs[_])
}
# homoglyph parity: the engine folds params to ASCII in tool_params_normalized
energy_control_in_params {
    some k
    v := input.tool_params_normalized[k]
    s := lower(sprintf("%v %v", [k, v]))
    contains(s, energy_control_verbs[_])
}

energy_on_ot_surface {
    contains(energy_tool, energy_ot_surface[_])
}

energy_is_read {
    startswith(energy_tool, energy_read_prefixes[_])
}
energy_is_read {
    endswith(energy_tool, "_status")
}
energy_is_read {
    endswith(energy_tool, "_read")
}

# OT-adjacent OMS/ADMS writes — one hop from control; human sign-off.
energy_ot_adjacent_verbs = [
    "oms_write", "adms_write", "create_switching_order", "update_outage", "restoration_step", "outage_assign",
]
energy_is_ot_adjacent {
    contains(energy_tool, energy_ot_adjacent_verbs[_])
}

# --- decisions ---
blocks["ot_control_command_blocked"] {
    energy_control_in_name
}
blocks["ot_control_command_blocked"] {
    energy_control_in_params
}
reasons["ot_control_command_blocked"] = "Energy: OT/control command blocked — agents must not actuate grid/control state (IT/OT segmentation; NERC CIP-005/007)"

escalates["ot_adjacent_write_escalate"] {
    energy_is_ot_adjacent
    not energy_control_in_name
    not energy_control_in_params
}
reasons["ot_adjacent_write_escalate"] = "Energy: OT-adjacent write requires human approval (OMS/ADMS is one hop from control)"

# Fail-safe catch-all: any OT-surface tool that is not a clear read and not already handled -> review.
escalates["ot_surface_review_escalate"] {
    energy_on_ot_surface
    not energy_is_read
    not energy_control_in_name
    not energy_control_in_params
    not energy_is_ot_adjacent
}
reasons["ot_surface_review_escalate"] = "Energy: OT-surface tool is not a recognized read — escalate for review (deny-by-default on the OT surface)"
# >>> PACK-CONTRIB-END energy

# >>> RESOLVER-BEGIN
# Shared decision resolver (block > escalate > audit > allow). Identical across all sector packs;
# the combiner includes exactly one copy. blocks/escalates/audits are partial SETS of rule_id;
# reasons is a partial OBJECT rule_id -> text. Each is unioned across combined packs.
default decision = "allow"
default rule_id = "default_allow"
default reason = "Allowed"

# Keep all four partial rules defined even when a pack uses only some of them (v0 safety).
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

# Deterministic single rule_id (sorted) so a complete-rule conflict can never occur when several
# triggers fire at once (e.g. two combined packs).
rule_id = sort([id | blocks[id]])[0] { block_fired }
rule_id = sort([id | escalates[id]])[0] { escalate_fired; not block_fired }
rule_id = sort([id | audits[id]])[0] { audit_fired; not block_fired; not escalate_fired }

reason = reasons[sort([id | blocks[id]])[0]] { block_fired }
reason = reasons[sort([id | escalates[id]])[0]] { escalate_fired; not block_fired }
reason = reasons[sort([id | audits[id]])[0]] { audit_fired; not block_fired; not escalate_fired }
# >>> RESOLVER-END
