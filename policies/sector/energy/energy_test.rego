# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.sector.energy_test

import data.norviq.sector.energy

# --- direct control verbs (block) ---
test_ot_control_open_breaker_blocked {
    energy.decision == "block" with input as {"tool_name": "open_breaker", "tool_params": {"line": "L1"}}
    energy.rule_id == "ot_control_command_blocked" with input as {"tool_name": "open_breaker", "tool_params": {}}
}

test_ot_control_set_setpoint_blocked {
    energy.decision == "block" with input as {"tool_name": "set_setpoint", "tool_params": {"value": "60Hz"}}
}

# --- word-order / device-class variants the flat list used to miss (block) ---
test_breaker_open_word_order_blocked {
    energy.decision == "block" with input as {"tool_name": "breaker_open", "tool_params": {}}
}

test_recloser_open_blocked {
    energy.decision == "block" with input as {"tool_name": "recloser_open", "tool_params": {}}
}

test_register_write_word_order_blocked {
    energy.decision == "block" with input as {"tool_name": "register_write", "tool_params": {}}
}

test_close_valve_blocked {
    energy.decision == "block" with input as {"tool_name": "close_valve", "tool_params": {}}
}

test_start_pump_blocked {
    energy.decision == "block" with input as {"tool_name": "start_pump", "tool_params": {}}
}

# --- param-based protocol control: the load-bearing case (C1) ---
test_modbus_write_register_param_blocked {
    energy.decision == "block" with input as {"tool_name": "modbus", "tool_params": {"function": "write_register", "address": 40001, "value": 1}}
    energy.rule_id == "ot_control_command_blocked" with input as {"tool_name": "modbus", "tool_params": {"function": "write_register"}}
}

test_dnp3_direct_operate_param_blocked {
    energy.decision == "block" with input as {"tool_name": "dnp3", "tool_params": {"operation": "direct_operate", "control_code": "LATCH_ON"}}
}

test_generic_gateway_with_control_in_params_blocked {
    energy.decision == "block" with input as {"tool_name": "historian_bridge", "tool_params": {"cmd": "open_breaker", "point": "BRKR_52"}}
}

# --- OT-surface, not a clear read, no explicit verb -> escalate (fail-safe, never silent allow) ---
test_ot_surface_ambiguous_escalates {
    energy.decision == "escalate" with input as {"tool_name": "rtu_session", "tool_params": {}}
    energy.rule_id == "ot_surface_review_escalate" with input as {"tool_name": "rtu_session", "tool_params": {}}
}

test_bare_modbus_call_escalates {
    energy.decision == "escalate" with input as {"tool_name": "modbus_client", "tool_params": {"unit": 1}}
}

# --- OT-adjacent OMS/ADMS write -> escalate ---
test_ot_adjacent_write_escalates {
    energy.decision == "escalate" with input as {"tool_name": "oms_write_outage", "tool_params": {}}
    energy.rule_id == "ot_adjacent_write_escalate" with input as {"tool_name": "oms_write_outage", "tool_params": {}}
}

# --- reads on the OT surface -> allow (not over-blocked) ---
test_breaker_status_read_allowed {
    energy.decision == "allow" with input as {"tool_name": "get_breaker_status", "tool_params": {"id": "B1"}}
}

test_register_read_allowed {
    energy.decision == "allow" with input as {"tool_name": "read_register", "tool_params": {"address": 30001}}
}

test_it_read_allowed {
    energy.decision == "allow" with input as {"tool_name": "get_meter_reading", "tool_params": {"meter": "m1"}}
}

# --- benign non-OT -> allow ---
test_benign_search_not_falsely_blocked {
    energy.decision == "allow" with input as {"tool_name": "search_kb", "tool_params": {"query": "breaker maintenance schedule"}}
}

# === F-09 / F-16 regression: noun-first OT names, homoglyph name, set_voltage, decomposed params ===

# noun-first control names that used to ALLOW must now NOT allow (block or escalate)
test_valve_close_not_allowed {
    energy.decision != "allow" with input as {"tool_name": "valve_close", "tool_params": {}}
}
test_valve_open_not_allowed {
    energy.decision != "allow" with input as {"tool_name": "valve_open", "tool_params": {}}
}
test_pump_start_not_allowed {
    energy.decision != "allow" with input as {"tool_name": "pump_start", "tool_params": {}}
}
test_pump_stop_not_allowed {
    energy.decision != "allow" with input as {"tool_name": "pump_stop", "tool_params": {}}
}
test_gate_close_not_allowed {
    energy.decision != "allow" with input as {"tool_name": "gate_close", "tool_params": {}}
}
test_switch_open_not_allowed {
    energy.decision != "allow" with input as {"tool_name": "switch_open", "tool_params": {}}
}
# these are recognized control verbs -> hard block specifically
test_valve_close_blocked {
    energy.decision == "block" with input as {"tool_name": "valve_close", "tool_params": {}}
    energy.rule_id == "ot_control_command_blocked" with input as {"tool_name": "valve_close", "tool_params": {}}
}

# F-09 homoglyph on the tool NAME (Cyrillic г folds to ASCII via tool_name_normalized) -> block
test_homoglyph_open_breaker_blocked {
    energy.decision == "block" with input as {"tool_name": "open_bгeaker", "tool_name_normalized": "open_breaker", "tool_params": {}}
}

# F-16 additional SCADA control verbs -> block
test_set_voltage_blocked {
    energy.decision == "block" with input as {"tool_name": "set_voltage", "tool_params": {"bus": "B1", "kv": 13.8}}
}
test_configure_protection_blocked {
    energy.decision == "block" with input as {"tool_name": "configure_protection", "tool_params": {"relay": "R1"}}
}

# F-16 decomposed param phrasing: verb in one field + device noun in another -> block
test_decomposed_open_breaker_blocked {
    energy.decision == "block" with input as {"tool_name": "device_command", "tool_params": {"verb": "open", "device_type": "breaker"}}
    energy.rule_id == "ot_control_command_blocked" with input as {"tool_name": "device_command", "tool_params": {"verb": "open", "device_type": "breaker"}}
}

# decomposed detection must be ACTION/DEVICE-key-scoped: a benign non-control tool whose params merely
# contain the word "open" in a status field + a device noun in a description must NOT false-block.
test_decomposed_benign_status_not_blocked {
    energy.decision == "allow" with input as {"tool_name": "update_ticket", "tool_params": {"state": "open", "asset": "transformer-7 inspection"}}
}

# benign device reads on the new noun roots -> still allow (not over-blocked)
test_valve_status_read_allowed {
    energy.decision == "allow" with input as {"tool_name": "get_valve_status", "tool_params": {"id": "V1"}}
}
test_pump_read_allowed {
    energy.decision == "allow" with input as {"tool_name": "read_pump_metrics", "tool_params": {"id": "P1"}}
}
