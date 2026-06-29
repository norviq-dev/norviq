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
