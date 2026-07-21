# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
#
# Parity tests for the shared horizontal PCI/PII rules: card-number (name + Luhn value, grouped and
# nested), SSN (field, free-text and nested), and benign allows — proving a sector namespace gets the
# same data-protection coverage as comprehensive.rego.
package norviq.sector.shared_test

import data.norviq.sector.shared

test_pci_field_name_blocked {
    shared.decision == "block" with input as {"tool_name": "x", "tool_params": {"card_number": "x"}}
    shared.rule_id == "pci_card_numbers" with input as {"tool_name": "x", "tool_params": {"card_number": "x"}}
}

test_pci_luhn_value_blocked {
    shared.decision == "block" with input as {"tool_name": "x", "tool_params": {"q": "4111111111111111"}}
}

test_pci_grouped_value_blocked {
    shared.decision == "block" with input as {"tool_name": "x", "tool_params": {"q": "4111 1111 1111 1111"}}
}

test_non_luhn_16_digits_allowed {
    shared.decision == "allow" with input as {"tool_name": "x", "tool_params": {"order_id": "1234567890123456"}}
}

test_pii_ssn_value_blocked {
    shared.decision == "block" with input as {"tool_name": "x", "tool_params": {"ssn": "123-45-6789"}}
    shared.rule_id == "pii_detection" with input as {"tool_name": "x", "tool_params": {"ssn": "123-45-6789"}}
}

test_pii_freetext_ssn_blocked {
    shared.decision == "block" with input as {"tool_name": "note", "tool_params": {"body": "his ssn is 123-45-6789 ok"}}
}

test_benign_allowed {
    shared.decision == "allow" with input as {"tool_name": "search_kb", "tool_params": {"q": "shipping status"}}
}

# Nested objects/arrays must be scanned identically to comprehensive.rego (parity).
test_nested_ssn_blocked {
    shared.decision == "block" with input as {"tool_name": "api_post", "tool_params": {"payload": {"ssn": "123-45-6789"}}}
    shared.rule_id == "pii_detection" with input as {"tool_name": "api_post", "tool_params": {"payload": {"ssn": "123-45-6789"}}}
}
test_nested_pan_value_blocked {
    shared.decision == "block" with input as {"tool_name": "api_post", "tool_params": {"payload": {"data": {"v": "4111111111111111"}}}}
}
test_nested_pan_field_blocked {
    shared.decision == "block" with input as {"tool_name": "api_post", "tool_params": {"body": {"card_number": "x"}}}
}
test_nested_in_array_blocked {
    shared.decision == "block" with input as {"tool_name": "api_post", "tool_params": {"items": [{"note": "ok"}, {"ssn": "123-45-6789"}]}}
}
test_nested_benign_allowed {
    shared.decision == "allow" with input as {"tool_name": "api_post", "tool_params": {"payload": {"note": "hello world", "qty": 3}}}
}
