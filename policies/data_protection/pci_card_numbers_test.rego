# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
package norviq.data_protection.pci_card_numbers_test

import rego.v1
import data.norviq.data_protection.pci_card_numbers

test_blocks_card_field_name if {
    result := pci_card_numbers.decision with input as {
        "tool_name": "store_payment",
        "tool_params": {"card_number": "4111111111111111", "name": "A"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-a",
        "trust_score": 0.8,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_blocks_card_number_pattern if {
    result := pci_card_numbers.decision with input as {
        "tool_name": "store_payment",
        "tool_params": {"note": "4111111111111111"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-b",
        "trust_score": 0.8,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    result == "block"
}

test_allows_non_pci_payload if {
    trigger_input := {
        "tool_name": "store_payment",
        "tool_params": {"invoice_id": "INV-123", "amount": "42"},
        "agent_identity": {"spiffe_id": "spiffe://test", "namespace": "default", "agent_class": "test"},
        "session_id": "sess-c",
        "trust_score": 0.8,
        "call_count": 1,
        "timestamp": "2026-05-30T22:34:00Z"
    }
    pci_card_numbers.decision with input as trigger_input == "allow"
    pci_card_numbers.rule_id with input as trigger_input == "default_allow"
}
