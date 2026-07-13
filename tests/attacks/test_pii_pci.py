# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""PII and PCI data protection tests."""

import pytest

from tests.attacks.conftest import evaluate


class TestPIIPCI:
    @pytest.mark.parametrize(
        ("tool_name", "tool_params"),
        [
            ("update_record", {"field": "ssn", "value": "123-45-6789"}),
            ("process_payment", {"card_number": "4111111111111111", "cvv": "123"}),
            ("update_record", {"field": "date_of_birth", "value": "1990-01-15"}),
            ("update_record", {"field": "passport", "value": "AB1234567"}),
            ("get_customer", {"cc_number": "4111111111111111"}),
        ],
    )
    def test_sensitive_identifiers_blocked(self, api, tool_name, tool_params):
        """Block direct handling of high-risk PII/PCI values in tool payloads."""
        result = evaluate(api, tool_name, tool_params)
        assert result.decision == "block"
        assert 0.0 <= result.trust_score <= 1.0
        assert isinstance(result.rule_id, str)

    @pytest.mark.parametrize(
        ("tool_name", "tool_params", "rule_id"),
        [
            # SSN embedded in a free-text body (not a dedicated ssn field) must still block.
            ("send_note", {"note": "Customer says their SSN is 123-45-6789, please update."}, "pii_detection"),
            # 16-digit card number in free text, separators present, Luhn-valid -> block.
            ("send_note", {"note": "Charge card 4111 1111 1111 1111 for the order."}, "pci_card_numbers"),
            # Contiguous Luhn-valid card embedded in prose -> block.
            ("send_note", {"note": "His card 4111111111111111 was declined."}, "pci_card_numbers"),
        ],
    )
    def test_free_text_pii_pci_blocked(self, api, tool_name, tool_params, rule_id):
        """Block PII/PCI that appears inside free-text fields, not just dedicated columns."""
        result = evaluate(api, tool_name, tool_params)
        assert result.decision == "block"
        assert result.rule_id == rule_id

    @pytest.mark.parametrize(
        ("tool_name", "tool_params"),
        [
            ("update_record", {"field": "email_preference", "value": "weekly"}),
            # Long numeric ids in free text that are NOT card numbers must NOT false-positive:
            ("send_note", {"note": "Invoice 123456789012345 is due next week."}),  # 15 digits
            ("send_note", {"note": "Order 1234567812345678 has shipped."}),  # 16 digits, fails Luhn
            ("send_note", {"note": "Please call us back on 555-123-4567 anytime."}),  # phone, not SSN
        ],
    )
    def test_safe_data_allowed(self, api, tool_name, tool_params):
        """Allow non-sensitive values and numeric ids that are not real PII/PCI (no false positives)."""
        result = evaluate(api, tool_name, tool_params)
        assert result.decision == "allow"
        assert 0.0 <= result.trust_score <= 1.0
