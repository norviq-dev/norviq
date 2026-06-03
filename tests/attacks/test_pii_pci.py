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

    def test_safe_data_allowed(self, api):
        """Allow non-sensitive preference updates."""
        result = evaluate(api, "update_record", {"field": "email_preference", "value": "weekly"})
        assert result.decision == "allow"
        assert 0.0 <= result.trust_score <= 1.0
