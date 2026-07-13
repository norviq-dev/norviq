# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Cross-tenant and cross-namespace access violations."""

from tests.attacks.conftest import evaluate


class TestCrossTenant:
    def test_different_tenant_id_blocked(self, api):
        """Block access requests carrying a mismatched tenant identifier."""
        result = evaluate(
            api,
            "get_customer",
            {"customer_id": "123", "tenant_id": "other-tenant"},
            namespace="default",
        )
        assert result.decision == "block"
        assert 0.0 <= result.trust_score <= 1.0

    def test_different_namespace_blocked(self, api):
        """Block calls that try to pivot into another namespace."""
        result = evaluate(
            api,
            "get_customer",
            {"customer_id": "123", "namespace": "payments"},
            namespace="default",
        )
        assert result.decision == "block"
        assert 0.0 <= result.trust_score <= 1.0

    def test_same_tenant_allowed(self, api):
        """Allow customer lookup inside the caller tenant boundary."""
        result = evaluate(
            api,
            "get_customer",
            {"customer_id": "123", "tenant_id": "default"},
            namespace="default",
        )
        assert result.decision == "allow"
        assert 0.0 <= result.trust_score <= 1.0

    def test_no_tenant_field_allowed(self, api):
        """Allow lookup when no cross-tenant indicator is present."""
        result = evaluate(api, "get_customer", {"customer_id": "123"}, namespace="default")
        assert result.decision == "allow"
        assert 0.0 <= result.trust_score <= 1.0
