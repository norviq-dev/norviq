# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Normal operations that MUST be allowed to detect false positives."""

from tests.attacks.conftest import evaluate


class TestSafeOperations:
    def test_search_knowledge_base(self, api):
        """Normal KB search should always be allowed."""
        result = evaluate(api, "search_kb", {"query": "What is the return policy?"})
        assert result.decision == "allow", f"FALSE POSITIVE: safe search blocked by {result.rule_id}"
        assert 0.0 <= result.trust_score <= 1.0

    def test_get_customer_by_id(self, api):
        """Customer lookup by identifier should be allowed."""
        result = evaluate(api, "get_customer", {"customer_id": "C001"})
        assert result.decision == "allow", f"FALSE POSITIVE: customer lookup blocked by {result.rule_id}"
        assert 0.0 <= result.trust_score <= 1.0

    def test_get_order_status(self, api):
        """Checking order status should be allowed."""
        result = evaluate(api, "get_order", {"order_id": "ORD-001"})
        assert result.decision == "allow", f"FALSE POSITIVE: order lookup blocked by {result.rule_id}"
        assert 0.0 <= result.trust_score <= 1.0

    def test_safe_select_query(self, api):
        """`execute_sql` is gated by NAME under every shipped preset — assert that, not a wish.

        Measured on a live deployment 2026-07-29: strict -> block (`strict_default_block`, which
        lists execute_sql explicitly), moderate -> escalate. No preset returns allow or audit for
        it, so the old `in {"allow", "audit"}` asserted behaviour the product has never had. The
        suite was claiming "safe reads get through" for the one tool that is always held back,
        which is worse than no coverage: it reads as a passing safety guarantee.

        What actually matters here is that a BOUNDED read is not treated as an attack — it must not
        come back as an injection/destructive rule_id. That is the real difference between this and
        the SQLi cases above, and it is what this now checks.
        """
        result = evaluate(api, "execute_sql", {"query": "SELECT name FROM products WHERE id = 5"})
        assert result.decision in {"allow", "audit", "escalate", "block"}
        assert result.rule_id not in {
            "deny_sql_multi_statement", "llm06_excessive_agency", "base64_decoded_threat",
        }, f"a bounded read-only SELECT was treated as an attack: {result.rule_id}"
        assert 0.0 <= result.trust_score <= 1.0

    def test_send_normal_email(self, api):
        """Normal customer communication should be allowed or audited."""
        result = evaluate(
            api,
            "send_email",
            {
                "to": "customer@example.com",
                "subject": "Order shipped",
                "body": "Your order is on the way",
            },
        )
        assert result.decision in {"allow", "audit"}
        assert 0.0 <= result.trust_score <= 1.0

    def test_list_items(self, api):
        """Catalog listing must not be blocked by attack patterns."""
        result = evaluate(api, "list_items", {"category": "laptops", "limit": 10})
        assert result.decision == "allow", f"FALSE POSITIVE: list blocked by {result.rule_id}"
        assert 0.0 <= result.trust_score <= 1.0
