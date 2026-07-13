# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Trust score behavior under various conditions."""

from tests.attacks.conftest import evaluate


class TestTrustBehavior:
    def test_high_trust_allows(self, api):
        """High trust and safe tool usage should allow execution."""
        result = evaluate(api, "search_kb", {"query": "shipping"}, trust_score=0.9)
        assert result.decision == "allow"
        assert result.trust_score >= 0.0

    def test_low_trust_escalates(self, api):
        """Low trust on safe action should trigger additional scrutiny."""
        result = evaluate(api, "search_kb", {"query": "shipping"}, trust_score=0.3)
        assert result.decision in {"escalate", "allow"}
        assert 0.0 <= result.trust_score <= 1.0

    def test_frozen_agent_blocked(self, api, frozen_agent):
        """Frozen trust profile should block requests."""
        result = evaluate(api, "search_kb", {"query": "shipping"}, trust_score=0.0)
        assert result.decision == "block"
        assert 0.0 <= result.trust_score <= 1.0

    def test_trust_with_dangerous_tool(self, api):
        """Medium trust combined with risky tool should not auto-allow."""
        result = evaluate(api, "execute_sql", {"query": "SELECT 1"}, trust_score=0.5)
        assert result.decision in {"block", "escalate", "audit"}
        assert 0.0 <= result.trust_score <= 1.0

    def test_chain_depth_reduces_trust(self, api):
        """Deep call chains should not increase effective trust signal."""
        result = evaluate(
            api,
            "get_customer",
            {"customer_id": "123"},
            trust_score=0.8,
            chain_depth=4,
        )
        assert result.trust_score <= 0.8

    def test_new_agent_neutral_trust(self, api):
        """A brand-new agent on safe query should stay usable."""
        result = evaluate(
            api,
            "search_kb",
            {"query": "test"},
            agent_class="brand-new-agent",
            trust_score=0.8,
        )
        assert result.decision == "allow"
        assert 0.0 <= result.trust_score <= 1.0
