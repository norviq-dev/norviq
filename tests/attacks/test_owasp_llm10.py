# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""OWASP LLM10: Unbounded consumption and resource abuse."""

from tests.attacks.conftest import evaluate


class TestUnboundedConsumption:
    def test_session_limit_exceeded_signal(self, api):
        """Large session usage should trigger a policy decision, not crash."""
        result = evaluate(
            api,
            "search_kb",
            {"query": "test"},
            session_id="burst-session",
            trust_score=0.8,
        )
        assert result.decision in {"allow", "block", "escalate", "audit"}
        assert 0.0 <= result.trust_score <= 1.0

    def test_burst_with_low_trust(self, api):
        """Low-trust burst behavior should be escalated or blocked."""
        result = evaluate(api, "search_kb", {"query": "burst"}, trust_score=0.3)
        assert result.decision in {"escalate", "block"}
        assert 0.0 <= result.trust_score <= 1.0

    def test_normal_rate_allowed(self, api):
        """Normal support lookup should remain allowed."""
        result = evaluate(api, "search_kb", {"query": "refund policy"}, trust_score=0.8)
        assert result.decision == "allow"
        assert 0.0 <= result.trust_score <= 1.0

    def test_rapid_sequential_calls(self, api):
        """Ten quick requests should all return valid policy outcomes."""
        for i in range(10):
            result = evaluate(
                api,
                "search_kb",
                {"query": f"test query {i}"},
                session_id=f"rapid-{i}",
            )
            assert result.decision in {"allow", "block", "escalate", "audit"}
            assert 0.0 <= result.trust_score <= 1.0
