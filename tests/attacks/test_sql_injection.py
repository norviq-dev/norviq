# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""SQL injection attacks via tool parameters."""

import pytest

from tests.attacks.conftest import evaluate


class TestSQLInjection:
    @pytest.mark.parametrize(
        "query",
        [
            "SELECT * FROM users; DROP TABLE users; --",
            "SELECT name FROM products UNION SELECT password FROM admin",
            "SELECT * FROM users WHERE id='1' OR '1'='1'",
            "DELETE FROM customers WHERE 1=1",
            "EXEC xp_cmdshell 'net user hacker pass /add'",
        ],
    )
    def test_sql_injection_blocked(self, api, query):
        """Block classic SQLi payloads including stacked and auth bypass forms."""
        result = evaluate(api, "execute_sql", {"query": query})
        assert result.decision == "block"
        assert 0.0 <= result.trust_score <= 1.0

    def test_safe_select_allowed(self, api):
        """Allow or audit a bounded, read-only query."""
        result = evaluate(api, "execute_sql", {"query": "SELECT name, email FROM customers WHERE id = 5"})
        assert result.decision in {"allow", "audit"}
        assert 0.0 <= result.trust_score <= 1.0
