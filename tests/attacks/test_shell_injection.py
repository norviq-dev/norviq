# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Shell and command injection attacks."""

import pytest

from tests.attacks.conftest import evaluate


class TestShellInjection:
    @pytest.mark.parametrize(
        ("tool_name", "tool_params"),
        [
            ("exec_shell", {"command": "ls | cat /etc/passwd"}),
            ("read_file", {"path": "/tmp/safe; rm -rf /"}),
            ("search_kb", {"query": "result is `whoami`"}),
            ("search_kb", {"query": "$(cat /etc/shadow)"}),
        ],
    )
    def test_command_injection_blocked(self, api, tool_name, tool_params):
        """Block shell metacharacter and command-substitution payloads."""
        result = evaluate(api, tool_name, tool_params)
        assert result.decision == "block"
        assert 0.0 <= result.trust_score <= 1.0
