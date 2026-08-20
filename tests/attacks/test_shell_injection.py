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
            ("search_kb", {"query": "$(cat /etc/shadow)"}),
        ],
    )
    def test_command_injection_blocked(self, api, tool_name, tool_params):
        """Block shell metacharacter and command-substitution payloads."""
        result = evaluate(api, tool_name, tool_params)
        assert result.decision == "block"
        assert 0.0 <= result.trust_score <= 1.0

    def test_a_quoted_command_in_prose_is_not_a_command(self, api):
        """A `backtick` in a search query is markdown, not a shell.

        This case used to sit in the list above and assert `block`. It was a false positive, and
        `deny_shell_execution` was deliberately narrowed to stop it — webhook/presets/strict.rego:210-222
        records the measurement: the bare metacharacters fired on 2 of 28 legitimate calls in the benign
        corpus, "a support note saying 'the pipe | in their filename breaks it', and a runbook quoting
        `kubectl get pods`". Prose about shells contains shell characters, and at `deny` that blocks the
        support ticket.

        So `|`, `;` and the backtick moved to a name-gated arm — they count only where a command could
        actually be run — while the unambiguous indicators (`rm -rf`, `/etc/passwd`, `/etc/shadow`,
        `$(`) stayed universal.

        Asserted as a PAIR, which is the point. Dropping the stale case alone would leave nothing
        stopping the narrowing from widening into a blanket exemption for read tools; the second half
        pins that `$(` still blocks on the very same tool. Verified against the shipped strict preset:
        the quoted form returns allow/default_allow and the substitution form block/deny_shell_execution.
        """
        quoted = evaluate(api, "search_kb", {"query": "result is `whoami`"})
        assert quoted.decision != "block", (
            f"a knowledge-base search quoting a command was blocked as shell execution: "
            f"{quoted.decision}/{quoted.rule_id}"
        )

        # CONTROL, on the same read tool: the narrowing must not have exempted it wholesale.
        substituted = evaluate(api, "search_kb", {"query": "$(cat /etc/shadow)"})
        assert substituted.decision == "block", (
            f"command substitution is unambiguous on any tool and must still block, got "
            f"{substituted.decision}/{substituted.rule_id}"
        )
