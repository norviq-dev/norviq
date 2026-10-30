# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""The chatbot scenario's BACKLOG 7.10 check, judged against what the call actually came back with.

The scenario runs on a live kind cluster, so its checks are only ever read off a cluster run — and a
check that passes on a call the policy never saw reports green for something nobody observed (the
7.11 shape). These drive `run()` with the MCP transport stubbed, so each check sees exactly the
(isError, text, rule_id) a real call would hand it.
"""

from __future__ import annotations

import asyncio

import pytest

from norviq.mcp.adversarial import chatbot_scenario as scenario

_CLAIM = "the read-only query tool is not refused as destructive by its name"
_SELECT = {"sql": "select * from customers where id = 8812"}


def _run_with(monkeypatch: pytest.MonkeyPatch, support_select: tuple[bool, str, str]) -> scenario.Check:
    """Run the scenario with every call allowed except the support agent's select, which returns
    `support_select` as (isError, text, rule_id)."""

    async def fake_call(server, agent_class, tool, args, call_log, rugpull="", token=None):
        if agent_class == "support-agent" and tool == "run_query" and args == _SELECT:
            err, text, rule = support_select
            if not err:
                with open(call_log, "a", encoding="utf-8") as fh:
                    fh.write('{"server": "postgres", "tool": "run_query"}\n')
            return err, text, rule, [tool]
        return False, "ok", "", [tool]

    monkeypatch.setattr(scenario, "_call", fake_call)
    checks = asyncio.run(scenario.run("http://unused.invalid", ""))
    (check,) = [c for c in checks if c.claim == _CLAIM]
    return check


def test_an_allowed_select_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _run_with(monkeypatch, (False, "id=8812", "")).passed is True


def test_a_refusal_by_the_destructive_verb_rule_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    check = _run_with(monkeypatch, (True, "blocked", "support_no_destructive_verb"))
    assert (check.passed, check.observed) == (False, "REFUSED AS DESTRUCTIVE")


def test_a_refusal_with_no_rule_is_not_evidence_either_way(monkeypatch: pytest.MonkeyPatch) -> None:
    """A transport failure, a 403 or an engine fault comes back as an error with no rule_id. The first
    cut of this check was `rule != "support_no_destructive_verb"`, which is true of an empty rule — so
    it passed a call the policy never decided."""
    check = _run_with(monkeypatch, (True, "connection reset", ""))
    assert check.passed is False
    assert check.observed.startswith("NOT EVALUATED")


def test_a_refusal_by_another_rule_passes_this_claim_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """The claim is about the name classifier. Another rule refusing the call is that rule's finding,
    and the next check ("tier-2 support CAN query") is the one that fails on it."""
    check = _run_with(monkeypatch, (True, "blocked", "support_no_sensitive_path"))
    assert check.passed is True
    assert "support_no_sensitive_path" in check.observed
