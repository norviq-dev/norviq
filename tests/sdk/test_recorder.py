# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Context-local decision recorder: capture a block even when a framework swallows the raised error.

Hermetic — a fake evaluator returns canned decisions keyed by tool name, so no Redis/OPA is needed.
The interceptor records every evaluated call on the active ``capture_decisions()`` scope; a host reads
``rec.last_denial`` / ``rec.tools_called`` afterwards. The important property is that this survives the
async/thread boundaries the adapters cross — proven directly against the real ``_run_sync`` sync-bridge
(the CrewAI path) rather than mocked.
"""

from __future__ import annotations

import asyncio

from norviq.exceptions import NorviqBlockError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sdk.core.recorder import capture_decisions, record_decision
from norviq.sdk.core.wrapping import _run_sync

_DECISIONS = {
    "search_kb": "allow",
    "read_only": "audit",
    "execute_sql": "block",
    "delete_record": "block",
    "sensitive_tool": "escalate",
}


class _FakeEvaluator:
    """Returns a canned decision keyed by tool name (satisfies SupportsEvaluate)."""

    async def evaluate(self, event) -> PolicyDecision:  # noqa: ANN001 - ToolCallEvent, structural typing
        verdict = _DECISIONS.get(event.tool_name, "allow")
        return PolicyDecision(
            decision=verdict,  # type: ignore[arg-type]
            rule_id=f"rule_{verdict}",
            reason=f"{event.tool_name} -> {verdict}",
        )


def _identity() -> AgentIdentity:
    return AgentIdentity(spiffe_id="spiffe://norviq/ns/default/sa/agent", namespace="default")


def _interceptor() -> ToolInterceptor:
    return ToolInterceptor(evaluator=_FakeEvaluator())


async def test_capture_records_every_call_in_order() -> None:
    """tools_called reflects every evaluated call, allow + audit + deny, in call order."""
    itc = _interceptor()
    with capture_decisions() as rec:
        await itc.intercept("search_kb", {"q": "hi"}, identity=_identity())
        await itc.intercept("read_only", {}, identity=_identity())
        await itc.intercept("execute_sql", {"query": "DROP"}, identity=_identity())
    assert rec.tools_called == ["search_kb", "read_only", "execute_sql"]


async def test_last_denial_returns_most_recent_block_or_escalate() -> None:
    """last_denial is the most recent refusal; an allow after it does not clear it."""
    itc = _interceptor()
    with capture_decisions() as rec:
        await itc.intercept("execute_sql", {"query": "DROP"}, identity=_identity())  # block
        await itc.intercept("sensitive_tool", {}, identity=_identity())  # escalate (more recent)
        await itc.intercept("search_kb", {}, identity=_identity())  # allow (does not clear)
    assert rec.last_denial is not None
    assert rec.last_denial.decision == "escalate"
    assert rec.last_denial.rule_id == "rule_escalate"


async def test_no_denial_when_all_allowed() -> None:
    """last_denial is None when nothing was refused."""
    itc = _interceptor()
    with capture_decisions() as rec:
        await itc.intercept("search_kb", {}, identity=_identity())
        await itc.intercept("read_only", {}, identity=_identity())
    assert rec.last_denial is None
    assert rec.tools_called == ["search_kb", "read_only"]


async def test_record_decision_is_a_noop_outside_capture() -> None:
    """Outside a capture scope, recording is a silent no-op — interception still works normally."""
    itc = _interceptor()
    # bare record_decision must not raise when nothing is installed
    record_decision("execute_sql", PolicyDecision(decision="block"))
    decision = await itc.intercept("execute_sql", {"query": "DROP"}, identity=_identity())
    assert decision.decision == "block"  # enforcement unaffected by the absence of a recorder


async def test_concurrent_captures_are_isolated() -> None:
    """Two capture scopes running concurrently must not see each other's decisions."""
    itc = _interceptor()

    async def run(tool: str) -> list[str]:
        with capture_decisions() as rec:
            await itc.intercept(tool, {"q": "x"}, identity=_identity())
            await asyncio.sleep(0)  # yield so the two scopes interleave
            await itc.intercept(tool, {"q": "y"}, identity=_identity())
            return rec.tools_called

    a, b = await asyncio.gather(run("search_kb"), run("read_only"))
    assert a == ["search_kb", "search_kb"]
    assert b == ["read_only", "read_only"]


async def test_records_across_sync_bridge_even_when_framework_swallows() -> None:
    """The CrewAI path: a block raised on the sync-bridge loop, inside asyncio.to_thread, and then
    SWALLOWED by the (emulated) framework, is still visible on the parent recorder.

    This exercises the real boundary chain — to_thread -> _run_sync (run_coroutine_threadsafe on the
    shared background loop) -> intercept -> record_decision — proving the mutable-recorder-in-a-
    ContextVar propagates all the way through and back."""
    itc = _interceptor()

    def framework_tool_call() -> str:
        # Emulates CrewAI's sync wrapper: run intercept_or_raise on the bg loop, then swallow the block
        # the way CrewAI's agent loop treats it as a recoverable tool error.
        try:
            _run_sync(
                itc.intercept_or_raise(
                    "delete_record", {"id": 1}, session_id="s", framework="crewai", identity=_identity()
                )
            )
        except NorviqBlockError:
            return "the model apologizes and moves on"
        return "ran"

    with capture_decisions() as rec:
        reply = await asyncio.to_thread(framework_tool_call)

    assert reply == "the model apologizes and moves on"  # the framework swallowed the raise...
    assert rec.last_denial is not None  # ...but the recorder still captured the decision
    assert rec.last_denial.decision == "block"
    assert rec.last_denial.rule_id == "rule_block"
    assert rec.tools_called == ["delete_record"]
