# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Framework-agnostic tool-call interceptor."""

from typing import Any, Protocol

import structlog

from norviq.engine.identity import SPIFFEResolver
from norviq.exceptions import NorviqBlockError, NorviqEscalateError
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.sdk.core.recorder import record_decision

log = structlog.get_logger()


class SupportsEvaluate(Protocol):
    """Structural type for anything ToolInterceptor can delegate evaluation to.

    Both the in-cluster `norviq.engine.evaluator.OPAEvaluator` and the out-of-cluster
    `norviq.sdk.client.engine.PolicyEngineClient` satisfy this protocol, so either can be
    passed to `ToolInterceptor` without a shared base class.
    """

    async def evaluate(self, event: ToolCallEvent) -> PolicyDecision:
        """Evaluate a tool call event and return a policy decision."""
        ...


class ToolInterceptor:
    """Generic tool call interceptor for policy evaluation."""

    def __init__(self, evaluator: SupportsEvaluate, resolver: SPIFFEResolver | None = None) -> None:
        """Store evaluator and identity resolver."""
        self._evaluator = evaluator
        self._resolver = resolver or SPIFFEResolver()

    async def intercept(
        self,
        tool_name: str,
        tool_params: dict[str, Any],
        session_id: str = "",
        framework: str = "",
        call_depth: int = 0,
        identity: AgentIdentity | None = None,
    ) -> PolicyDecision:
        """Evaluate a tool call and return policy decision."""
        resolved = identity or await self._resolver.resolve()
        event = ToolCallEvent(
            tool_name=tool_name,
            tool_params=tool_params,
            agent_identity=resolved,
            session_id=session_id,
            framework=framework,
            call_depth=call_depth,
        )
        decision = await self._evaluator.evaluate(event)
        # Record every evaluated call on the active capture scope (if any). This is what lets a host
        # report a block that a framework's own agent loop swallows before it can propagate — and gives
        # an honest tools_called for frameworks whose message objects don't expose the calls. No-op
        # (one ContextVar.get) when nothing opted in, so the in-cluster hot path is untouched.
        record_decision(tool_name, decision)
        log.info("nrvq.intercept.result", tool=tool_name, decision=decision.decision, code="NRVQ-SDK-1020")
        return decision

    async def intercept_or_raise(
        self,
        tool_name: str,
        tool_params: dict[str, Any],
        session_id: str = "",
        framework: str = "",
        call_depth: int = 0,
        identity: AgentIdentity | None = None,
    ) -> PolicyDecision:
        """Evaluate call and raise on blocked or escalated outcomes."""
        decision = await self.intercept(tool_name, tool_params, session_id, framework, call_depth, identity)
        if decision.is_blocked():
            log.warning("nrvq.intercept.blocked", tool=tool_name, rule=decision.rule_id, code="NRVQ-SDK-1021")
            raise NorviqBlockError(decision)
        if decision.is_escalated():
            log.warning("nrvq.intercept.escalated", tool=tool_name, code="NRVQ-SDK-1022")
            raise NorviqEscalateError(decision)
        return decision
