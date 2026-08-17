# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Framework-agnostic tool-call interceptor."""

from contextlib import contextmanager
from contextvars import ContextVar
from time import perf_counter
from typing import Any, Protocol

import structlog

from norviq.engine.identity import SPIFFEResolver
from norviq.exceptions import NorviqBlockError, NorviqEscalateError
from norviq.sdk.core.decisions import PolicyDecision, apply_pep_denial
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent
from norviq.telemetry.metrics import record_interception_latency
from norviq.sdk.core.recorder import record_decision

log = structlog.get_logger()

# `framework` -> the `mode` label on the caller-observed interception-latency metric. A table rather
# than a conditional so a new enforcement surface adds a row instead of editing the hot path, and so
# every surface keeps its OWN latency series: folding MCP into "sdk" would have silently mixed a
# proxy-mediated call into the in-process adapter's numbers and made the no-regression comparison on
# the existing series unreadable. Anything unlisted still maps to "sdk", so the existing two labels
# are byte-for-byte what they were.
_MODE_BY_FRAMEWORK = {"sidecar": "sidecar", "mcp": "mcp"}


class SupportsEvaluate(Protocol):
    """Structural type for anything ToolInterceptor can delegate evaluation to.

    Both the in-cluster `norviq.engine.evaluator.OPAEvaluator` and the out-of-cluster
    `norviq.sdk.client.engine.PolicyEngineClient` satisfy this protocol, so either can be
    passed to `ToolInterceptor` without a shared base class.
    """

    async def evaluate(self, event: ToolCallEvent) -> PolicyDecision:
        """Evaluate a tool call event and return a policy decision."""
        ...


# In-process tool-call nesting depth. This is AUTHORITATIVE where it applies — the SDK adapters wrap
# tool EXECUTION, so a tool invoked from inside another tool is measurably deeper, and nothing the agent
# says can under-report it. It is the counterpart to the caller-reported depth the sidecar PEPs forward
# (norviq/sidecar/proxy.py _coerce_depth), which is all a cross-process proxy can know.
#
# Before this, every adapter called intercept_or_raise with keyword args and none passed call_depth, so
# the parameter's 0 default won on every path. `chain_depth_limit` — shipped ENABLED in the default
# comprehensive policy and the strict preset, exercised by the Policy Tester, reported PASSED by the
# red-team suite — could not fire on a single real call, and ChainDepthSignal (10% of the trust weight)
# scored all production traffic at depth 0.
_CALL_DEPTH: ContextVar[int] = ContextVar("nrvq_call_depth", default=0)


def current_call_depth() -> int:
    """The nesting depth of the tool call currently executing in this context."""
    return _CALL_DEPTH.get()


@contextmanager
def depth_scope():
    """Mark the execution of one tool call, so anything it invokes reports one level deeper.

    Adapters that wrap tool execution should hold this for the duration of the tool body. Uses a
    ContextVar token so concurrent agent tasks each carry their own depth rather than sharing a counter.
    """
    token = _CALL_DEPTH.set(_CALL_DEPTH.get() + 1)
    try:
        yield
    finally:
        _CALL_DEPTH.reset(token)


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
        mcp: dict[str, Any] | None = None,
        pep_decision: str = "",
        pep_rule_id: str = "",
        pep_reason: str = "",
    ) -> PolicyDecision:
        """Evaluate a tool call and return policy decision.

        ``mcp`` carries protocol context for calls that arrived over MCP (server id, transport, pin
        status, Gate-A scan severity). Keyword-only in practice and defaulted to None, so every
        existing caller — the sidecar, all six framework adapters, the red-team runner — is
        unchanged and still produces an event with an empty ``mcp``.

        ``pep_decision`` REPORTS a refusal this PEP already made on its own, before any policy ran —
        the MCP firewall's Gate A, its schema conformance check, its tool-header guard. Without it
        those denials reach no audit row at all and the console cannot show that anything happened.
        It may only ever be ``"block"`` (validated on the event) and can never loosen a decision.
        The returned decision still reflects the fold, so a caller that reads it sees the same
        outcome the audit log recorded.
        """
        # What the CALLER waits for one decision — the number a deployed agent actually feels, and the one
        # the published performance table cannot show: it reads the engine's own latency_ms, which excludes
        # everything outside the engine (identity resolve, the round trip to reach it, response handling).
        # In proxy mode that excluded part is the cross-pod hop, i.e. the term that dominates the tail.
        _t0 = perf_counter()
        # A caller that states a depth wins (the sidecar forwards what its client reported, and the
        # red-team runner sets it explicitly). Otherwise fall back to the ambient in-process depth,
        # which is what makes nested SDK tool calls report honestly without every adapter threading it.
        if not call_depth:
            call_depth = current_call_depth()
        resolved = identity or await self._resolver.resolve()
        event = ToolCallEvent(
            tool_name=tool_name,
            tool_params=tool_params,
            agent_identity=resolved,
            session_id=session_id,
            framework=framework,
            call_depth=call_depth,
            mcp=mcp or {},
            pep_decision=pep_decision,
            pep_rule_id=pep_rule_id,
            pep_reason=pep_reason,
        )
        decision = await self._evaluator.evaluate(event)
        # Fold the PEP's own refusal in here TOO, not only in the API router. Over HTTP the router has
        # already applied it and this is a no-op (the operation is idempotent — a decision that is
        # already "block" is returned unchanged). In EMBEDDED mode there is no router in the path at
        # all, and without this the same PEP refusal would be recorded over HTTP and lost in-process:
        # one property, two transports, and the property has to hold on both.
        decision = apply_pep_denial(decision, pep_decision, pep_rule_id, pep_reason)
        # Record every evaluated call on the active capture scope (if any). This is what lets a host
        # report a block that a framework's own agent loop swallows before it can propagate — and gives
        # an honest tools_called for frameworks whose message objects don't expose the calls. No-op
        # (one ContextVar.get) when nothing opted in, so the in-cluster hot path is untouched.
        record_decision(tool_name, decision)
        # `framework` already distinguishes the injected sidecar from an in-process SDK adapter, so it
        # doubles as the mode label rather than inventing a second signal that could disagree with it.
        record_interception_latency(
            _MODE_BY_FRAMEWORK.get(framework, "sdk"), "total", (perf_counter() - _t0) * 1000.0
        )
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
        mcp: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate call and raise on blocked or escalated outcomes."""
        decision = await self.intercept(
            tool_name, tool_params, session_id, framework, call_depth, identity, mcp
        )
        if decision.is_blocked():
            log.warning("nrvq.intercept.blocked", tool=tool_name, rule=decision.rule_id, code="NRVQ-SDK-1021")
            raise NorviqBlockError(decision)
        if decision.is_escalated():
            log.warning("nrvq.intercept.escalated", tool=tool_name, code="NRVQ-SDK-1022")
            raise NorviqEscalateError(decision)
        return decision
