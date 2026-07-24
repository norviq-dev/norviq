# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Context-local capture of enforcement decisions.

Enforcement is a raised exception: ``ToolInterceptor.intercept_or_raise`` raises
``NorviqBlockError``/``NorviqEscalateError`` at the tool boundary, and a host that lets that
exception propagate (LangChain, LangGraph) can report the decision directly. But some frameworks
run their own agent loop that *catches* the raised exception, treats it as a recoverable tool
error, and has the model paraphrase an apology — so the block really happened (the interceptor
evaluated it, the tool body never ran) yet the exception never reaches the host, and the host has
nothing to report. CrewAI, AutoGen, and Semantic Kernel all do this.

This module lets a host recover the decision anyway. ``capture_decisions()`` installs a mutable
recorder for the duration of one agent run; the interceptor calls ``record_decision()`` for every
call it evaluates; afterwards the host reads ``rec.last_denial`` / ``rec.tools_called``.

Why a *mutable object* in a ``ContextVar`` (not a plain global, not a bare value):

* Plain global → two concurrent requests clobber each other. A per-capture recorder is isolated.
* ``contextvars`` are propagated across every async/thread boundary the adapters cross —
  ``asyncio.to_thread`` (CrewAI's sync ``kickoff``), ``loop.create_task`` (child tasks), and
  ``run_coroutine_threadsafe`` (the SDK's shared sync-bridge loop) each ``copy_context()``. A copy
  duplicates the *bindings*, not the objects, so every nested context still points at the SAME
  recorder object — as long as we only ever MUTATE it (append) and never rebind the var inside the
  child. That is exactly what ``record_decision`` does, so a recorder installed on the request task
  before any of those boundaries sees decisions made on the far side of them.

This is purely additive and side-effect-free when no recorder is installed (the sidecar/in-cluster
path never installs one): ``record_decision`` is a cheap ``ContextVar.get()`` that no-ops on ``None``.
It changes NOTHING about the enforcement decision itself — the block still happens the same way.
"""

from __future__ import annotations

import contextlib
import contextvars
from collections.abc import Iterator
from dataclasses import dataclass, field

from norviq.sdk.core.decisions import PolicyDecision

_ACTIVE: contextvars.ContextVar["DecisionRecorder | None"] = contextvars.ContextVar(
    "nrvq_decision_recorder", default=None
)


@dataclass(frozen=True)
class RecordedDecision:
    """One evaluated tool call: the tool name (PolicyDecision carries no tool name) + its decision."""

    tool_name: str
    decision: PolicyDecision


@dataclass
class DecisionRecorder:
    """Accumulates every decision seen during one ``capture_decisions()`` scope.

    One recorder per captured run, so concurrent runs never interfere. Mutated in place (append)
    so the same object is visible across the async/thread boundaries the adapters cross.
    """

    records: list[RecordedDecision] = field(default_factory=list)

    def record(self, tool_name: str, decision: PolicyDecision) -> None:
        """Append one evaluated call (allow, audit, block, or escalate)."""
        self.records.append(RecordedDecision(tool_name=tool_name, decision=decision))

    @property
    def tools_called(self) -> list[str]:
        """Every tool name the interceptor evaluated, in call order (allow + audit + deny).

        This is the honest ``tools_called`` for a framework whose own message objects don't expose
        the calls it made — the interceptor saw every one of them.
        """
        return [r.tool_name for r in self.records if r.tool_name]

    @property
    def last_denial(self) -> PolicyDecision | None:
        """The most recent block/escalate decision, or ``None`` if nothing was refused."""
        for r in reversed(self.records):
            if r.decision.is_blocked() or r.decision.is_escalated():
                return r.decision
        return None


def record_decision(tool_name: str, decision: PolicyDecision) -> None:
    """Record a decision on the active recorder, if a ``capture_decisions()`` scope is open.

    A no-op (one ``ContextVar.get()``) when no recorder is installed — i.e. everywhere except a host
    that opted in — so this never touches the in-cluster enforcement hot path.
    """
    rec = _ACTIVE.get()
    if rec is not None:
        rec.record(tool_name, decision)


@contextlib.contextmanager
def capture_decisions() -> Iterator[DecisionRecorder]:
    """Install a fresh recorder for the duration of the block and yield it.

    Enter this on the task that drives one agent run, BEFORE the framework spawns any thread/task,
    so the recorder propagates to wherever the tool actually executes::

        with capture_decisions() as rec:
            reply = await run_agent(user_message)
        if rec.last_denial is not None:      # a framework swallowed the raised block — report it anyway
            return denied_response(rec.last_denial, tools=rec.tools_called)
    """
    rec = DecisionRecorder()
    token = _ACTIVE.set(rec)
    try:
        yield rec
    finally:
        _ACTIVE.reset(token)
