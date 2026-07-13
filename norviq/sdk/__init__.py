# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Norviq in-process SDK.

The integration model is one paragraph: build a `ToolCallEvent` per tool call (or let a
`ToolInterceptor` do it for you from `tool_name`/`tool_params`/`session_id`), hand it to
anything that satisfies `SupportsEvaluate` (the in-cluster `OPAEvaluator` or the
out-of-cluster `PolicyEngineClient`), and get back a `PolicyDecision` — `allow`/`audit`
pass the call through, `block`/`escalate` raise `NorviqBlockError`/`NorviqEscalateError`
so the call never reaches the tool (fail-closed by construction). Framework adapters
(`norviq.sdk.langchain`, `norviq.sdk.langgraph`, `norviq.sdk.crewai`, `norviq.sdk.autogen`,
`norviq.sdk.semantic_kernel`) are thin, opt-in wrappers around this core and are not
imported here — install and import only the adapter(s) you need.
"""

import importlib
from typing import Any

__all__ = [
    "AgentIdentity",
    "NorviqBlockError",
    "NorviqEscalateError",
    "PolicyDecision",
    "PolicyEngineClient",
    "SupportsEvaluate",
    "ToolCallEvent",
    "ToolInterceptor",
]

# name -> (module to import from, attribute name). Resolved lazily via module __getattr__
# (PEP 562) rather than as top-of-file imports: `norviq.engine.identity` imports
# `norviq.sdk.core.events.AgentIdentity`, and importing ANY norviq.sdk submodule first runs
# this file — so an eager `from norviq.sdk.core.interceptor import ToolInterceptor` here (which
# itself needs `norviq.engine.identity.SPIFFEResolver`) creates a real import cycle the first
# time `norviq.engine.identity` is the entry point. Lazy resolution defers that import until a
# re-export is actually used, after both modules have finished initializing.
_EXPORTS: dict[str, tuple[str, str]] = {
    "AgentIdentity": ("norviq.sdk.core.events", "AgentIdentity"),
    "NorviqBlockError": ("norviq.exceptions", "NorviqBlockError"),
    "NorviqEscalateError": ("norviq.exceptions", "NorviqEscalateError"),
    "PolicyDecision": ("norviq.sdk.core.decisions", "PolicyDecision"),
    "PolicyEngineClient": ("norviq.sdk.client.engine", "PolicyEngineClient"),
    "SupportsEvaluate": ("norviq.sdk.core.interceptor", "SupportsEvaluate"),
    "ToolCallEvent": ("norviq.sdk.core.events", "ToolCallEvent"),
    "ToolInterceptor": ("norviq.sdk.core.interceptor", "ToolInterceptor"),
}


def __getattr__(name: str) -> Any:
    """Resolve a public re-export on first access and cache it on the module."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = target
    value = getattr(importlib.import_module(module_name), attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Include lazy re-exports in dir() output."""
    return sorted(set(globals()) | set(__all__))
