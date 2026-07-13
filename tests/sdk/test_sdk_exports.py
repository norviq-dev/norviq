# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Tests for the norviq.sdk public re-export surface."""

from __future__ import annotations

import norviq.sdk as sdk


def test_all_declares_expected_names() -> None:
    """__all__ should list exactly the intended public re-exports."""
    assert set(sdk.__all__) == {
        "AgentIdentity",
        "NorviqBlockError",
        "NorviqEscalateError",
        "PolicyDecision",
        "PolicyEngineClient",
        "SupportsEvaluate",
        "ToolCallEvent",
        "ToolInterceptor",
    }


def test_tool_interceptor_identity() -> None:
    """norviq.sdk.ToolInterceptor must be the same object as the deep import."""
    from norviq.sdk.core.interceptor import ToolInterceptor as DeepToolInterceptor

    assert sdk.ToolInterceptor is DeepToolInterceptor
    assert callable(sdk.ToolInterceptor)


def test_supports_evaluate_identity() -> None:
    """norviq.sdk.SupportsEvaluate must be the same object as the deep import."""
    from norviq.sdk.core.interceptor import SupportsEvaluate as DeepSupportsEvaluate

    assert sdk.SupportsEvaluate is DeepSupportsEvaluate


def test_policy_decision_identity() -> None:
    """norviq.sdk.PolicyDecision must be the same object as the deep import."""
    from norviq.sdk.core.decisions import PolicyDecision as DeepPolicyDecision

    assert sdk.PolicyDecision is DeepPolicyDecision
    assert callable(sdk.PolicyDecision)


def test_events_identity() -> None:
    """norviq.sdk.ToolCallEvent/AgentIdentity must be the same objects as the deep imports."""
    from norviq.sdk.core.events import AgentIdentity as DeepAgentIdentity
    from norviq.sdk.core.events import ToolCallEvent as DeepToolCallEvent

    assert sdk.ToolCallEvent is DeepToolCallEvent
    assert sdk.AgentIdentity is DeepAgentIdentity


def test_policy_engine_client_identity() -> None:
    """norviq.sdk.PolicyEngineClient must be the same object as the deep import."""
    from norviq.sdk.client.engine import PolicyEngineClient as DeepPolicyEngineClient

    assert sdk.PolicyEngineClient is DeepPolicyEngineClient
    assert callable(sdk.PolicyEngineClient)


def test_exception_identities() -> None:
    """norviq.sdk exception re-exports must be the same objects as norviq.exceptions."""
    from norviq.exceptions import NorviqBlockError as DeepNorviqBlockError
    from norviq.exceptions import NorviqEscalateError as DeepNorviqEscalateError

    assert sdk.NorviqBlockError is DeepNorviqBlockError
    assert sdk.NorviqEscalateError is DeepNorviqEscalateError


def test_framework_adapters_not_imported_at_package_level() -> None:
    """norviq/sdk/__init__.py's import statements must not reference any framework adapter package."""
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(sdk))
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported_modules.append(node.module)

    adapters = ("langchain", "langgraph", "crewai", "autogen", "semantic_kernel")
    for module_name in imported_modules:
        for adapter in adapters:
            assert f".{adapter}" not in module_name and not module_name.endswith(adapter), (
                f"norviq/sdk/__init__.py must not import the {adapter!r} adapter eagerly (found {module_name!r})"
            )
