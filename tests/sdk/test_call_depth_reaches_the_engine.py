# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`call_depth` must reach the engine, or the shipped chain-depth control is unreachable.

Every PEP called `intercept(...)` without passing `call_depth`, so the parameter's 0 default won on
every production path: the injected sidecar, its HTTP fallback, the MCP firewall and all six SDK
adapters. Meanwhile `chain_depth_limit` ships ENABLED in the default comprehensive policy and in the
webhook's strict preset, the Policy Tester lets an operator set a chain depth and shows a real block,
a builder/intent rule on `call_depth` saves and reports Active, and the red-team suite reported the
control as PASSED — because the simulator is the only caller in the tree that ever set a non-zero
depth. ChainDepthSignal (10% of the trust weight) likewise scored all real traffic at depth 0.

Two mechanisms now feed it, with different trust levels, and both are pinned here:
  * the sidecar PEPs forward a CALLER-REPORTED depth (cooperative, like session_id) — all a
    cross-process proxy can know;
  * the SDK path uses an AUTHORITATIVE in-process ContextVar, because the adapters wrap tool
    EXECUTION, so a tool invoked inside another tool is measurably deeper.
"""

from __future__ import annotations

import pytest

from norviq.sdk.core.interceptor import current_call_depth, depth_scope


# ---- the in-process scope --------------------------------------------------------------------

def test_depth_scope_nests_and_unwinds() -> None:
    assert current_call_depth() == 0
    with depth_scope():
        assert current_call_depth() == 1
        with depth_scope():
            assert current_call_depth() == 2
        assert current_call_depth() == 1
    assert current_call_depth() == 0


def test_depth_unwinds_even_when_the_tool_raises() -> None:
    with pytest.raises(RuntimeError):
        with depth_scope():
            assert current_call_depth() == 1
            raise RuntimeError("tool blew up")
    assert current_call_depth() == 0, "a failing tool must not leak depth into sibling calls"


async def test_concurrent_agents_do_not_share_a_counter() -> None:
    """A ContextVar, not a global: two agent tasks running at once must not inflate each other."""
    import asyncio

    seen: list[int] = []

    async def branch(n: int) -> None:
        with depth_scope():
            await asyncio.sleep(0)
            seen.append(current_call_depth())

    await asyncio.gather(*(branch(i) for i in range(5)))
    assert seen == [1] * 5, f"depth bled across concurrent tasks: {seen}"


# ---- the caller-reported coercion the sidecar PEPs use ----------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (None, 0), ("", 0), ("nonsense", 0), (-1, 0),   # never fail the call on a bad value
    (3, 3), ("7", 7), (2.9, 2),
    (10**9, 1000),                                   # clamped, so a hostile value cannot blow up rego
])
def test_caller_reported_depth_is_coerced(raw, expected) -> None:
    from norviq.sidecar.proxy import _coerce_depth

    assert _coerce_depth(raw) == expected


# ---- the wiring itself, which is what actually regressed --------------------------------------

def test_every_pep_forwards_a_depth() -> None:
    """Guard the call sites. The bug was never in the interceptor — it was that no PEP passed the
    argument, so the default silently won."""
    import inspect

    from norviq.mcp import firewall
    from norviq.sidecar import http_fallback, proxy

    assert "call_depth=call_depth" in inspect.getsource(proxy), "sidecar proxy dropped call_depth again"
    assert "call_depth=call_depth" in inspect.getsource(http_fallback), "http fallback dropped call_depth"
    assert "call_depth=current_call_depth()" in inspect.getsource(firewall), "MCP firewall dropped call_depth"


def test_interceptor_falls_back_to_ambient_depth() -> None:
    import inspect

    from norviq.sdk.core.interceptor import ToolInterceptor

    src = inspect.getsource(ToolInterceptor.intercept)
    assert "current_call_depth()" in src, (
        "intercept no longer falls back to the ambient depth, so SDK-nested calls report 0 again"
    )
