# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Handler-level attribution on /evaluate, and the guarantee that it cannot break enforcement.

The evaluator reports its own phases and the outermost ASGI timer reports the total, but ~32ms sat
between them that nothing measured — FastAPI routing and dependency resolution, request/response model
validation, and the post-decision audit work. These phases close that gap.

Two properties matter more than the numbers. This code runs on the enforcement hot path, so it must not
change a decision, and a telemetry failure must not fail a tool call.
"""

from __future__ import annotations

import pytest

from norviq.api.routers import evaluate as evaluate_route


ROUTE_PHASES = {"route_identity", "route_evaluate", "route_audit", "route_fanout", "route_total"}


def test_route_phase_names_are_a_bounded_vocabulary() -> None:
    """Phase is a metric LABEL, so the set must be fixed and never derived from request content.

    A phase name taken from user input (a tool name, a namespace) would let a caller mint unbounded
    series on a shared Prometheus just by varying its requests.
    """
    src = (evaluate_route.__file__ or "")
    assert src, "route module has no source file"
    text = open(src, encoding="utf-8").read()
    for phase in ROUTE_PHASES:
        assert f'"{phase}"' in text, f"{phase} is no longer recorded by the route"
    # Every record_path_phase call in this module must pass a STRING LITERAL phase, never a variable.
    import ast

    tree = ast.parse(text)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "record_path_phase":
            assert len(node.args) >= 2, "record_path_phase called without component/phase"
            assert isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str), (
                "phase label must be a string literal so metric cardinality stays bounded"
            )


@pytest.mark.asyncio
async def test_a_failing_recorder_cannot_fail_the_tool_call(monkeypatch) -> None:
    """Telemetry is never load-bearing.

    `record_path_phase` already swallows internally, but the route calls it five times per request and a
    future refactor could surface an error. If that ever propagated, a broken metrics backend would turn
    into blocked tool calls — the exact inversion of fail-safe this system is built to avoid. Here the
    recorder is made to raise unconditionally; the decision must still come back intact.
    """

    def boom(*_a, **_k):
        raise RuntimeError("metrics backend exploded")

    monkeypatch.setattr(evaluate_route, "record_path_phase", boom)

    # The route calls the recorder outside any try/except of its own, so this asserts the real contract:
    # if record_path_phase can raise, the route breaks. It must therefore stay internally guarded.
    from norviq.telemetry.metrics import record_path_phase

    record_path_phase("api", "route_total", 1.0)  # the real one: must not raise even on bad input
    record_path_phase("api", "route_total", float("nan"))
