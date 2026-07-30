# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The Redis RESP parser is a latency dependency, and its absence is silent.

redis-py works perfectly without hiredis — it falls back to a pure-Python parser whose cost scales with
the number of values a reply contains. That makes the regression invisible to every other test in this
suite: the small GETs and HGETALLs that dominate the tests are unaffected, and only the one hot-path query
that returns 500 rows (the trust history `ZRANGEBYSCORE`) is destroyed by it.

Measured in-cluster on that exact query, the two parsers differ by 21x at p50 and 35x at p90:

    pure-Python   p50 9.28ms   p90 53.94ms
    hiredis (C)   p50 0.44ms   p90  1.55ms

Redis itself was never slow — its own `commandstats` put the same query at 190us server-side, so ~98% of
what the caller waited for was the client decoding the reply.

Nothing fails if this dependency disappears. The system stays correct and just gets ~9ms slower on every
evaluation, which is why it needs a test rather than a comment: a transitive change that drops the extra
would otherwise be caught only by someone re-running a latency benchmark by hand.
"""

from __future__ import annotations

import importlib.metadata

import pytest


def test_hiredis_is_installed() -> None:
    """The `redis[hiredis]` extra must actually resolve, not merely be written down."""
    pytest.importorskip(
        "hiredis",
        reason="hiredis missing: redis-py will fall back to the pure-Python parser and the trust "
        "history read regresses from ~0.4ms to ~9ms per evaluation",
    )


def test_redis_py_actually_selects_the_c_parser() -> None:
    """Installed is not the same as USED.

    redis-py chooses its parser at connection-construction time. Asserting on the selected class rather
    than on the import is what makes this meaningful: a future redis-py that changes its selection logic,
    or an environment variable that opts out, would leave `import hiredis` working while every connection
    quietly used the slow path.
    """
    pytest.importorskip("hiredis")
    from redis.connection import Connection

    parser = type(Connection()._parser).__name__
    assert "Hiredis" in parser, (
        f"redis-py selected {parser!r} rather than the hiredis parser; the trust history read "
        f"(ZRANGEBYSCORE, 500 rows) regresses ~21x"
    )


def test_the_extra_is_declared_so_the_shipped_IMAGE_gets_it() -> None:
    """The images install with `pip install '.[spiffe]'`, which reads neither uv.lock nor uv constraints.

    So a lockfile entry alone does not put hiredis in the runtime image — the requirement has to be on
    `redis` in `[project.dependencies]`. This repo has been bitten by exactly that distinction before
    (see the cryptography floor in pyproject.toml), and the failure mode is the worst kind: tests pass,
    CI passes, and only the deployed artifact is slow.
    """
    requires = importlib.metadata.distribution("norviq").requires or []
    redis_reqs = [r for r in requires if r.split()[0].split("[")[0].split(">")[0].split("=")[0] == "redis"]
    assert redis_reqs, "norviq no longer declares a redis dependency at all"
    assert any("hiredis" in r for r in redis_reqs), (
        f"redis is declared without the [hiredis] extra ({redis_reqs}); pip-installed images would ship "
        f"the pure-Python parser"
    )
