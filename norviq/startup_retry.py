# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Bounded startup retry for a datastore connection, shared by the API and the embedded engine."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

import structlog

log = structlog.get_logger()

T = TypeVar("T")

# 5 attempts with sleeps of 1, 2, 4 and 8 s between them: about 15 s of waiting before the caller's
# startup fails and the pod restarts. There is no sleep after the last attempt.
STARTUP_ATTEMPTS = 5


async def connect_with_backoff(
    coro_factory: Callable[[], Awaitable[T]],
    name: str,
    retry_code: str,
    fail_code: str,
    attempts: int = STARTUP_ATTEMPTS,
) -> T:
    """Retry a startup connection: `attempts` tries, sleeping 1, 2, 4, 8 s between them (15 s at 5).

    A backend may refuse connections, or accept TCP before it is query-ready, for a while after the pod
    starts. The chart's wait initContainers do not always cover that: with an external datastore given
    only by `existingSecret` the chart cannot name the host and renders no gate, so this retry is the
    only wait there is (docs/deployment.md, "Dependency waits"). Raises after the final attempt so the
    pod restarts: startup fails closed rather than serving without its datastore.
    """
    delay = 1
    for attempt in range(1, attempts + 1):
        try:
            return await coro_factory()
        except Exception as exc:
            if attempt == attempts:
                log.error(f"nrvq.startup.{name}_failed", attempts=attempt, error=str(exc), code=fail_code)
                raise
            log.warning(f"nrvq.startup.{name}_retry", attempt=attempt, delay=delay, error=str(exc), code=retry_code)
            await asyncio.sleep(delay)
            delay *= 2
    raise AssertionError("unreachable: the loop returns or raises")  # pragma: no cover


# Startup WARMS (copying state Postgres holds into the store the engine enforces from) are not
# connections: by the time they run, both stores answered. A failed warm is retried, then logged at ERROR
# and startup goes on, because refusing to start would not put the state back either. 3 attempts, 1 s
# then 2 s apart, each cut off at 10 s, so one warm costs at most 3 x 10 + 3 = 33 s of startup and the
# API's two warms 66 s. With the API lifespan's three connect_with_backoff steps (Postgres, Redis, the
# revocation load) at their refused-store bound, about 15 s each, that is 111 s of the API
# startupProbe's 160 s (10 + 30 x 5). The cut-off also bounds a store
# that stops answering, which has no client-side timeout of its own.
WARM_ATTEMPTS = 3
WARM_ATTEMPT_TIMEOUT_S = 10.0


async def warm_with_backoff(
    coro_factory: Callable[[], Awaitable[T]],
    name: str,
    retry_code: str,
    fail_code: str,
    attempts: int = WARM_ATTEMPTS,
    attempt_timeout_s: float | None = None,
) -> T | None:
    """connect_with_backoff for a startup warm: each attempt bounded by `attempt_timeout_s`, and None
    instead of a raise once every attempt failed (connect_with_backoff has logged `fail_code` at ERROR).
    The warm must be idempotent: an attempt cut off part-way is simply run again."""

    timeout_s = WARM_ATTEMPT_TIMEOUT_S if attempt_timeout_s is None else attempt_timeout_s

    async def _attempt() -> T:
        return await asyncio.wait_for(coro_factory(), timeout_s)

    try:
        return await connect_with_backoff(_attempt, name, retry_code, fail_code, attempts)
    except Exception:  # noqa: BLE001 - logged at ERROR by connect_with_backoff; startup goes on
        return None
