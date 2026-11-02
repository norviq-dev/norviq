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
