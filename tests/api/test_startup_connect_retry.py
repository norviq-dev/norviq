# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The API must retry a Postgres it cannot reach yet, not die on the first refused connection.

With an external datastore given only by `existingSecret` (the production path docs/configuration.md
recommends) the chart cannot name the host, so it renders no wait init container and the API's own
startup retry is the only wait there is. That retry wrapped `init_db`, which only builds SQLAlchemy's
lazy engine and never opens a socket, so it could not fail. The first real connection was
`create_tables()`, which retries a lock TIMEOUT only. Measured against a refused port before the fix:
`init_db` "succeeded" in 0.05 s and `create_tables` raised ConnectionRefusedError in 0.28 s, zero
retries, and NRVQ-DB-9034/9035 could never fire.

Runs the real lifespan against a refused local port with `asyncio.sleep` stubbed, so the backoff
schedule is asserted, not waited for.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from norviq.api import main
from norviq.api.db import session as db_session
from norviq.config import settings


def _refused_port() -> int:
    """A local port nothing listens on: bind, read the number, close."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def sleeps(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    recorded: list[float] = []

    async def _no_wait(delay: float, *args, **kwargs) -> None:
        recorded.append(delay)

    monkeypatch.setattr(asyncio, "sleep", _no_wait)
    return recorded


def test_lifespan_retries_a_refused_postgres_then_fails_closed(
    monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    monkeypatch.setattr(settings, "pg_url", f"postgresql://u:p@127.0.0.1:{_refused_port()}/norviq?sslmode=disable")
    monkeypatch.setattr(settings, "db_ssl_mode", "disable", raising=False)
    monkeypatch.setattr(settings, "require_strong_secret", False)

    async def _run() -> None:
        try:
            async with main.lifespan(main.app):
                pass
        finally:
            await db_session.close_db()

    # Fail closed: after the last attempt startup raises, so the pod restarts rather than serving.
    with pytest.raises(OSError):
        asyncio.run(_run())
    assert sleeps == [1, 2, 4, 8], f"expected 5 attempts with the 1/2/4/8 s backoff, slept {sleeps}"
