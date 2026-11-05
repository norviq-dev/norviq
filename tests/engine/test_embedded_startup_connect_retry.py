# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""An embedded engine must retry a datastore it cannot reach yet, with the API's bounded backoff.

With `existingSecret` and no `host` the chart renders no wait init container, so the engine's own
startup is the only wait. Before this, it had none for connectivity: `RedisCache.connect` raised on the
first refused connection (0.01 s measured) and `warm_cache` retried only a missing schema, so a
refused Postgres raised at once too. The engine exited and the kubelet's restart backoff was the wait.

What must not change: only "cannot reach it" is retried (an auth failure or a corrupt row surfaces at
once), the retry is bounded and then raises (the pod restarts, loud), and nothing reports warm until a
`warm_cache` actually succeeded, so the no-policy path stays `policy_load_pending` -> block.
"""

from __future__ import annotations

import asyncio
import socket

import pytest
import redis.exceptions

from norviq.config import settings
from norviq.sidecar import proxy as proxy_mod
from norviq.sidecar.proxy import SidecarProxy


def _refused_port() -> int:
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


def test_embedded_start_retries_a_refused_redis_then_fails_closed(
    monkeypatch: pytest.MonkeyPatch, sleeps: list[float]
) -> None:
    monkeypatch.setattr(settings, "sidecar_mode", "embedded")
    monkeypatch.setattr(settings, "redis_url", f"redis://127.0.0.1:{_refused_port()}/0")
    proxy = SidecarProxy(socket_path="/tmp/nrvq-test-connect-retry.sock")
    with pytest.raises(redis.exceptions.ConnectionError):
        asyncio.run(proxy.start())
    assert sleeps == [1, 2, 4, 8], f"expected 5 Redis attempts with the 1/2/4/8 s backoff, slept {sleeps}"


class _Loader:
    def __init__(self, failures: int, exc: BaseException) -> None:
        self.remaining = failures
        self.calls = 0
        self.warmed = False
        self._exc = exc

    async def warm_cache(self) -> None:
        self.calls += 1
        if self.remaining > 0:
            self.remaining -= 1
            raise self._exc
        self.warmed = True


def _proxy(loader: _Loader) -> SidecarProxy:
    p = SidecarProxy(socket_path="/tmp/nrvq-test-connect-retry.sock")
    p._loader = loader
    return p


def test_warm_retries_a_refused_postgres_and_then_warms(sleeps: list[float]) -> None:
    loader = _Loader(failures=2, exc=ConnectionRefusedError(111, "Connect call failed"))
    asyncio.run(_proxy(loader)._warm_cache_once_the_schema_exists())
    assert loader.warmed is True
    assert loader.calls == 3
    assert sleeps == [1, 2]


def test_warm_gives_up_after_the_bounded_backoff_and_never_reports_warm(sleeps: list[float]) -> None:
    loader = _Loader(failures=10_000, exc=ConnectionRefusedError(111, "Connect call failed"))
    with pytest.raises(ConnectionRefusedError):
        asyncio.run(_proxy(loader)._warm_cache_once_the_schema_exists())
    assert loader.calls == 5, f"expected 5 attempts, got {loader.calls}"
    assert sleeps == [1, 2, 4, 8]
    assert loader.warmed is False


def test_an_authentication_failure_is_not_retried(sleeps: list[float]) -> None:
    class InvalidPasswordError(Exception):
        sqlstate = "28P01"

    loader = _Loader(failures=10_000, exc=InvalidPasswordError("password authentication failed"))
    with pytest.raises(InvalidPasswordError):
        asyncio.run(_proxy(loader)._warm_cache_once_the_schema_exists())
    assert loader.calls == 1
    assert sleeps == []


@pytest.mark.parametrize(
    "exc,expected",
    [
        (ConnectionRefusedError(111, "refused"), True),
        (socket.gaierror(-2, "Name or service not known"), True),
        (TimeoutError(), True),
        (ValueError("policy source is corrupt"), False),
        (Exception("password authentication failed"), False),
    ],
)
def test_unreachable_predicate_is_narrow(exc: BaseException, expected: bool) -> None:
    assert proxy_mod._is_unreachable(exc) is expected


def test_unreachable_predicate_reads_the_wrapped_driver_error() -> None:
    """SQLAlchemy wraps driver errors; `cannot_connect_now` (57P03) is a server still starting up."""

    class _Starting(Exception):
        sqlstate = "57P03"

    class _Outer(Exception):
        def __init__(self) -> None:
            self.orig = _Starting("the database system is starting up")

    assert proxy_mod._is_unreachable(_Outer()) is True
