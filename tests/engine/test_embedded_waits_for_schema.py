# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""An embedded engine must WAIT for the schema, not die — and must stay fail-closed while it waits.

`warm_cache` SELECTs from `policies`, but only the API creates that table, and nothing orders the two:
the standalone engine's init containers gate on Postgres and Redis, NOT on the API. Observed on a fresh
`helm install` — the engine reached the DB first and its startup died:

    asyncpg.exceptions.UndefinedTableError: relation "policies" does not exist

Kubernetes restarted it, the API had caught up by then, and it self-healed — which is exactly why it
read as noise. It is the same nondeterminism as the other fresh-install races: a crash backoff can
outlast `helm install --wait --atomic`, which then rolls back a healthy install.

The part that must never regress is the SECOND assertion below. Waiting is only acceptable because the
engine stays fail-closed the whole time: `_warmed` is set solely by a successful `warm_cache`, so the
no-policy path remains `policy_load_pending` → block, never "nothing matched → allow". A retry that
swallowed the error and started serving would turn a startup race into an authorization bypass.
"""

from __future__ import annotations

import asyncio

import pytest

from norviq.sidecar.proxy import SidecarProxy, _is_missing_schema


class _Loader:
    """Fails with the real error N times, then succeeds — like the API finishing its migration."""

    def __init__(self, failures: int, exc: BaseException | None = None) -> None:
        self.remaining = failures
        self.calls = 0
        self.warmed = False
        self._exc = exc or Exception('relation "policies" does not exist')

    async def warm_cache(self) -> None:
        self.calls += 1
        if self.remaining > 0:
            self.remaining -= 1
            raise self._exc
        self.warmed = True


def _proxy(loader) -> SidecarProxy:
    p = SidecarProxy(socket_path="/tmp/nrvq-test.sock")
    p._loader = loader
    p._SCHEMA_POLL_S = 0.01  # keep the unit test fast; the shipped value is 2s
    return p


def test_it_waits_through_a_missing_schema_and_then_warms() -> None:
    loader = _Loader(failures=3)
    asyncio.run(_proxy(loader)._warm_cache_once_the_schema_exists())
    assert loader.warmed is True
    assert loader.calls == 4, f"expected 3 retries then success, got {loader.calls} attempts"


def test_it_does_not_report_warm_while_it_is_still_waiting() -> None:
    """FAIL-CLOSED: the wait must never look like a successful warm.

    If this ever passes with `warmed is True`, the engine would serve traffic believing it has the
    policy set when it has not read it — the no-policy path would answer "allow" instead of
    `policy_load_pending` → block. That is a bypass, not a startup nicety.
    """
    loader = _Loader(failures=10_000)
    proxy = _proxy(loader)
    proxy._SCHEMA_WAIT_S = 0.05
    with pytest.raises(Exception, match="does not exist"):
        asyncio.run(proxy._warm_cache_once_the_schema_exists())
    assert loader.warmed is False, "reported warm without ever reading the policy table"


def test_it_gives_up_loudly_if_the_schema_never_appears() -> None:
    """Bounded, not infinite: a genuinely broken deployment must still crash and be visible."""
    loader = _Loader(failures=10_000)
    proxy = _proxy(loader)
    proxy._SCHEMA_WAIT_S = 0.05
    with pytest.raises(Exception, match="does not exist"):
        asyncio.run(proxy._warm_cache_once_the_schema_exists())


def test_a_real_error_is_not_retried() -> None:
    """Only "not there YET" is transient. Anything else must surface immediately, unretried."""
    loader = _Loader(failures=10_000, exc=ValueError("policy source is corrupt"))
    proxy = _proxy(loader)
    with pytest.raises(ValueError, match="corrupt"):
        asyncio.run(proxy._warm_cache_once_the_schema_exists())
    assert loader.calls == 1, f"a non-transient error was retried {loader.calls} times"


@pytest.mark.parametrize("message,expected", [
    ('relation "policies" does not exist', True),
    ('relation "policy_versions" does not exist', True),
    ("connection refused", False),
    ("password authentication failed", False),
    ("column policies.priority does not exist", False),  # a real schema mismatch, not a missing table
])
def test_missing_schema_predicate_is_narrow(message: str, expected: bool) -> None:
    assert _is_missing_schema(Exception(message)) is expected


def test_predicate_matches_the_postgres_sqlstate_too() -> None:
    """Message matching is the fallback; SQLSTATE 42P01 is the authoritative signal."""

    class _Wrapped(Exception):
        sqlstate = "42P01"

    class _Outer(Exception):
        def __init__(self) -> None:
            self.orig = _Wrapped("some driver-specific rendering")

    assert _is_missing_schema(_Outer()) is True
