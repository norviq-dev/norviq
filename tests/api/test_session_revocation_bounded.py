# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-044: revocation degrades for a bounded window, then refuses.

`is_revoked` failed OPEN on any Redis error, so a logged-out token kept working for as long as the
store was unreachable — indefinitely, and with a warning line as the only signal. "Log out" that does
not survive a dependency outage is not a security control, it is a UI gesture.

Failing closed outright (the card's suggestion) is worse: a Redis blip becomes a 401 for every
authenticated caller — a total outage of the product, caused by the product. Both directions are
real, so neither absolute is correct and the fail-open is time-boxed instead.
"""

from __future__ import annotations

import time

import pytest

from norviq.api import session_revocation as sr


class _Broken:
    async def is_token_revoked(self, _h):
        raise RuntimeError("redis down")


class _Healthy:
    def __init__(self, revoked: bool = False):
        self._revoked = revoked

    async def is_token_revoked(self, _h):
        return self._revoked


@pytest.fixture(autouse=True)
def _reset_clock():
    sr._degraded_since = None
    sr._mirror.clear()
    yield
    sr._degraded_since = None
    sr._mirror.clear()


async def test_a_blip_keeps_callers_working():
    """The case that actually happens — a restart or failover — must not 401 everyone."""
    assert await sr.is_revoked(_Broken(), "tok") is False


async def test_still_open_inside_the_grace_window():
    sr._degraded_since = time.time() - (sr._REVOCATION_GRACE_S / 2)
    assert await sr.is_revoked(_Broken(), "tok") is False


async def test_a_sustained_outage_fails_closed():
    """Indistinguishable from someone holding the store down so a stolen token keeps working."""
    sr._degraded_since = time.time() - (sr._REVOCATION_GRACE_S + 5)
    assert await sr.is_revoked(_Broken(), "tok") is True


async def test_the_window_measures_this_outage_not_the_lifetime():
    """A successful read clears the clock, so unrelated blips do not accumulate into a lockout."""
    sr._degraded_since = time.time() - (sr._REVOCATION_GRACE_S / 2)
    await sr.is_revoked(_Healthy(), "tok")
    assert sr._degraded_since is None
    assert await sr.is_revoked(_Broken(), "tok") is False  # a fresh outage starts a fresh window


async def test_the_grace_window_is_far_shorter_than_a_session():
    """The bound only means something if it expires long before the tokens it is protecting do."""
    from norviq.config import settings

    assert sr._REVOCATION_GRACE_S < settings.auth_session_ttl_s / 10


async def test_a_healthy_store_still_decides():
    assert await sr.is_revoked(_Healthy(revoked=True), "tok") is True
    assert await sr.is_revoked(_Healthy(revoked=False), "tok") is False
