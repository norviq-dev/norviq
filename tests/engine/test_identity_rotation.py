# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""SVID ROTATION — the half of the credential lifecycle that had no tests at all.

The token half is well covered and well designed: an expired sidecar JWT produces a 4xx, and
`EngineClient._handle_http_error` blocks on ANY 4xx regardless of `sdk_fallback_mode`, precisely
because with fail-open configured a 401 would otherwise turn a revoked credential into a total
governance bypass (tests/sdk/test_dataplane_failure_posture.py,
tests/sidecar/test_remote_evaluator_retry.py).

The SVID half had nothing. That matters more than it looks, because the injected API token
DELIBERATELY cannot rotate — `mintSidecarToken` (webhook/injector.go) says so outright: "The token is
baked into the pod env (cannot self-refresh), hence the long TTL". So the SVID is the credential that
IS expected to rotate underneath a long-lived process, and `SPIFFEResolver` caches the identity it
derives from it for `spiffe_cache_ttl_s` (300s default) with no reference to the SVID's own lifetime.

These tests state what rotation must do. Where one fails, it is describing a real gap, not a style
preference — an identity is what every policy decision, trust score and kill-switch is keyed on.
"""

from __future__ import annotations

import pytest

from norviq.config import settings
from norviq.engine.identity import SPIFFEResolver, SpiffeResolutionError

pytestmark = pytest.mark.asyncio

ID_A = "spiffe://norviq/ns/payments/sa/agent-sa"
ID_B = "spiffe://norviq/ns/payments/sa/rotated-sa"


class _Svid:
    def __init__(self, spiffe_id: str) -> None:
        self._id = spiffe_id

    @property
    def spiffe_id(self):
        return self._id


class _Source:
    """A Workload API that can change what it serves between fetches — i.e. one that rotates."""

    def __init__(self, ids: list[str]) -> None:
        self._ids = list(ids)
        self.fetches = 0

    def fetch_x509_svid(self) -> _Svid:
        self.fetches += 1
        # Serve each id in turn, then hold on the last — a rotation, then a steady state.
        idx = min(self.fetches - 1, len(self._ids) - 1)
        return _Svid(self._ids[idx])

    def close(self) -> None:  # pragma: no cover - channel cleanup
        pass


@pytest.fixture(autouse=True)
def _workload_api(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "spiffe_mode", "workload-api", raising=False)


async def test_a_rotated_svid_is_picked_up_once_the_cache_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    """The baseline rotation contract: the identity must follow the SVID, not outlive it forever."""
    monkeypatch.setattr(settings, "spiffe_cache_ttl_s", 300, raising=False)
    src = _Source([ID_A, ID_B])
    r = SPIFFEResolver()
    monkeypatch.setattr(r, "_svid_source", lambda: src)

    assert (await r.resolve()).spiffe_id == ID_A
    # Age the cache past its TTL without sleeping.
    import norviq.engine.identity as mod

    base = mod.time.monotonic()
    monkeypatch.setattr(mod.time, "monotonic", lambda: base + 10_000)
    assert (await r.resolve()).spiffe_id == ID_B


async def test_a_rotated_svid_is_not_served_from_a_previous_identitys_cache_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_get_cached` iterates the cache and returns the FIRST entry still inside its TTL, ignoring the
    key it is stored under. The dict is keyed by spiffe_id, so once two identities are present the
    lookup can return either — and which one depends on insertion order, not on who is calling.

    An identity is what every policy decision, trust score and the agent_frozen kill-switch key on, so
    serving the wrong one is not a caching nicety."""
    monkeypatch.setattr(settings, "spiffe_cache_ttl_s", 300, raising=False)
    r = SPIFFEResolver()

    import norviq.engine.identity as mod

    base = mod.time.monotonic()
    src = _Source([ID_A, ID_B])
    monkeypatch.setattr(r, "_svid_source", lambda: src)

    assert (await r.resolve()).spiffe_id == ID_A
    # Rotate: expire A's entry so B is fetched and cached alongside.
    monkeypatch.setattr(mod.time, "monotonic", lambda: base + 10_000)
    assert (await r.resolve()).spiffe_id == ID_B

    # Now BOTH may sit in the dict. Whatever the resolver answers must be the identity the Workload
    # API is currently attesting — never a stale sibling that merely happens to be inside its window.
    third = await r.resolve()
    assert third.spiffe_id == ID_B, (
        f"resolver served {third.spiffe_id} while the Workload API attests {ID_B} — "
        "the cache lookup ignored its own key"
    )


async def test_the_identity_cache_cannot_outlive_the_svid_it_was_derived_from(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`spiffe_cache_ttl_s` is operator-configurable and bears no relationship to the SVID's lifetime.
    Set it long and the resolver keeps enforcing on an identity whose attestation has lapsed — the
    Workload API is never consulted again for the whole window, so a revoked or rotated workload keeps
    its old identity for as long as the operator configured.

    Rotation is the SVID's whole purpose; a cache that can outlast it defeats it."""
    # `_CACHE_TTL` is a MODULE-LEVEL constant bound at import from settings, so patching the setting
    # alone changes nothing — the first version of this test did exactly that and passed while never
    # setting a long TTL at all. Patch what the code actually reads.
    import norviq.engine.identity as mod

    monkeypatch.setattr(mod, "_CACHE_TTL", 86_400, raising=False)  # a day
    src = _Source([ID_A, ID_B])
    r = SPIFFEResolver()
    monkeypatch.setattr(r, "_svid_source", lambda: src)

    assert (await r.resolve()).spiffe_id == ID_A
    base = mod.time.monotonic()
    # An hour later: far beyond any sane SVID lifetime (SPIRE defaults to minutes/hours), and the
    # Workload API is now attesting a different identity.
    monkeypatch.setattr(mod.time, "monotonic", lambda: base + 3_600)
    got = await r.resolve()
    assert got.spiffe_id == ID_B, (
        f"after an hour the resolver still served {got.spiffe_id}; the identity cache TTL "
        f"({settings.spiffe_cache_ttl_s}s) is unbounded by the SVID lifetime, so a rotated or revoked "
        "workload keeps its previous identity for the whole window"
    )


async def test_a_workload_api_that_stops_answering_fails_closed_rather_than_serving_the_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Once the cache expires and the socket is gone, there is no attested identity. Returning the last
    known one would be exactly the 'unknown rendered as compliant' shape, at the identity layer."""
    monkeypatch.setattr(settings, "spiffe_cache_ttl_s", 1, raising=False)
    r = SPIFFEResolver()

    class _Dies:
        def __init__(self) -> None:
            self.n = 0

        def fetch_x509_svid(self):
            self.n += 1
            if self.n == 1:
                return _Svid(ID_A)
            raise OSError("workload api socket closed")

        def close(self) -> None:  # pragma: no cover
            pass

    src = _Dies()
    monkeypatch.setattr(r, "_svid_source", lambda: src)
    assert (await r.resolve()).spiffe_id == ID_A

    import norviq.engine.identity as mod

    base = mod.time.monotonic()
    monkeypatch.setattr(mod.time, "monotonic", lambda: base + 10_000)
    with pytest.raises(SpiffeResolutionError):
        await r.resolve()


async def test_an_over_long_configured_ttl_is_clamped_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    """The knob is the danger, not the default. 300s is fine; an operator raising it to an hour is not
    buying a faster cache, they are turning SVID rotation off. Clamped, and logged so it is findable."""
    import norviq.engine.identity as mod

    monkeypatch.setattr(settings, "spiffe_cache_ttl_s", 86_400, raising=False)
    r = SPIFFEResolver()
    assert r._cache_ttl() == mod._MAX_CACHE_TTL


async def test_the_configured_ttl_actually_takes_effect(monkeypatch: pytest.MonkeyPatch) -> None:
    """It did not before: `_CACHE_TTL` was bound at import, so NRVQ_SPIFFE_CACHE_TTL_S changed nothing
    once the module was loaded. A setting that silently does nothing is worse than no setting."""
    monkeypatch.setattr(settings, "spiffe_cache_ttl_s", 7, raising=False)
    assert SPIFFEResolver()._cache_ttl() == 7
