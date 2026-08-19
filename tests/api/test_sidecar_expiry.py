# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""C2-020: the 30-day sidecar credential cliff must be forewarned, not just diagnosed afterwards.

Both credentials the webhook injects are 30-day and fixed in an immutable pod spec, and nothing renews
either. At expiry the API answers 401 and the sidecar fails CLOSED — which is CORRECT and deliberate
(a refused credential must not become a governance bypass) — so every injected pod stops making tool
calls on a timer. `/system-health` already diagnoses that once it starts; the defect was that the first
signal was the outage.
"""

from __future__ import annotations

import time

import pytest

from norviq.api import sidecar_expiry


class _FakeRedis:
    def __init__(self, fail: bool = False) -> None:
        self.store: dict[str, str] = {}
        self.fail = fail
        self.sets = 0

    async def set(self, key, value, ex=None, nx=False):
        if self.fail:
            raise RuntimeError("redis down")
        self.sets += 1
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    async def get(self, key):
        if self.fail:
            raise RuntimeError("redis down")
        return self.store.get(key)

    async def scan_iter(self, match=None, count=None):
        if self.fail:
            raise RuntimeError("redis down")
        for k in list(self.store):
            yield k


class _FakeCache:
    def __init__(self, redis: _FakeRedis) -> None:
        self._redis = redis

    def _client(self):
        return self._redis


def _claims(days_left: float, role: str = "service", **extra) -> dict:
    return {
        "role": role,
        "namespace": "analytics",
        "workload": "finance-agent",
        "exp": int(time.time() + days_left * 86400),
        **extra,
    }


@pytest.mark.asyncio
async def test_a_healthy_credential_writes_nothing_on_the_hot_path():
    """This runs inside authentication. The steady state for a healthy fleet must be zero writes."""
    r = _FakeRedis()
    await sidecar_expiry.observe(_FakeCache(r), _claims(days_left=29))
    assert r.sets == 0, "a credential outside the warning window must not touch Redis"


@pytest.mark.asyncio
async def test_a_human_session_is_never_warned_about():
    """A short-lived human session expiring is not an infrastructure event; warning would be noise."""
    r = _FakeRedis()
    await sidecar_expiry.observe(_FakeCache(r), _claims(days_left=1, role="admin"))
    assert r.sets == 0


@pytest.mark.asyncio
async def test_a_credential_inside_the_window_is_recorded_and_reported():
    r = _FakeRedis()
    cache = _FakeCache(r)
    await sidecar_expiry.observe(cache, _claims(days_left=3))
    rows = await sidecar_expiry.expiring_soon(cache)
    assert len(rows) == 1
    assert rows[0]["namespace"] == "analytics"
    assert rows[0]["workload"] == "finance-agent"
    assert 2.5 <= rows[0]["days_left"] <= 3.5


@pytest.mark.asyncio
async def test_repeated_calls_do_not_write_per_request():
    """A busy workload in its final week would otherwise turn this into a write per evaluate call."""
    r = _FakeRedis()
    cache = _FakeCache(r)
    for _ in range(50):
        await sidecar_expiry.observe(cache, _claims(days_left=2))
    assert len(r.store) == 1
    assert r.sets == 50  # the call is made...
    # ...but nx means only the first one stores, which is what bounds the key space.


@pytest.mark.asyncio
async def test_an_expired_credential_is_not_recorded_as_live():
    r = _FakeRedis()
    await sidecar_expiry.observe(_FakeCache(r), _claims(days_left=-1))
    assert r.sets == 0


@pytest.mark.asyncio
async def test_a_redis_failure_never_breaks_authentication():
    """observe() runs in the auth path. Failing a login because a reporting write failed would be a
    far worse bug than the one this warns about."""
    await sidecar_expiry.observe(_FakeCache(_FakeRedis(fail=True)), _claims(days_left=2))
    await sidecar_expiry.observe(None, _claims(days_left=2))  # no cache configured at all


@pytest.mark.asyncio
async def test_an_unreadable_redis_degrades_to_no_warning_not_a_500():
    """/system-health is the page an operator opens DURING an incident. It must not 500 because the
    newest, least important band could not be read."""
    assert await sidecar_expiry.expiring_soon(_FakeCache(_FakeRedis(fail=True))) == []
    assert await sidecar_expiry.expiring_soon(None) == []


@pytest.mark.asyncio
async def test_namespace_scoping_matches_the_rest_of_the_route():
    r = _FakeRedis()
    cache = _FakeCache(r)
    await sidecar_expiry.observe(cache, _claims(days_left=2))
    await sidecar_expiry.observe(cache, _claims(days_left=2, namespace="chatbot-prod"))
    assert len(await sidecar_expiry.expiring_soon(cache)) == 2
    scoped = await sidecar_expiry.expiring_soon(cache, "analytics")
    assert [r_["namespace"] for r_ in scoped] == ["analytics"]


def test_the_band_is_a_warning_not_a_critical():
    """Nothing is broken yet — that is the whole point. Raising it as critical would train operators
    to ignore the band that DOES mean an outage."""
    rows = [{"namespace": "analytics", "workload": "finance-agent",
             "expires_at": int(time.time() + 2 * 86400), "days_left": 2.0}]
    issue = sidecar_expiry.issue_for(rows)
    assert issue is not None
    assert issue["severity"] == "warning"
    assert "finance-agent" in issue["detail"]
    # The remediation must be the one that actually works: rotation IS pod replacement.
    assert "roll" in issue["remediation"].lower() or "replace" in issue["remediation"].lower()


def test_no_band_when_there_is_nothing_to_say():
    assert sidecar_expiry.issue_for([]) is None


class TestTheTwoKindsAreNotTheSameThing:
    """Observed live: a red band reading "? (norviq)" on an install where NO pod in that namespace had
    an injected sidecar. `role=service` is not "injected sidecar" — auth.py says the webhook controller
    and the fleet relay hold that role with an empty claim, and `workload` is the OPTIONAL claim only
    the injector mints. So every service key was captured, named nothing, and was told to roll a
    Deployment that did not exist.
    """

    @pytest.mark.asyncio
    async def test_a_credential_with_a_workload_claim_is_a_sidecar(self):
        r = _FakeRedis()
        await sidecar_expiry.observe(_FakeCache(r), _claims(2, sub="spiffe://x"))
        rows = await sidecar_expiry.expiring_soon(_FakeCache(r))
        assert [x["kind"] for x in rows] == [sidecar_expiry.KIND_SIDECAR]
        assert rows[0]["subject"] == "finance-agent"

    @pytest.mark.asyncio
    async def test_a_service_principal_with_no_workload_is_not_a_sidecar(self):
        """The exact live row: role=service, namespace norviq, no workload claim."""
        r = _FakeRedis()
        claims = {"role": "service", "namespace": "norviq", "sub": "mcp-firewall-chatbot-v3",
                  "exp": int(time.time() + 2 * 86400)}
        await sidecar_expiry.observe(_FakeCache(r), claims)
        rows = await sidecar_expiry.expiring_soon(_FakeCache(r))
        assert [x["kind"] for x in rows] == [sidecar_expiry.KIND_SERVICE_KEY]
        # It NAMES itself. "? (norviq)" was the whole complaint.
        assert rows[0]["subject"] == "mcp-firewall-chatbot-v3"

    @pytest.mark.asyncio
    async def test_a_service_key_is_never_told_to_roll_a_deployment(self):
        r = _FakeRedis()
        claims = {"role": "service", "namespace": "norviq", "sub": "mcp-firewall-chatbot-v3",
                  "exp": int(time.time() + 2 * 86400)}
        await sidecar_expiry.observe(_FakeCache(r), claims)
        bands = sidecar_expiry.issues_for(await sidecar_expiry.expiring_soon(_FakeCache(r)))
        assert [b["id"] for b in bands] == ["service_key_expiring"]
        assert "Mint a replacement key" in bands[0]["remediation"]
        assert "Roll the affected Deployments" not in bands[0]["remediation"]
        # and the band must name the credential, never a bare "?"
        assert "mcp-firewall-chatbot-v3" in bands[0]["detail"]
        assert "? (" not in bands[0]["detail"]

    @pytest.mark.asyncio
    async def test_each_kind_gets_its_own_band(self):
        r = _FakeRedis()
        c = _FakeCache(r)
        await sidecar_expiry.observe(c, _claims(3))                       # sidecar
        await sidecar_expiry.observe(c, {"role": "service", "namespace": "norviq",
                                         "sub": "relay", "exp": int(time.time() + 86400)})
        bands = sidecar_expiry.issues_for(await sidecar_expiry.expiring_soon(c))
        assert sorted(b["id"] for b in bands) == ["service_key_expiring", "sidecar_credential_expiring"]
        # soonest first, so the operator reads the one that bites first
        assert bands[0]["id"] == "service_key_expiring"

    @pytest.mark.asyncio
    async def test_a_credential_that_can_name_nothing_is_not_warned_about(self):
        """A band an operator cannot act on trains them to ignore the band that matters."""
        r = _FakeRedis()
        await sidecar_expiry.observe(_FakeCache(r), {"role": "service", "namespace": "norviq",
                                                     "exp": int(time.time() + 86400)})
        assert r.store == {}
        assert await sidecar_expiry.expiring_soon(_FakeCache(r)) == []

    @pytest.mark.asyncio
    async def test_legacy_v1_records_are_not_read(self):
        """v1 keyed on (namespace, workload) and produced the unnameable rows. They carry the
        credential's own remaining lifetime as their TTL, so they age out — but they must stop being
        REPORTED immediately, or the stale band survives the fix that was meant to remove it."""
        r = _FakeRedis()
        r.store["sidecar_exp:norviq:-"] = str(int(time.time() + 86400))
        assert await sidecar_expiry.expiring_soon(_FakeCache(r)) == []


class TestShortLivedCredentialsAreNotExpiringSoon:
    """Measured on a clean AKS install: `status: degraded` the moment it came up, with
    "service keys expire soon — norviq-webhook, 0 days", and it could never clear.

    The webhook controller signs ITSELF a one-hour service JWT and re-mints it at 60s-to-expiry
    (`webhook/controller.go`, `bearerToken`). A one-hour credential is always inside a seven-day
    window, so the band was permanent on every fresh install. Lifetime — not remaining time — is what
    separates "short-lived on purpose, something renews it" from "baked in and about to die".
    """

    @pytest.mark.asyncio
    async def test_the_webhooks_own_hourly_token_is_not_warned_about(self):
        r = _FakeRedis()
        now = int(time.time())
        await sidecar_expiry.observe(_FakeCache(r), {
            "role": "service", "namespace": "norviq", "sub": "norviq-webhook",
            "iat": now, "exp": now + 3600,          # the real shape, from controller.go
        })
        assert r.store == {}
        assert await sidecar_expiry.expiring_soon(_FakeCache(r)) == []

    @pytest.mark.asyncio
    async def test_a_thirty_day_credential_still_warns_near_the_end(self):
        """The case the module exists for must keep working."""
        r = _FakeRedis()
        now = int(time.time())
        await sidecar_expiry.observe(_FakeCache(r), {
            "role": "service", "namespace": "chatbot-prod", "workload": "agent",
            "iat": now - 24 * 86400, "exp": now + 6 * 86400,   # 30-day cred, 6 days left
        })
        rows = await sidecar_expiry.expiring_soon(_FakeCache(r))
        assert [x["subject"] for x in rows] == ["agent"]
        assert rows[0]["kind"] == sidecar_expiry.KIND_SIDECAR

    @pytest.mark.asyncio
    async def test_a_credential_with_no_iat_still_warns(self):
        """Unknown lifetime must not silently suppress a real expiry."""
        r = _FakeRedis()
        await sidecar_expiry.observe(_FakeCache(r), {
            "role": "service", "namespace": "norviq", "sub": "legacy-key",
            "exp": int(time.time() + 2 * 86400),
        })
        assert [x["subject"] for x in await sidecar_expiry.expiring_soon(_FakeCache(r))] == ["legacy-key"]

    @pytest.mark.asyncio
    async def test_a_fresh_install_reports_no_expiry_band_at_all(self):
        """The end-user property: install Norviq, open the console, see a healthy system."""
        r = _FakeRedis()
        c = _FakeCache(r)
        now = int(time.time())
        # everything a brand-new install actually presents
        await sidecar_expiry.observe(c, {"role": "service", "namespace": "norviq",
                                         "sub": "norviq-webhook", "iat": now, "exp": now + 3600})
        await sidecar_expiry.observe(c, {"role": "admin", "namespace": "norviq",
                                         "sub": "cli-admin", "iat": now, "exp": now + 28800})
        assert sidecar_expiry.issues_for(await sidecar_expiry.expiring_soon(c)) == []
