# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Spoke puller adversarial fail-closed matrix (F045 P2). The security heart of policy-push: a tampered,
unsigned, wrong-key, expired, replayed, or wrong-cluster bundle must NEVER reach the local PolicyLoader,
and the last-good bundle must survive a hub outage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from jose.backends import RSAKey

from norviq.config import settings
from norviq.fleet.bundle import rfc3339_z, sign_bundle
from norviq.fleet_puller import FleetPolicyPuller


def _gen_rsa_pem() -> str:
    import rsa as rsalib

    _, priv = rsalib.newkeys(2048)
    return priv.save_pkcs1().decode()


def _pub(priv_pem: str) -> str:
    return RSAKey(priv_pem, "RS256").public_key().to_pem().decode()


def _bundle(version: int, nbf_delta=-60, exp_delta=900, cluster="fleet-a") -> dict:
    now = datetime.now(timezone.utc)
    return {
        "cluster_id": cluster, "bundle_version": version, "issued_at": rfc3339_z(now),
        "not_before": rfc3339_z(now + timedelta(seconds=nbf_delta)),
        "expires_at": rfc3339_z(now + timedelta(seconds=exp_delta)),
        "prev_bundle_version": version - 1,
        "policies": [{"namespace": "default", "agent_class": "bot", "rego_source": "package x",
                      "priority": 100, "enforcement_mode": "block", "version": 1}],
    }


class _FakeLoader:
    def __init__(self):
        self.created = []

    async def create(self, namespace, agent_class, rego_source, saved_by="", priority=100, enforcement_mode="block"):
        self.created.append((namespace, agent_class, rego_source))
        return 1


class _Resp:
    def __init__(self, body, status=200):
        self._body = body
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=None)

    def json(self):
        return self._body


class _FakeHub:
    def __init__(self, bundle_body, get_status=200):
        self.bundle_body = bundle_body
        self.get_status = get_status
        self.rollouts = []

    async def get(self, url, headers=None):
        return _Resp(self.bundle_body, self.get_status)

    async def post(self, url, headers=None, json=None):
        self.rollouts.append(json)
        return _Resp({})


class _FakeSpokeSession:
    def __init__(self, last_applied=0):
        self.last_applied = last_applied
        self.persisted = []

    async def execute(self, stmt):
        if getattr(stmt, "is_insert", False):
            self.persisted.append(stmt)
            return SimpleNamespace()
        row = SimpleNamespace(last_applied_version=self.last_applied) if self.last_applied else None
        return SimpleNamespace(scalar_one_or_none=lambda: row)

    async def commit(self):
        pass

    async def aclose(self):
        pass


def _factory(session):
    async def _gen():
        yield session
    return _gen


def _puller(priv, hub, loader, last_applied=0, pubkey=None, monkeypatch=None):
    monkeypatch.setattr(settings, "fleet_api_url", "http://hub:8080")
    monkeypatch.setattr(settings, "fleet_cluster_id", "fleet-a")
    monkeypatch.setattr(settings, "fleet_oidc_token_url", "")
    monkeypatch.setattr(settings, "legacy_hs256_enabled", True)
    monkeypatch.setattr(settings, "fleet_bundle_pubkey", pubkey if pubkey is not None else _pub(priv))
    p = FleetPolicyPuller(loader=loader, session_factory=_factory(_FakeSpokeSession(last_applied)), client=hub)
    return p


@pytest.mark.asyncio
async def test_valid_bundle_applies(monkeypatch) -> None:
    priv = _gen_rsa_pem()
    loader = _FakeLoader()
    hub = _FakeHub(sign_bundle(_bundle(42), priv))
    out = await _puller(priv, hub, loader, monkeypatch=monkeypatch).pull_once()
    assert out["applied"] and out["version"] == 42
    assert loader.created == [("default", "bot", "package x")]
    assert hub.rollouts and hub.rollouts[-1]["state"] == "applied"


@pytest.mark.asyncio
@pytest.mark.parametrize("mutate,reason", [
    ("tamper", "verify_failed"),
    ("unsigned", "verify_failed"),
    ("expired", "expired"),
    ("not_before", "not_before"),
    ("wrong_cluster", "wrong_cluster"),
])
async def test_bad_bundles_rejected(monkeypatch, mutate, reason) -> None:
    priv = _gen_rsa_pem()
    loader = _FakeLoader()
    if mutate == "tamper":
        body = sign_bundle(_bundle(42), priv)
        body["payload"]["policies"][0]["rego_source"] = 'package x\ndefault decision = "allow"'
    elif mutate == "unsigned":
        body = {"payload": _bundle(42)}
    elif mutate == "expired":
        body = sign_bundle(_bundle(42, exp_delta=-10), priv)
    elif mutate == "not_before":
        body = sign_bundle(_bundle(42, nbf_delta=3600), priv)
    elif mutate == "wrong_cluster":
        body = sign_bundle(_bundle(42, cluster="fleet-b"), priv)
    out = await _puller(priv, _FakeHub(body), loader, monkeypatch=monkeypatch).pull_once()
    assert out["applied"] is False and out["reason"] == reason
    assert loader.created == []  # enforcement NEVER touched


@pytest.mark.asyncio
async def test_wrong_key_rejected(monkeypatch) -> None:
    priv = _gen_rsa_pem()
    loader = _FakeLoader()
    body = sign_bundle(_bundle(42), priv)  # signed with priv
    p = _puller(priv, _FakeHub(body), loader, pubkey=_pub(_gen_rsa_pem()), monkeypatch=monkeypatch)  # trust a DIFFERENT key
    out = await p.pull_once()
    assert out["applied"] is False and loader.created == []


@pytest.mark.asyncio
async def test_replay_older_version_rejected(monkeypatch) -> None:
    priv = _gen_rsa_pem()
    loader = _FakeLoader()
    body = sign_bundle(_bundle(41), priv)  # valid signature, but version 41
    p = _puller(priv, _FakeHub(body), loader, last_applied=42, monkeypatch=monkeypatch)  # already applied 42
    out = await p.pull_once()
    assert out["applied"] is False and out["reason"] == "not_newer" and loader.created == []


@pytest.mark.asyncio
async def test_compromised_hub_allow_all_rejected(monkeypatch) -> None:
    # A hub that has the DB/process but NOT the signing key swaps in an allow-all and signs with its own key.
    attacker = _gen_rsa_pem()
    trust = _gen_rsa_pem()
    loader = _FakeLoader()
    evil = _bundle(99)
    evil["policies"][0]["rego_source"] = 'package x\ndefault decision = "allow"'
    body = sign_bundle(evil, attacker)  # signed by the attacker, not the fleet key
    p = _puller(trust, _FakeHub(body), loader, pubkey=_pub(trust), monkeypatch=monkeypatch)
    out = await p.pull_once()
    assert out["applied"] is False and loader.created == []  # trust root holds


@pytest.mark.asyncio
async def test_hub_down_keeps_last_good(monkeypatch) -> None:
    priv = _gen_rsa_pem()
    loader = _FakeLoader()
    hub = _FakeHub(sign_bundle(_bundle(42), priv), get_status=503)  # hub 5xx
    with pytest.raises(httpx.HTTPStatusError):
        await _puller(priv, hub, loader, monkeypatch=monkeypatch).pull_once()
    assert loader.created == []  # enforcement unaffected; last-good stays (the _run loop swallows + retries)
