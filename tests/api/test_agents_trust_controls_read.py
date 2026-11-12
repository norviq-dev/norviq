# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Agent reads take the freeze and the trust cap from the controls the engine enforces.

The trust calculator reads ``agent_frozen:<id>`` and ``agent_trust_override:<id>`` fresh on every call.
``GET /agents`` and ``GET /agents/{id}`` built score and category from the last trust SNAPSHOT instead
(the 30 s ``trust:<id>`` row, else the registry's trust_score/trust_category) and never read either flag:

* a freeze vanished from the console about 30 s after it was set: the admin's display row expired and the
  registry snapshot predates the freeze, so a frozen agent read "medium 0.455" and Unfreeze was not offered;
* a lifted freeze read FROZEN 0.00 again once a call made while frozen had written 0.0/Frozen into the
  snapshot;
* a cap was invisible, and the score shown was the snapshot, not the min(score, cap) the engine uses.

The admin trust write also stored the cap or lift value it was sent as the agent's displayed score, so
"Unfreeze" (a cap of 0.8) read "high 0.80" on an agent the engine scored 0.455.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from types import SimpleNamespace

import jwt
import pytest
from fastapi.testclient import TestClient

import norviq.api.routers.agents as agents_mod
from norviq.api.main import create_app
from norviq.api.routers.agents import get_admin_db
from norviq.config import settings
from norviq.sdk.core.trust import TrustScore

AGENT = "spiffe://norviq/ns/payments/sa/invoice-agent"
OTHER = "spiffe://norviq/ns/payments/sa/ledger-agent"


def _hdr(role: str = "admin") -> dict[str, str]:
    claims = {"sub": "u", "role": role, "exp": datetime.now(timezone.utc) + timedelta(hours=1)}
    return {"Authorization": f"Bearer {jwt.encode(claims, settings.api_secret_key, algorithm='HS256')}"}


class _Store:
    """A Redis double over one key/value map: SCAN MATCH, GET, MGET, the per-namespace settings mirror, and
    the fenced admin control write (RedisCache.apply_admin_trust_control_if_owner's effect)."""

    def __init__(self, values: dict[str, str] | None = None, ns_settings: dict[str, dict] | None = None) -> None:
        self.values: dict[str, str] = dict(values or {})
        self.ns_settings = ns_settings or {}
        self.broken = False

    def _client(self) -> "_Store":
        return self

    async def scan_iter(self, match: str):
        for key in list(self.values):
            if fnmatch(key, match):
                yield key

    async def get(self, key: str) -> str | None:
        if self.broken and key.startswith(("agent_frozen:", "agent_trust_override:")):
            raise ConnectionError("store unavailable")
        return self.values.get(key)

    async def mget(self, keys: list[str]) -> list[str | None]:
        if self.broken and any(k.startswith(("agent_frozen:", "agent_trust_override:")) for k in keys):
            raise ConnectionError("store unavailable")
        return [self.values.get(k) for k in keys]

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:
        raw = self.values.get(f"trust:{spiffe_id}")
        return TrustScore.model_validate_json(raw) if raw else None

    async def get_ns_settings(self, namespace: str) -> dict | None:
        return self.ns_settings.get(namespace)

    async def claim_admin_trust_owner(self, spiffe_id: str, token, ttl_ms: int | None = None) -> str:
        token = "1" if token is None else str(token)
        self.values[f"agent_trust_owner:{spiffe_id}"] = token
        return token

    async def apply_admin_trust_control_if_owner(self, spiffe_id, token, *, frozen, cap, display=None) -> int:
        if self.values.get(f"agent_trust_owner:{spiffe_id}") != str(token):
            return 0
        if frozen:
            self.values[f"agent_frozen:{spiffe_id}"] = "1"
        else:
            self.values.pop(f"agent_frozen:{spiffe_id}", None)
        if cap is not None:
            self.values[f"agent_trust_override:{spiffe_id}"] = str(float(cap))
        else:
            self.values.pop(f"agent_trust_override:{spiffe_id}", None)
        shown = self.values.get(f"trust:{spiffe_id}")
        if display is not None:
            self.values[f"trust:{spiffe_id}"] = display.model_dump_json()
        elif not frozen and shown and TrustScore.model_validate_json(shown).category.lower() == "frozen":
            del self.values[f"trust:{spiffe_id}"]  # the script drops a frozen snapshot on any non-freeze write
        return 1


def _snapshot(score: float, category: str) -> str:
    """What the evaluator writes to trust:<id> (category title-cased, as _safe_set_trust stores it)."""
    return TrustScore(score=score, category=category).model_dump_json()


def _registry(sid: str, score: float, category: str, frozen: bool = False, cap: float | None = None) -> dict:
    """One row as _agents_from_registry builds it from agent_registry."""
    return {
        "spiffe_id": sid,
        "namespace": agents_mod._namespace_from_spiffe(sid),
        "agent_class": agents_mod._class_from_spiffe(sid),
        "last_seen": None,
        "score": score,
        "category": category.lower(),
        "violation_count": 6,
        "signals": {},
        "dominant_signal": "",
        "recommendation": "",
        "synthetic": False,
        "frozen": frozen,
        "trust_cap": cap,
    }


def _client(monkeypatch, store: _Store, registry: list[dict]) -> TestClient:
    app = create_app()
    app.state.cache = store

    async def _last_seen(_ns):
        return {}

    async def _roster(_ns):
        return [dict(r) for r in registry]

    async def _one(sid):
        found = [dict(r) for r in registry if r["spiffe_id"] == sid]
        if not found:
            return None
        row = found[0]
        return {k: row[k] for k in ("spiffe_id", "score", "category", "violation_count", "signals",
                                     "dominant_signal", "recommendation", "frozen", "trust_cap")}

    monkeypatch.setattr(agents_mod, "_registry_last_seen", _last_seen)
    monkeypatch.setattr(agents_mod, "_agents_from_registry", _roster)
    monkeypatch.setattr(agents_mod, "_agent_from_registry", _one)
    return TestClient(app)


def _listed(client: TestClient) -> dict[str, dict]:
    resp = client.get("/api/v1/agents?namespace=payments", headers=_hdr())
    assert resp.status_code == 200, resp.text
    return {row["spiffe_id"]: row for row in resp.json()}


def _detail(client: TestClient, sid: str) -> dict:
    resp = client.get(f"/api/v1/agents/{sid}", headers=_hdr())
    assert resp.status_code == 200, resp.text
    return resp.json()


# --- a freeze stays visible after the 30 s display row expires --------------------------------------------


def test_a_frozen_agent_reads_frozen_after_its_display_row_expired(monkeypatch) -> None:
    """The measured case: frozen in the registry and the store, no trust:<id> row left, registry snapshot
    medium 0.455. Before the fix both reads said medium 0.455."""
    store = _Store({f"agent_frozen:{AGENT}": "1"})
    client = _client(monkeypatch, store, [_registry(AGENT, 0.455, "Medium", frozen=True)])
    try:
        for row in (_listed(client)[AGENT], _detail(client, AGENT)):
            assert row["frozen"] is True
            assert row["score"] == 0.0
            assert row["category"] == "frozen"
            assert row["recommendation"] == "freeze"
    finally:
        client.close()


def test_the_live_freeze_is_what_is_shown_even_on_a_warm_pre_freeze_snapshot(monkeypatch) -> None:
    """A warm trust:<id> row written by the agent's last call BEFORE the freeze (high 0.9) is overridden too."""
    store = _Store({f"agent_frozen:{AGENT}": "1", f"trust:{AGENT}": _snapshot(0.9, "High")})
    client = _client(monkeypatch, store, [_registry(AGENT, 0.9, "High", frozen=True)])
    try:
        for row in (_listed(client)[AGENT], _detail(client, AGENT)):
            assert (row["frozen"], row["score"], row["category"]) == (True, 0.0, "frozen")
    finally:
        client.close()


@pytest.mark.parametrize("registry_frozen", [False, True])
def test_with_the_store_unreadable_the_freeze_is_unknown_not_the_registry_copy(monkeypatch, registry_frozen) -> None:
    """The engine fails CLOSED when it cannot read the store (RedisCache.get_agent_flags answers frozen), so
    during an outage every call the agent makes is blocked. The reads used to show the registry's durable copy
    instead: an agent never frozen there read "not frozen, medium 0.455" while the engine blocked it. Neither
    copy is known to be what is enforced, so both reads now say they do not know."""
    store = _Store({f"trust:{AGENT}": _snapshot(0.455, "Medium")})
    store.broken = True
    client = _client(monkeypatch, store, [_registry(AGENT, 0.455, "Medium", frozen=registry_frozen)])
    try:
        for row in (_listed(client)[AGENT], _detail(client, AGENT)):
            assert row["controls"] == "unavailable"
            assert row["frozen"] is None  # never False: that is the "not frozen" the engine contradicts
            assert row["trust_cap"] is None
            assert (row["score"], row["category"], row["recommendation"]) == (None, "unknown", "")
    finally:
        client.close()


def test_with_the_store_readable_the_controls_are_reported_live(monkeypatch) -> None:
    store = _Store({f"trust:{AGENT}": _snapshot(0.455, "Medium")})
    client = _client(monkeypatch, store, [_registry(AGENT, 0.455, "Medium")])
    try:
        for row in (_listed(client)[AGENT], _detail(client, AGENT)):
            assert (row["controls"], row["frozen"], row["score"], row["category"]) == ("live", False, 0.455, "medium")
    finally:
        client.close()


# --- a lifted freeze does not come back from a snapshot taken while it was in force --------------------------


def test_a_lifted_freeze_does_not_read_frozen_from_the_registry_snapshot(monkeypatch) -> None:
    """A call made while frozen wrote 0.0/Frozen into the registry. After the lift, with no new call, the agent is
    not frozen and its score is not known until it calls again."""
    store = _Store()  # no agent_frozen key: the freeze was lifted
    client = _client(monkeypatch, store, [_registry(AGENT, 0.0, "Frozen", frozen=False)])
    try:
        for row in (_listed(client)[AGENT], _detail(client, AGENT)):
            assert row["frozen"] is False
            assert row["category"] == "unscored"
            assert row["score"] is None
            assert row["recommendation"] != "freeze"
    finally:
        client.close()


def test_a_lifted_freeze_does_not_read_frozen_from_a_warm_snapshot(monkeypatch) -> None:
    store = _Store({f"trust:{AGENT}": _snapshot(0.0, "Frozen")})
    client = _client(monkeypatch, store, [_registry(AGENT, 0.0, "Frozen", frozen=False)])
    try:
        for row in (_listed(client)[AGENT], _detail(client, AGENT)):
            assert (row["frozen"], row["score"], row["category"]) == (False, None, "unscored")
    finally:
        client.close()


def test_a_snapshot_marked_unscored_when_its_cap_was_removed_reads_unscored(monkeypatch) -> None:
    """Removing or raising a cap marks a registry snapshot the old cap held down "Unscored"
    (_persist_trust_control) and drops the store's copy (the fenced script). The reads must then say the score
    is not known, not show the "Unscored" row's stale number: after Remove Cap they showed the capped 0.30 with
    no cap beside it until the agent's next call."""
    store = _Store()
    client = _client(monkeypatch, store, [_registry(AGENT, 0.3, "Unscored")])
    try:
        for row in (_listed(client)[AGENT], _detail(client, AGENT)):
            assert (row["frozen"], row["trust_cap"], row["score"], row["category"]) == (False, None, None, "unscored")
            assert row["recommendation"] == ""
    finally:
        client.close()


# --- a cap is shown, and the score is the one the engine uses ---------------------------------------------


def test_a_cap_above_the_score_is_shown_and_does_not_raise_the_score(monkeypatch) -> None:
    """The old Unfreeze: cap 0.8 on an agent scoring 0.455. The engine uses min(0.455, 0.8) = 0.455. The cap is
    only in the store here, so the row can only show it by reading the store."""
    store = _Store({f"agent_trust_override:{AGENT}": "0.8"})
    client = _client(monkeypatch, store, [_registry(AGENT, 0.455, "Medium")])
    try:
        for row in (_listed(client)[AGENT], _detail(client, AGENT)):
            assert row["trust_cap"] == 0.8
            assert row["frozen"] is False
            assert (row["score"], row["category"]) == (0.455, "medium")
    finally:
        client.close()


def test_a_cap_below_the_snapshot_is_the_score_shown_in_the_engines_band(monkeypatch) -> None:
    store = _Store({f"agent_trust_override:{AGENT}": "0.5", f"trust:{AGENT}": _snapshot(0.9, "High")})
    client = _client(monkeypatch, store, [_registry(AGENT, 0.9, "High", cap=0.5)])
    try:
        for row in (_listed(client)[AGENT], _detail(client, AGENT)):
            assert (row["score"], row["category"], row["trust_cap"]) == (0.5, "medium", 0.5)
            assert row["dominant_signal"] == "manual_override"
    finally:
        client.close()


def test_a_capped_score_is_banded_with_the_namespaces_own_threshold(monkeypatch) -> None:
    """trust_threshold 0.9 moves the high band to 0.9 (calculator _tiers): a cap of 0.75 is medium there."""
    store = _Store({f"agent_trust_override:{AGENT}": "0.75"}, ns_settings={"payments": {"trust_threshold": 0.9}})
    client = _client(monkeypatch, store, [_registry(AGENT, 0.95, "High")])
    try:
        row = _listed(client)[AGENT]
        assert (row["score"], row["category"]) == (0.75, "medium")
    finally:
        client.close()


def test_an_agent_with_no_control_reads_as_before(monkeypatch) -> None:
    store = _Store({f"trust:{OTHER}": _snapshot(0.82, "High")})
    client = _client(monkeypatch, store, [_registry(OTHER, 0.6, "Medium")])
    try:
        row = _listed(client)[OTHER]
        assert (row["frozen"], row["trust_cap"], row["score"], row["category"]) == (False, None, 0.82, "high")
    finally:
        client.close()


# --- the admin write never stores a cap or a lift as the agent's score -----------------------------------


class _AdminConn:
    async def execute(self, _stmt, _params=None):
        return SimpleNamespace(mappings=lambda: SimpleNamespace(first=lambda: None), scalar=lambda: 1, rowcount=1)

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def invalidate(self) -> None:
        return None


class _AdminDb:
    async def connect(self):
        return _AdminConn()


def test_a_cap_or_a_lift_does_not_write_a_displayed_score(monkeypatch) -> None:
    before = _snapshot(0.455, "Medium")
    store = _Store({f"trust:{AGENT}": before})
    client = _client(monkeypatch, store, [_registry(AGENT, 0.455, "Medium")])
    client.app.dependency_overrides[get_admin_db] = lambda: _AdminDb()
    try:
        resp = client.put(f"/api/v1/agents/{AGENT}/trust", json={"score": 0.8}, headers=_hdr())
        assert resp.status_code == 200, resp.text
        # The answer is the control in force, not a score.
        assert resp.json() == {"spiffe_id": AGENT, "frozen": False, "trust_cap": 0.8}
        assert store.values[f"trust:{AGENT}"] == before
        row = _listed(client)[AGENT]
        assert (row["score"], row["category"], row["trust_cap"]) == (0.455, "medium", 0.8)

        resp = client.put(f"/api/v1/agents/{AGENT}/trust", json={"score": 1.0}, headers=_hdr())
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"spiffe_id": AGENT, "frozen": False, "trust_cap": None}
        assert store.values[f"trust:{AGENT}"] == before
        assert f"agent_trust_override:{AGENT}" not in store.values
    finally:
        client.close()


def test_a_freeze_answers_with_the_control_and_reads_frozen(monkeypatch) -> None:
    store = _Store({f"trust:{AGENT}": _snapshot(0.455, "Medium")})
    client = _client(monkeypatch, store, [_registry(AGENT, 0.455, "Medium")])
    client.app.dependency_overrides[get_admin_db] = lambda: _AdminDb()
    try:
        resp = client.put(f"/api/v1/agents/{AGENT}/trust", json={"score": 0}, headers=_hdr())
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"spiffe_id": AGENT, "frozen": True, "trust_cap": None}
        # The 30 s display row expires; the registry snapshot still predates the freeze.
        del store.values[f"trust:{AGENT}"]
        row = _listed(client)[AGENT]
        assert (row["frozen"], row["score"], row["category"]) == (True, 0.0, "frozen")
    finally:
        client.close()
