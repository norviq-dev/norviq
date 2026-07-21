# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""FAIL-ON-BUG regressions for the agents-dashboard reconciliation group.

/agents synthetic flag: every ``/agents`` row must carry a ``synthetic`` boolean (via the ONE
    shared ``is_synthetic_identity`` classifier) — true for probe/eval/test identities, false for real
    ones — so the Overview trust donut + Agent Monitor can exclude exactly the identities the asset/attack
    graph already hides.

list_agents perf: ``list_agents`` must scope the Redis SCAN to the caller's namespace
    (``trust:spiffe://*/ns/<ns>/*``) instead of scanning the whole cluster-wide ``trust:*`` keyspace and
    filtering in Python, and must BATCH the per-agent reads via MGET instead of a GET per agent. A tenant
    listing its 3 agents must not traverse another tenant's 20 keys, and must not issue N sequential GETs.

Overview reconciliation: ``/audit/top-blocked`` and ``/audit/volume`` must exclude red-team
    framework events + synthetic/probe identities — the SAME real-traffic population the headline KPI
    (``/audit/stats``) and Compliance/MITRE already count — so the two Overview widgets stop contradicting
    their own headline.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from types import SimpleNamespace

import jwt
from fastapi.testclient import TestClient

import norviq.api.routers.agents as agents_mod
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.config import settings
from norviq.sdk.core.trust import TrustScore

# ---- identities -------------------------------------------------------------------------------------
REAL_AGENT = "spiffe://norviq/ns/alpha/sa/customer-support"        # real product class -> synthetic False
PROBE_AGENT = "spiffe://norviq/ns/alpha/sa/allowlist-probe-42"     # prefix match       -> synthetic True
SCORER_AGENT = "spiffe://norviq/ns/alpha/sa/scorer"                # exact eval class    -> synthetic True


def _token(role: str = "admin", namespace: str | None = None) -> str:
    # The HS256 validator requires an `exp` claim (norviq/api/auth.py _validate_token).
    claims: dict[str, object] = {
        "sub": "u",
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    if namespace is not None:
        claims["namespace"] = namespace
    return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")


def _hdr(role: str = "admin", namespace: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(role, namespace)}"}


# ==== /agents (list scoping + synthetic flag) =======================================================


class _CountingCache:
    """Redis-double that emulates SCAN MATCH globbing + MGET, and counts commands so a test can assert
    the SCAN is namespace-scoped and the per-agent reads are batched. It also backs
    the legacy per-agent ``get_trust`` path so the pre-fix code runs (and trips the assertion) rather
    than erroring — proving the test is fail-on-bug, not fake-incompatible."""

    def __init__(self, trust_json: dict[str, str]) -> None:
        self._trust = trust_json  # keyed by spiffe_id (no "trust:" prefix)
        self.scanned = 0
        self.mget_calls = 0
        self.get_trust_calls = 0
        self._redis = object()

    def _client(self) -> "_CountingCache":
        return self

    async def scan_iter(self, match: str):
        # Emulate real Redis SCAN MATCH: only keys matching the glob reach the client.
        for sid in self._trust:
            key = f"trust:{sid}"
            if fnmatch(key, match):
                self.scanned += 1
                yield key

    async def mget(self, keys: list[str]) -> list[str | None]:
        self.mget_calls += 1
        out: list[str | None] = []
        for k in keys:
            if k.startswith("trust:"):
                out.append(self._trust.get(k[len("trust:"):]))
            else:  # trustcalc:* — none seeded, falls back to trust.factors
                out.append(None)
        return out

    async def get(self, key: str) -> str | None:
        return None  # no trustcalc:* payloads

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:  # legacy per-agent path (pre-fix)
        self.get_trust_calls += 1
        raw = self._trust.get(spiffe_id)
        return TrustScore.model_validate_json(raw) if raw else None


def _trust_blob(category: str = "High", score: float = 0.9) -> str:
    return TrustScore(score=score, category=category).model_dump_json()


def _agents_app(cache: _CountingCache, monkeypatch) -> TestClient:
    app = create_app()
    app.state.cache = cache

    async def _no_last_seen(_ns):
        return {}

    async def _no_registry(_ns):
        return []

    monkeypatch.setattr(agents_mod, "_registry_last_seen", _no_last_seen)  # avoid a real DB round-trip
    monkeypatch.setattr(agents_mod, "_agents_from_registry", _no_registry)  # roster union reads it too
    return TestClient(app)


def test_agents_row_carries_synthetic_flag(monkeypatch) -> None:
    """FAIL-ON-BUG: a real identity is synthetic=False; a probe and an eval-scorer are
    synthetic=True."""
    cache = _CountingCache({
        REAL_AGENT: _trust_blob("High"),
        PROBE_AGENT: _trust_blob("Low"),
        SCORER_AGENT: _trust_blob("Medium"),
    })
    client = _agents_app(cache, monkeypatch)
    try:
        resp = client.get("/api/v1/agents?namespace=alpha", headers=_hdr(role="admin"))
        assert resp.status_code == 200
        by_id = {row["spiffe_id"]: row for row in resp.json()}
        assert set(by_id) == {REAL_AGENT, PROBE_AGENT, SCORER_AGENT}
        # The key must exist (pre-fix rows omit it) AND classify correctly.
        assert by_id[REAL_AGENT]["synthetic"] is False
        assert by_id[PROBE_AGENT]["synthetic"] is True
        assert by_id[SCORER_AGENT]["synthetic"] is True
    finally:
        client.close()


def test_list_agents_scan_is_namespace_scoped_and_batched(monkeypatch) -> None:
    """FAIL-ON-BUG: seed 20 keys in ns 'other' + 3 in ns 'alpha'; a request scoped to 'alpha'
    must (a) only SCAN the 3 alpha keys (Redis-side MATCH, not a full-keyspace walk) and (b) batch the
    reads via MGET, not one GET per agent."""
    seed: dict[str, str] = {
        f"spiffe://norviq/ns/other/sa/svc-{i}": _trust_blob("High") for i in range(20)
    }
    alpha_ids = [
        "spiffe://norviq/ns/alpha/sa/customer-support",
        "spiffe://norviq/ns/alpha/sa/deploy-bot",
        "spiffe://norviq/ns/alpha/sa/report-runner",
    ]
    for sid in alpha_ids:
        seed[sid] = _trust_blob("Medium")
    cache = _CountingCache(seed)
    client = _agents_app(cache, monkeypatch)
    try:
        resp = client.get("/api/v1/agents?namespace=alpha", headers=_hdr(role="admin"))
        assert resp.status_code == 200
        assert {row["spiffe_id"] for row in resp.json()} == set(alpha_ids)
        # (a) scoped SCAN: only the 3 alpha keys ever reached the client — NOT all 23.
        assert cache.scanned == len(alpha_ids), f"scan was not ns-scoped: scanned={cache.scanned}"
        # (b) batched reads: two MGETs (trust: + trustcalc:), zero per-agent GET_TRUST round-trips.
        assert cache.mget_calls == 2, f"reads not batched: mget_calls={cache.mget_calls}"
        assert cache.get_trust_calls == 0, f"still doing per-agent GETs: {cache.get_trust_calls}"
    finally:
        client.close()


IDLE_AGENT = "spiffe://norviq/ns/alpha/sa/report-gen"  # governed but quiet -> cache entry aged out


def _registry_row(sid: str, score: float, category: str) -> dict:
    return {
        "spiffe_id": sid,
        "namespace": agents_mod._namespace_from_spiffe(sid),
        "agent_class": agents_mod._class_from_spiffe(sid),
        "last_seen": None,
        "score": score,
        "category": category.lower(),
        "violation_count": 0,
        "signals": {},
        "dominant_signal": "",
        "recommendation": "",
        "synthetic": False,
    }


def test_list_agents_unions_registry_roster_with_live_cache(monkeypatch) -> None:
    """FAIL-ON-BUG: a quiet-but-governed agent (its short-TTL trust cache entry has aged out) must STILL
    appear in the list — the view is the full registry roster with live trust overlaid where the cache is
    warm. Pre-fix the registry was consulted only when the cache was 100% empty, so with even one warm key
    the idle agent vanished from the Agent Monitor."""
    cache = _CountingCache({REAL_AGENT: _trust_blob("High", 0.9)})  # only REAL_AGENT is warm
    app = create_app()
    app.state.cache = cache

    async def _no_last_seen(_ns):
        return {}

    async def _roster(_ns):
        # REAL_AGENT carries a STALE registry score (Medium); IDLE_AGENT is cache-cold (Low).
        return [_registry_row(REAL_AGENT, 0.5, "Medium"), _registry_row(IDLE_AGENT, 0.3, "Low")]

    monkeypatch.setattr(agents_mod, "_registry_last_seen", _no_last_seen)
    monkeypatch.setattr(agents_mod, "_agents_from_registry", _roster)
    client = TestClient(app)
    try:
        resp = client.get("/api/v1/agents?namespace=alpha", headers=_hdr(role="admin"))
        assert resp.status_code == 200
        by_id = {row["spiffe_id"]: row for row in resp.json()}
        # Both are listed — the idle agent no longer vanishes just because another agent is warm.
        assert set(by_id) == {REAL_AGENT, IDLE_AGENT}
        # The warm agent shows the LIVE cache score (0.9/high), not the stale registry value (0.5/medium).
        assert by_id[REAL_AGENT]["score"] == 0.9 and by_id[REAL_AGENT]["category"] == "high"
        # The idle agent keeps its last-known registry score instead of disappearing.
        assert by_id[IDLE_AGENT]["score"] == 0.3 and by_id[IDLE_AGENT]["category"] == "low"
    finally:
        client.close()


# ==== /audit/top-blocked + /audit/volume reconciliation =============================================


class _AuditResult:
    """Result double supporting BOTH the pre-fix (``.all()`` over grouped rows) and post-fix
    (``.scalars().all()`` over full ORM rows) access patterns, so the test fails on the OLD code via a
    clean assertion instead of an AttributeError."""

    def __init__(self, rows: list[SimpleNamespace]) -> None:
        self._rows = rows

    def all(self) -> list[SimpleNamespace]:
        return self._rows

    def scalars(self) -> SimpleNamespace:
        return SimpleNamespace(all=lambda: self._rows)


class _AuditSession:
    def __init__(self, rows: list[SimpleNamespace]) -> None:
        self._rows = rows

    async def execute(self, _stmt) -> _AuditResult:
        return _AuditResult(self._rows)

    async def close(self) -> None:
        return None


def _rec(tool: str, framework: str, agent_class: str, decision: str = "block") -> SimpleNamespace:
    return SimpleNamespace(
        tool_name=tool,
        decision=decision,
        framework=framework,
        agent_class=agent_class,
        namespace="alpha",
        count=1,  # lets the PRE-FIX grouped-query path run (row.count) so failure is a clean assertion
        timestamp_utc=datetime(2026, 7, 16, 10, 30, tzinfo=timezone.utc),
    )


def _audit_app(rows: list[SimpleNamespace]) -> TestClient:
    app = create_app()

    async def _override():
        yield _AuditSession(rows)

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


# One real block, one red-team block, one synthetic-probe block — all on distinct tools, same hour.
_MIXED = [
    _rec("db.query", framework="sidecar", agent_class="customer-support"),  # real -> kept
    _rec("shell.exec", framework="redteam", agent_class="attacker"),        # red-team -> excluded
    _rec("net.exfil", framework="sidecar", agent_class="allowlist-probe-9"),  # synthetic -> excluded
]


def test_top_blocked_excludes_redteam_and_synthetic() -> None:
    """FAIL-ON-BUG: only the real block survives; the red-team + synthetic tools must not appear."""
    client = _audit_app(_MIXED)
    try:
        resp = client.get("/api/v1/audit/top-blocked", headers=_hdr(role="admin"))
        assert resp.status_code == 200
        body = resp.json()
        tools = {row["tool_name"] for row in body}
        assert tools == {"db.query"}, f"top-blocked leaked excluded traffic: {tools}"
    finally:
        client.close()


def test_volume_excludes_redteam_and_synthetic() -> None:
    """FAIL-ON-BUG: the volume chart counts only the real block (1), not all three (3)."""
    client = _audit_app(_MIXED)
    try:
        resp = client.get("/api/v1/audit/volume", headers=_hdr(role="admin"))
        assert resp.status_code == 200
        total_block = sum(int(bucket.get("block", 0)) for bucket in resp.json())
        assert total_block == 1, f"volume did not exclude red-team/synthetic: block={total_block}"
    finally:
        client.close()
