# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Part B — draft/version retention unit tests, incl. the SAFETY INVARIANT: version-prune NEVER deletes the
current-enforcing version, and draft GC only ever touches the dedicated (non-enforcing) intent_drafts table."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from norviq.api.retention import draft_expiry, enforce_draft_cap, gc_expired_drafts
from norviq.config import settings


def test_draft_expiry_is_short_for_test_classes_and_normal_for_real():
    now = datetime(2026, 7, 5, tzinfo=timezone.utc)
    # a synthetic/test class expires in the fast (test) window…
    test_exp = draft_expiry("wave4e2e-probe", now)
    assert test_exp == now + timedelta(hours=settings.draft_ttl_test_hours)
    # …a real class in the normal window.
    real_exp = draft_expiry("customer-support", now)
    assert real_exp == now + timedelta(days=settings.draft_ttl_days)
    assert test_exp < real_exp


class _Result:
    def __init__(self, rowcount=0):
        self.rowcount = rowcount


class _RecordingSession:
    """Captures executed SQL + params so we can assert the retention queries are correctly SCOPED (drafts only,
    expired only) without a real DB."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    async def execute(self, stmt, params=None):
        self.calls.append((str(stmt), dict(params or {})))
        return _Result(rowcount=1)

    async def commit(self):
        pass


async def test_gc_only_deletes_expired_drafts_never_policies():
    sess = _RecordingSession()
    n = await gc_expired_drafts(sess, "default")
    assert n == 1
    sql, params = sess.calls[0]
    # ONLY the intent_drafts table, ONLY expired rows — never `policies`/`policy_versions`.
    assert "DELETE FROM intent_drafts" in sql
    assert "expires_at IS NOT NULL AND expires_at <" in sql
    assert "policies" not in sql.replace("intent_drafts", "")  # no policy/version table touched
    assert params["ns"] == "default"


async def test_cap_evicts_oldest_beyond_the_configured_ceiling():
    sess = _RecordingSession()
    await enforce_draft_cap(sess, "default")
    sql, params = sess.calls[0]
    assert "DELETE FROM intent_drafts" in sql
    assert "ORDER BY created_at DESC OFFSET :cap" in sql  # keep newest `cap`, drop the rest
    assert params["cap"] == settings.draft_cap_per_namespace


# ---- SAFETY INVARIANT: version-prune never drops the current-enforcing version ---------------------------

class _Row:
    def __init__(self, d):
        self._d = d

    def mappings(self):
        return self

    def first(self):
        return self._d


class _PruneConn:
    def __init__(self, current_version):
        self._current = current_version
        self.deletes: list[tuple[str, dict]] = []

    async def execute(self, stmt, params=None):
        sql = str(stmt)
        if sql.strip().upper().startswith("SELECT"):
            return _Row({"id": "pid-1", "version": self._current})
        # a DELETE
        self.deletes.append((sql, dict(params or {})))
        return _Result(rowcount=3)


class _PruneBegin:
    def __init__(self, conn):
        self._c = conn

    async def __aenter__(self):
        return self._c

    async def __aexit__(self, *_a):
        return False


class _PruneEngine:
    def __init__(self, conn):
        self._c = conn

    def begin(self):
        return _PruneBegin(self._c)


async def test_prune_versions_never_touches_the_current_enforcing_version():
    """The single most important retention gate: the DELETE must exclude the current version (version <> :current),
    and the current version passed to it must equal the policies.version. If this guard is ever removed, retention
    could drop the version backing the enforcing state — this test fails."""
    from norviq.engine.policy_loader import PolicyLoader

    class _Cache:
        _pool = None

    class _Eval:
        def bind_loader(self, _l):
            pass

    loader = PolicyLoader(cache=_Cache(), evaluator=_Eval())
    conn = _PruneConn(current_version=42)
    loader._db = _PruneEngine(conn)

    pruned = await loader.prune_versions("default", "customer-support")
    assert pruned == 3
    assert len(conn.deletes) == 1
    sql, params = conn.deletes[0]
    assert "DELETE FROM policy_versions" in sql
    assert "version <> :current" in sql            # ← the safety guard
    assert params["current"] == 42                 # ← equals the current-enforcing version, so it is NEVER deleted
    assert params["keep"] == settings.policy_version_keep_count


# --- RETENTION: the unified background pruner's new table sweeps (SQL scoping + knob gating) --------


class _PrunerSession(_RecordingSession):
    async def rollback(self):
        pass


def _factory_for(sess):
    async def _factory():
        yield sess
    return _factory


async def test_pruner_asset_graph_keeps_newest_n_and_fk_referenced_rows(monkeypatch):
    from norviq.api.audit_retention import RetentionPruner

    sess = _PrunerSession()
    n = await RetentionPruner(_factory_for(sess))._prune_asset_graph(sess)
    assert n == 1
    sql, params = sess.calls[0]
    # newest-N per namespace, and NEVER a row attack_paths still references (FK has no cascade).
    assert "DELETE FROM asset_graph" in sql
    assert "PARTITION BY namespace ORDER BY built_at DESC" in sql
    assert "rn > :keep" in sql
    assert "NOT IN (SELECT DISTINCT graph_id FROM attack_paths)" in sql
    assert params["keep"] == settings.graph_snapshot_keep_per_namespace


async def test_pruner_registry_and_coverage_scoped_and_disable_knobs(monkeypatch):
    from norviq.api.audit_retention import RetentionPruner

    p = RetentionPruner(_factory_for(_PrunerSession()))
    sess = _PrunerSession()
    assert await p._prune_agent_registry(sess) == 1
    assert "DELETE FROM agent_registry WHERE last_seen < :cutoff" in sess.calls[0][0]
    sess2 = _PrunerSession()
    assert await p._prune_coverage_snapshots(sess2) == 1
    assert "DELETE FROM mitre_coverage_snapshots WHERE timestamp_utc < :cutoff" in sess2.calls[0][0]
    # <=0 disables each window: no SQL executed at all.
    monkeypatch.setattr(settings, "agent_registry_retention_days", 0)
    monkeypatch.setattr(settings, "coverage_snapshot_retention_days", 0)
    monkeypatch.setattr(settings, "graph_snapshot_keep_per_namespace", 0)
    for fn in (p._prune_agent_registry, p._prune_coverage_snapshots, p._prune_asset_graph):
        quiet = _PrunerSession()
        assert await fn(quiet) == 0 and quiet.calls == []


async def test_prune_once_isolates_a_failing_step(monkeypatch):
    """One table's prune blowing up must not stop the others (per-step session + error isolation)."""
    from norviq.api.audit_retention import RetentionPruner

    p = RetentionPruner(_factory_for(_PrunerSession()))

    async def _boom(_session):
        raise RuntimeError("table on fire")

    # Sabotage one step; every OTHER step still runs and reports its count.
    monkeypatch.setattr(p, "_prune_audit", _boom)
    counts = await p.prune_once()
    assert counts["audit_log"] == 0                    # isolated failure -> 0, not an exception
    assert counts["intent_drafts"] == 1                # drafts GC still ran
    assert counts["agent_registry"] == 1               # registry sweep still ran
    assert counts["asset_graph"] == 1                  # graph prune still ran
