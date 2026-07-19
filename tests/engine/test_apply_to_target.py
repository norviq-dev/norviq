# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Part C regression: ``PolicyLoader.apply_to_target`` must load the applied policy into the READ PATH
(``loader._policies``, which ``_collect_candidates`` consults) and persist it at the target — not the
evaluator's own unread ``_policies`` dict. The old apply wrote the unread dict + never persisted the target,
so ``/apply`` returned 200 but ``/evaluate`` at the target stayed ``no_policy_loaded`` (a 200 that did not
enforce). These fakes need no Redis/DB so the regression runs everywhere and fails if apply ever stops
reaching the read path."""

from __future__ import annotations

from datetime import datetime, timezone

from norviq.engine.policy_loader import PolicyLoader, PolicyVersion

_FAKE_APPLIED_AT = datetime(2026, 1, 1, tzinfo=timezone.utc)


class _Row:
    def __init__(self, version: int):
        self._v = version

    def mappings(self):
        return self

    def one(self):
        # HA C1 fix: create()'s upsert and apply_to_target()'s mode-change UPDATE now both
        # `RETURNING ... applied_at` (the DB-side NOW() stamp) — the fake must carry that key too,
        # matching what real Postgres would return.
        return {"id": "pid", "version": self._v, "applied_at": _FAKE_APPLIED_AT}


class _FakeConn:
    def __init__(self, version: int):
        self._v = version

    async def execute(self, *_a, **_k):
        return _Row(self._v)


class _FakeBegin:
    def __init__(self, version: int):
        self._v = version

    async def __aenter__(self):
        return _FakeConn(self._v)

    async def __aexit__(self, *_a):
        return False


class _FakeEngine:
    """Stands in for the async DB engine — create()'s upsert returns an ever-incrementing version."""

    def __init__(self):
        self.version = 0

    def begin(self):
        self.version += 1
        return _FakeBegin(self.version)


class _FakeCache:
    _pool = None  # no Redis → create()/invalidate take the pool-less branch

    async def delete_policy(self, *_a, **_k):
        pass

    async def set_policy(self, *_a, **_k):
        pass

    async def invalidate_eval_scope(self, *_a, **_k):
        pass

    async def publish_policy_event(self, *_a, **_k):
        pass


class _FakeEvaluator:
    def __init__(self):
        self.loaded: list[tuple[str, str, str]] = []

    def bind_loader(self, loader):
        self._loader = loader

    def load_policy(self, ns, cls, rego, priority=100):
        self.loaded.append((ns, cls, rego))


def _loader() -> PolicyLoader:
    loader = PolicyLoader(cache=_FakeCache(), evaluator=_FakeEvaluator())
    loader._db = _FakeEngine()  # bypass the real DB engine
    return loader


_REGO = 'package norviq.intent.lc\ndefault decision = "block"\nrule_id = "lc_block"'


async def test_apply_to_a_new_target_populates_the_loader_read_path():
    """THE regression: after apply, the TARGET key must be in loader._policies (what _collect_candidates reads).
    On the old apply this dict stayed empty for the target → /evaluate returned no_policy_loaded."""
    loader = _loader()
    loader._policies = {"srcns:agent": {"rego": _REGO, "priority": 100}}  # a saved source policy

    result = await loader.apply_to_target("srcns", "agent", "dstns", "agent")

    assert result is not None
    version, created = result
    assert created is True                                   # a fresh target → a new version was persisted
    assert loader.get_current("dstns", "agent") == _REGO     # ← loaded into the READ path
    assert ("dstns", "agent", _REGO) in loader._evaluator.loaded


async def test_reapply_identical_content_does_not_bump_the_version():
    """Same-namespace UI re-apply (target already byte-identical) must re-affirm the read path WITHOUT creating
    a new version — preserving the no-version-inflation-on-re-apply invariant."""
    loader = _loader()
    loader._policies = {"ns:agent": {"rego": _REGO, "priority": 100}}

    result = await loader.apply_to_target("ns", "agent", "ns", "agent")

    assert result is not None
    _version, created = result
    assert created is False                                  # no new version
    assert loader.get_current("ns", "agent") == _REGO        # still enforcing
    assert loader._db.version == 0                           # create()/DB was never invoked


async def test_apply_with_no_source_returns_none():
    """Nothing saved to apply → None (the router turns this into a 404, not a false 200)."""
    loader = _loader()
    assert await loader.apply_to_target("nope", "agent", "dst", "agent") is None


async def test_reapply_same_rego_different_mode_persists_mode_without_version_bump():
    """FIX A regression: the editor's "Enforcement -> audit" change with byte-identical rego previously hit the
    same-rego branch, which DISCARDED the caller's enforcement_mode and re-derived the OLD one from the existing
    entry — never updating the DB column and never publishing a propagation event, so list_policies kept
    reporting the stale mode (a 200 that lied). Now a genuine mode change in this branch must PERSIST the new
    mode (a DB UPDATE, since create()/DB is otherwise skipped for a same-rego reapply) WITHOUT bumping the
    version — the rego itself is unchanged, so no-version-inflation-on-reapply still holds."""
    loader = _loader()
    loader._policies = {"ns:agent": {"rego": _REGO, "priority": 100, "enforcement_mode": "block"}}
    loader._versions = {
        "ns:agent": [PolicyVersion(version=1, rego_source=_REGO, priority=100, enforcement_mode="block")]
    }

    result = await loader.apply_to_target("ns", "agent", "ns", "agent", enforcement_mode="audit")

    assert result is not None
    _version, created = result
    assert created is False                                                    # rego unchanged → no new version
    assert loader.get_entry("ns", "agent")["enforcement_mode"] == "audit"      # NEW mode persisted in memory
    assert loader._db.version == 1                                             # the UPDATE actually ran once
    # rollback-to-current must not resurrect the stale mode:
    assert loader._versions["ns:agent"][-1].enforcement_mode == "audit"


async def test_reapply_same_rego_returns_true_latest_version_not_history_count():
    """Regression: with pruned history (cap 10 / 90d), len(get_versions(...)) != the real latest version
    number. A same-rego reapply branch that returns ``len(self.get_versions(...)) or 1`` as
    ``current_version`` understates it once a class passes 10 lifetime versions, which flows into
    apply_policy's response -> UI expectedVersion. The verify-poll compares that against list_policies'
    CORRECT ``versions[-1].version``, so a class with >10 lifetime versions could never converge -> permanent
    false "STALLED". current_version must be ``versions[-1].version``, matching list_policies' fix
    (norviq/api/routers/policies.py:227)."""
    loader = _loader()
    loader._policies = {"ns:agent": {"rego": _REGO, "priority": 100, "enforcement_mode": "block"}}
    # Simulate pruned history: only 3 snapshots retained, but the class has lived to real version 15.
    loader._versions = {
        "ns:agent": [
            PolicyVersion(version=13, rego_source=_REGO, priority=100, enforcement_mode="block"),
            PolicyVersion(version=14, rego_source=_REGO, priority=100, enforcement_mode="block"),
            PolicyVersion(version=15, rego_source=_REGO, priority=100, enforcement_mode="block"),
        ]
    }

    result = await loader.apply_to_target("ns", "agent", "ns", "agent", enforcement_mode="audit")

    assert result is not None
    current_version, created = result
    assert created is False
    assert current_version == 15                 # the TRUE latest version, not len(versions) == 3
    assert loader._versions["ns:agent"][-1].enforcement_mode == "audit"


async def test_reapply_same_rego_same_mode_is_a_true_noop():
    """A genuine reaffirm (mode unchanged) must stay a true no-op — no DB write, matching the pre-existing
    no-version-inflation invariant covered by test_reapply_identical_content_does_not_bump_the_version above."""
    loader = _loader()
    loader._policies = {"ns:agent": {"rego": _REGO, "priority": 100, "enforcement_mode": "audit"}}

    result = await loader.apply_to_target("ns", "agent", "ns", "agent", enforcement_mode="audit")

    assert result is not None
    _version, created = result
    assert created is False
    assert loader.get_entry("ns", "agent")["enforcement_mode"] == "audit"
    assert loader._db.version == 0  # no UPDATE, no create() — a genuine no-op
