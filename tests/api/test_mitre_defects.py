# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Fail-on-bug regressions for the Compliance/MITRE defect group:

    - remediation draft_id must be a SEED-INDEPENDENT pure function of its content, so the deeplink
      resolves on a second replica (never a PYTHONHASHSEED-salted builtin hash()).
    - the hourly coverage-snapshot throttle must be single-writer under concurrent GETs, so a racy
      read-then-insert cannot double the trend points.
    - batch generate must compute the loop-invariant coverage ONCE, not 2*N times.
    - each technique/control must expose PER-RULE blocked counts, not the technique-wide total
      repeated on every evidence row (which misattributes all blocks to each rule).

Each test fails against buggy code and passes on the correct code. The live-concurrency test is
skipped unless a Postgres is reachable (NRVQ_PG_URL, else the local dev default on :5433)."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.models import MitreCoverageSnapshot
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.api.routers import mitre

_REPO_ROOT = Path(__file__).resolve().parents[2]

# A technique the atlas mapping covers with exactly two rules — the misattribution case.
_T = "AML.T0054"
_RULE_A = "deny_shell_execution"
_RULE_B = "llm01_prompt_injection"


# --------------------------------------------------------------------------------------------------
# test doubles (no live DB) — reshape base (rule_id, decision, count) rows per query, like test_mitre_overlay
# --------------------------------------------------------------------------------------------------

class _StubResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return self._rows


class _StubSession:
    """Stub async session. Records every executed statement + added object so tests can assert wiring."""

    def __init__(self, rows, cls="customer-support"):
        self._rows = rows
        self._cls = cls
        self.executed: list[str] = []
        self.added: list[object] = []
        self.scalar_return = None

    async def execute(self, stmt, *a, **k):
        sql = str(stmt)
        self.executed.append(sql)
        if "pg_advisory_xact_lock" in sql:
            return _StubResult([(1,)])
        # _blocked_by_rule_class filters WHERE decision IN (block/escalate) and now selects
        # (rule_id, agent_class, framework, count) — matched by its decision filter, which the
        # sibling activity query never has.
        if "decision IN" in sql:
            return _StubResult([(rid, self._cls, "", n) for (rid, dec, n) in self._rows if dec in ("block", "escalate")])
        # _activity_by_rule → (rule_id, decision, agent_class, framework, count), no decision filter
        return _StubResult([(rid, dec, self._cls, "", n) for (rid, dec, n) in self._rows])

    async def scalar(self, *a, **k):
        return self.scalar_return

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        return None


class _State:  # tiny attribute bag standing in for starlette State
    pass


class _Loader:
    def __init__(self, rego: str):
        self._policies = {"default:__baseline__": {"rego": rego, "priority": 100}}


class _App:
    def __init__(self, loader):
        self.state = _State()
        self.state.loader = loader


class _Request:
    def __init__(self, loader):
        self.app = _App(loader)
        self.state = _State()


def _rego_covering_both() -> str:
    return f'blocks["{_RULE_A}"] {{ x }} blocks["{_RULE_B}"] {{ y }}'


# --------------------------------------------------------------------------------------------------
# Deterministic, seed-independent draft id
# --------------------------------------------------------------------------------------------------

def test_def031_stable_draft_id_matches_sha256_and_format():
    import hashlib

    got = mitre._stable_draft_id("atlas", "AML.T0051", "default", "payments")
    expected = "dmitre" + hashlib.sha256(b"atlas|AML.T0051|default|payments", usedforsecurity=False).hexdigest()[:11]
    assert got == expected
    assert got.startswith("dmitre") and len(got) == 17  # fits IntentDraft.id String(64)


def _subprocess_out(code: str, seed: int) -> str:
    env = dict(os.environ, PYTHONHASHSEED=str(seed))
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          env=env, cwd=str(_REPO_ROOT))
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def test_def031_stable_draft_id_is_seed_independent():
    # The production id computed under two different PYTHONHASHSEED values MUST match — the property the
    # multi-replica deeplink relies on (each replica is a separate process with its own seed).
    code = ("import sys;"
            "from norviq.api.routers.mitre import _stable_draft_id;"
            "sys.stdout.write(_stable_draft_id('atlas','AML.T0051','default','payments'))")
    a = _subprocess_out(code, 1)
    b = _subprocess_out(code, 2)
    assert a and a == b


def test_def031_old_builtin_hash_was_seed_dependent():
    # Documents the root cause: `abs(hash(tuple)) % 10**11` diverges across seeds.
    # (Runs identically on old + new code — it exercises the builtin, not the module — proving the fix's need.)
    code = ("import sys;"
            "t=('atlas','AML.T0051','default','payments');"
            "sys.stdout.write(str(abs(hash(t)) % (10**11)))")
    assert _subprocess_out(code, 1) != _subprocess_out(code, 2)


# --------------------------------------------------------------------------------------------------
# Single-writer-per-hour snapshot throttle
# --------------------------------------------------------------------------------------------------

def test_def032_snapshot_has_partial_unique_hour_index():
    idx = next((ix for ix in MitreCoverageSnapshot.__table__.indexes
                if ix.name == "uq_mitre_snap_hourly"), None)
    assert idx is not None, "missing single-writer-per-hour index on mitre_coverage_snapshots"
    assert idx.unique, "the hourly snapshot index must be UNIQUE to dedup concurrent inserts"
    exprs = " ".join(str(e) for e in idx.expressions)
    assert "namespace" in exprs and "framework" in exprs and "date_trunc" in exprs
    # scoped to snapshots so evidence-pack exports (several per hour) stay unconstrained
    assert "snapshot" in str(idx.dialect_options["postgresql"].get("where"))


async def test_def032_record_snapshot_serializes_with_advisory_lock():
    cov = {"enforced": 1, "enforceable_total": 2, "coverage_pct": 50, "blocked": 3}

    # no existing snapshot this hour → it inserts, but ONLY after taking the advisory lock
    sess = _StubSession([])
    sess.scalar_return = 0
    await mitre._record_snapshot(sess, "team-a", cov, "atlas")
    assert any("pg_advisory_xact_lock" in s for s in sess.executed), \
        "_record_snapshot must take a transaction-scoped advisory lock before the read-then-insert"
    assert len(sess.added) == 1

    # an existing row this hour → throttle still short-circuits (no duplicate)
    sess2 = _StubSession([])
    sess2.scalar_return = 1
    await mitre._record_snapshot(sess2, "team-a", cov, "atlas")
    assert sess2.added == []


def _async_pg_url() -> str:
    raw = (os.getenv("NRVQ_PG_URL")
           or "postgresql://norviq:norviq_local_dev@127.0.0.1:5433/norviq?sslmode=disable")
    return raw.replace("postgresql://", "postgresql+asyncpg://").split("?")[0]


async def test_def032_record_snapshot_blocks_on_held_advisory_lock_live():
    """The real proof: while another session holds the SAME hour lock, _record_snapshot must BLOCK (it
    serializes), then insert exactly one row once the lock frees. Skips if Postgres is unreachable."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_async_pg_url(), pool_size=2, max_overflow=3)
    try:
        async with engine.connect() as c:
            await c.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        await engine.dispose()
        pytest.skip(f"Postgres unreachable: {exc}")

    Session = async_sessionmaker(engine, expire_on_commit=False)
    ns = f"deftest032-{uuid.uuid4().hex[:8]}"
    cov = {"enforced": 1, "enforceable_total": 2, "coverage_pct": 50, "blocked": 3}
    hour_start = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    key = mitre._snapshot_lock_key(mitre._ns_key(ns), "atlas", hour_start)

    holder = Session()
    try:
        # hold the same advisory xact lock in an open transaction
        await holder.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": key})

        worker = Session()
        try:
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(mitre._record_snapshot(worker, ns, cov, "atlas"), timeout=2.0)
        finally:
            await worker.rollback()
            await worker.close()

        await holder.rollback()  # release the lock

        w2 = Session()
        try:
            await mitre._record_snapshot(w2, ns, cov, "atlas")
        finally:
            await w2.close()

        async with Session() as chk:
            n = await chk.scalar(
                text("SELECT count(*) FROM mitre_coverage_snapshots WHERE namespace=:ns AND kind='snapshot'"),
                {"ns": ns},
            )
            assert n == 1, f"expected exactly one serialized snapshot, got {n}"
            await chk.execute(text("DELETE FROM mitre_coverage_snapshots WHERE namespace=:ns"), {"ns": ns})
            await chk.commit()
    finally:
        await holder.close()
        await engine.dispose()


# --------------------------------------------------------------------------------------------------
# Batch computes the loop-invariant coverage once
# --------------------------------------------------------------------------------------------------

async def test_def033_batch_computes_coverage_once(monkeypatch):
    req = _Request(_Loader(_rego_covering_both()))
    sess = _StubSession([(_RULE_A, "block", 25), (_RULE_B, "block", 15)])

    calls = {"n": 0}
    real = mitre._compute_coverage

    async def _counting(*a, **k):
        calls["n"] += 1
        return await real(*a, **k)

    monkeypatch.setattr(mitre, "_compute_coverage", _counting)

    # Three techniques in one request (same ns/range/framework) must reuse a single coverage computation.
    for tid in (_T, "AML.T0057", "AML.T0053"):
        await mitre._resolve_target_class(req, sess, "default", "24h", "atlas", tid, None)

    assert calls["n"] == 1, f"coverage recomputed per technique ({calls['n']}x); must be 1 per request"


# --------------------------------------------------------------------------------------------------
# Per-rule blocked counts, not the technique-wide total repeated
# --------------------------------------------------------------------------------------------------

async def test_def038_blocked_by_rule_is_per_rule_not_technique_total():
    req = _Request(_Loader(_rego_covering_both()))
    sess = _StubSession([(_RULE_A, "block", 25), (_RULE_B, "block", 15)])
    cov = await mitre._compute_coverage(req, sess, "default", "24h", "atlas")

    tech = next(t for t in cov["techniques"] if t["technique_id"] == _T)
    assert tech["blocked"] == 40  # technique-wide total is unchanged
    assert tech["blocked_by_rule"] == {_RULE_A: 25, _RULE_B: 15}, \
        "each rule must carry its OWN blocked count, not the technique total"
    # the exact misattribution the bug produced: both rows reading the same total
    assert tech["blocked_by_rule"][_RULE_A] != tech["blocked_by_rule"][_RULE_B]


def test_def038_export_pack_carries_per_rule_blocked():
    app = create_app()
    app.state.loader = _Loader(_rego_covering_both())
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "namespace": "default", "sub": "tester"}

    async def _sess():
        yield _StubSession([(_RULE_A, "block", 25), (_RULE_B, "block", 15)])

    app.dependency_overrides[get_session] = _sess
    resp = TestClient(app).get(
        "/api/v1/mitre/coverage/export?namespace=default&range=24h&framework=atlas&format=json"
    )
    assert resp.status_code == 200
    pack = json.loads(resp.content)
    ctrl = next(c for c in pack["controls"] if c["technique_id"] == _T)
    assert ctrl["blocked_by_rule"] == {_RULE_A: 25, _RULE_B: 15}, \
        "the evidence export must attribute blocks per rule (docstring promises 'per-rule blocked counts')"


# --------------------------------------------------------------------------------------------------
# "ENFORCED" must mean a rule is DEFINED, and must not be read as block evidence
# --------------------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_a_rule_named_only_in_a_comment_does_not_make_a_technique_enforced():
    """Coverage was decided by `rule_id in rego_blob` — raw substring containment over the
    concatenation of every loaded policy. A `#` comment mentioning a rule enforces nothing, but
    satisfied the test, so a technique could read ENFORCED in the donut, the legend, and the exported
    auditor evidence pack with no rule behind it at all."""
    rego = f"package norviq.decoy\n\ndefault decision = \"allow\"\n# TODO: reinstate {_RULE_A} and {_RULE_B}\n"
    cov = await mitre._compute_coverage(_Request(_Loader(rego)), _StubSession([]), "default", "24h", "atlas")
    tech = next(t for t in cov["techniques"] if t["technique_id"] == _T)
    assert tech["covered_policies"] == []
    assert tech["status"] == "gap"


@pytest.mark.asyncio
async def test_a_rule_named_inside_prose_does_not_make_a_technique_enforced():
    """Same defect, the form a comment strip alone would miss: the name inside a reason string on a
    live code line. A rule is present when it is DEFINED (`blocks["id"]` / `rule_id = "id"`), which is
    always the quoted id — never when it merely appears inside some other string."""
    rego = f'package norviq.decoy\n\ndefault decision = "allow"\nnote := "superseded by {_RULE_A}"  # {_RULE_B}\n'
    cov = await mitre._compute_coverage(_Request(_Loader(rego)), _StubSession([]), "default", "24h", "atlas")
    tech = next(t for t in cov["techniques"] if t["technique_id"] == _T)
    assert tech["covered_policies"] == []
    assert tech["status"] == "gap"


@pytest.mark.asyncio
async def test_a_really_defined_rule_still_counts_as_enforced():
    """The control for the two above: tightening the test must not lose a single real rule."""
    cov = await mitre._compute_coverage(
        _Request(_Loader(_rego_covering_both())), _StubSession([]), "default", "24h", "atlas"
    )
    tech = next(t for t in cov["techniques"] if t["technique_id"] == _T)
    assert tech["status"] == "enforced"
    assert sorted(tech["covered_policies"]) == sorted([_RULE_A, _RULE_B])


@pytest.mark.asyncio
async def test_enforced_is_rules_present_and_says_so_rather_than_implying_block_evidence():
    """`status` is decided from the loaded rego and never consults the block counts the same loop
    computes, so "enforced" carries no evidence that anything was ever blocked — and in a monitor-mode
    namespace, where the evaluator softens block->audit, it never can. The sibling /coverage route over
    the same rego ships `basis: "rules_present"` and documents that "'present' is NOT 'effective'";
    this route shipped the bare word with no such qualifier, under console copy asserting "backed by a
    live policy AND block evidence". `basis` + `proven` are what make that copy checkable."""
    cov = await mitre._compute_coverage(
        _Request(_Loader(_rego_covering_both())), _StubSession([]), "default", "24h", "atlas"
    )
    assert cov["basis"] == "rules_present"
    tech = next(t for t in cov["techniques"] if t["technique_id"] == _T)
    assert tech["status"] == "enforced"
    assert tech["blocked"] == 0
    assert tech["proven"] is False  # enforced, but NOT backed by block evidence
    assert cov["enforced"] >= 1
    assert cov["proven"] == 0  # not one enforced technique has block evidence in this window


@pytest.mark.asyncio
async def test_proven_counts_only_techniques_whose_rules_actually_acted():
    cov = await mitre._compute_coverage(
        _Request(_Loader(_rego_covering_both())),
        _StubSession([(_RULE_A, "block", 25)]),
        "default", "24h", "atlas",
    )
    tech = next(t for t in cov["techniques"] if t["technique_id"] == _T)
    assert tech["proven"] is True
    assert cov["proven"] == sum(
        1 for t in cov["techniques"] if t["status"] == "enforced" and t["blocked"] > 0
    )
    assert cov["proven"] <= cov["enforced"]


# --------------------------------------------------------------------------------------------------
# ...and tightening "present" must not break the product's OWN way of becoming present
# --------------------------------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_applying_the_generated_remediation_overlay_closes_its_gap():
    """The Compliance page offers "Generate enforcing policy" on a gap technique; the operator reviews
    it and applies it to the `<class>__remediation__` key, and the technique is supposed to flip to
    ENFORCED. That overlay is `generate_remediation_rego`, and it names the mapped rule ONLY as the
    last segment of a namespaced block id — `blocks["remediation:<fw>:<control>:<rule_id>"]` — plus in
    two `#` comments. A presence test anchored on the BARE quoted id matches neither (the comments are
    stripped, and the compound literal has `:` where the opening quote would have to be), so the
    remediation loop could never close: apply the overlay, still a gap, generate again.

    Built from the real generator, never a hand-written approximation of its output."""
    from norviq.api.threat_intent import generate_remediation_overlay_rego

    overlay = generate_remediation_overlay_rego(
        "customer-support",
        [{"framework": "atlas", "control_id": _T, "control_name": "Exploit", "rule_ids": [_RULE_A, _RULE_B]}],
    )
    # premise: the generator really does emit the compound form and no bare quoted id.
    assert f'blocks["remediation:atlas:{_T}:{_RULE_A}"]' in overlay

    cov = await mitre._compute_coverage(
        _Request(_Loader(overlay)), _StubSession([]), "default", "24h", "atlas"
    )
    tech = next(t for t in cov["techniques"] if t["technique_id"] == _T)
    assert tech["status"] == "enforced", "applying the product's own remediation overlay must close the gap"
    assert sorted(tech["covered_policies"]) == sorted([_RULE_A, _RULE_B])
    # and it is still only RULES-PRESENT — no block evidence was recorded.
    assert tech["proven"] is False


@pytest.mark.asyncio
async def test_a_namespaced_id_that_merely_ENDS_in_prose_is_still_not_a_control():
    """The control for the test above: accepting `...:<rule_id>` must not re-open the prose hole. A
    literal that merely CONTAINS the id, or ends with it after a space rather than a colon segment
    boundary, is not a definition."""
    rego = (
        'package norviq.decoy\n\n'
        'default decision = "allow"\n'
        f'note := "superseded by {_RULE_A}"\n'
        f'other := "{_RULE_B} was removed"\n'
    )
    cov = await mitre._compute_coverage(_Request(_Loader(rego)), _StubSession([]), "default", "24h", "atlas")
    tech = next(t for t in cov["techniques"] if t["technique_id"] == _T)
    assert tech["covered_policies"] == []
    assert tech["status"] == "gap"
