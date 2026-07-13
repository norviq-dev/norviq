# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""D3 — unit tests for the pure two-tier retention planner (no DB). SAFETY-critical: the latest run is never
pruned, detail is bounded by count AND age, summaries by count AND age."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from norviq.api.routers.redteam import plan_retention

NOW = datetime(2026, 7, 6, tzinfo=timezone.utc)
D = timedelta
CFG = dict(detail_runs=3, detail_ttl=D(days=7), summary_runs=20, summary_ttl=D(days=30))


def _runs(*ages_days):
    # newest first: age 0 == the latest run
    return [(f"r{i}", NOW - D(days=a)) for i, a in enumerate(ages_days)]


def test_single_run_never_pruned():
    assert plan_retention(_runs(0), now=NOW, **CFG) == (set(), set())


def test_latest_is_always_protected_even_when_ancient():
    # a lone run that is 999 days old is STILL the latest → never deleted or detail-pruned
    d, p = plan_retention([("only", NOW - D(days=999))], now=NOW, **CFG)
    assert d == set() and p == set()


def test_detail_pruned_beyond_count_or_ttl_summary_kept():
    # ages 0,1,2,8,40 : r0 latest; r1,r2 within top-3 & <7d keep detail; r3 (8d) detail-pruned; r4 (40d) deleted
    d, p = plan_retention(_runs(0, 1, 2, 8, 40), now=NOW, **CFG)
    assert d == {"r4"}
    assert p == {"r3"}
    assert "r0" not in d and "r0" not in p  # latest protected


def test_detail_bounded_by_count_on_a_same_day_burst():
    # 25 runs all today: detail must be bounded to the newest 3 (count), summaries to the newest 20 (count)
    runs = [(f"b{i}", NOW - D(seconds=i)) for i in range(25)]
    d, p = plan_retention(runs, now=NOW, **CFG)
    kept_detail = {"b0", "b1", "b2"}  # newest 3 keep detail
    assert d == {f"b{i}" for i in range(20, 25)}          # beyond the 20 summary count → deleted
    assert p == {f"b{i}" for i in range(3, 20)}           # beyond detail count but within summary → summary only
    assert kept_detail.isdisjoint(d | p)                  # newest 3 keep FULL detail
    assert "b0" not in d and "b0" not in p                # latest protected


def test_summary_deleted_when_older_than_ttl_even_within_count():
    # only 4 runs (within the 20 count) but two are older than 30d → those are deleted (age cap)
    d, p = plan_retention(_runs(0, 5, 35, 60), now=NOW, **CFG)
    assert d == {"r2", "r3"}   # 35d, 60d both > 30d summary TTL → deleted
    assert p == set()          # r1 (5d) is within top-3 detail + <7d → keeps full detail


def test_empty_is_noop():
    assert plan_retention([], now=NOW, **CFG) == (set(), set())


def test_config_default_detail_keep_runs_is_one():
    """C: the shipped default keeps FULL detail for only the newest run (last-run-only)."""
    from norviq.config import settings
    assert settings.redteam_detail_keep_runs == 1


def test_detail_keep_one_prunes_all_but_the_latest():
    """C: with detail_runs=1, only the newest run keeps full detail; the immediately-prior run is detail-pruned
    (summary kept), and older runs likewise — the latest is NEVER pruned."""
    d, p = plan_retention(_runs(0, 1, 2), now=NOW, detail_runs=1, detail_ttl=D(days=7), summary_runs=20, summary_ttl=D(days=30))
    assert d == set()              # all 3 within the summary window → none deleted
    assert p == {"r1", "r2"}       # only r0 (latest) keeps detail; r1 (prior) + r2 are detail-pruned
    # raising detail_runs back to 3 restores 3-run detail (env/Helm-configurable)
    d3, p3 = plan_retention(_runs(0, 1, 2), now=NOW, detail_runs=3, detail_ttl=D(days=7), summary_runs=20, summary_ttl=D(days=30))
    assert p3 == set()
