# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""A class's path count must be its TRUE count, not its count inside the globally-capped list.

WHY THIS EXISTS. `/threats/attack-paths` ranks every kill-chain worst-first and returns the top
`_MAX_PATHS`. The console's class picker used to tally classes inside that truncated list, which
answers a different question than the one it displays: not "how exposed is this class" but "how many
of this class survived the global cap". The two agree only while the estate is smaller than the cap.

On a saturated estate they diverge, and the Attack Graph showed both at once — the picker read
"customer-support · 22 paths" while the coverage denominator in the same dialog, derived class-scoped,
read 49. The number shown first understated real exposure by 27 paths, on a surface whose entire job
is to size exposure honestly.

WHY THE TEST IS SHAPED LIKE THIS. It asserts the PROPERTY (counts are pre-truncation) rather than the
symptom (22 vs 49), and it does so above the cap on purpose: below the cap the buggy and correct
implementations agree exactly, so a fixture with fewer than `_MAX_PATHS` paths passes either way and
proves nothing. That is the vacuity this file is built to avoid — the divergence only exists at scale,
which is why it survived every hermetic suite and only surfaced once a seeded cluster grew past 200.
"""

from __future__ import annotations

import pytest

from norviq.api.routers import threats as threats_router
from norviq.api.schemas.threats import ThreatPath

_MAX = threats_router._MAX_PATHS


def _path(idx: int, cls: str, *, sev: str = "low", status: str = "blocked") -> ThreatPath:
    return ThreatPath(
        id=f"p{idx}", sev=sev, src=f"agent-{cls}", tgt="db", ns="default", cls=cls,
        mitre="T1190", hops=2, trust=0.5, blast=1, status=status, tool="execute_sql",
    )


def _saturating_fixture() -> list[ThreatPath]:
    """Deliberately MORE than `_MAX_PATHS`, split unevenly across three classes.

    `wide` is stacked at the END so the global cap truncates it hardest — that is the class whose real
    exposure the old code hid, and an even split would have masked the bug.
    """
    paths: list[ThreatPath] = []
    for i in range(_MAX):
        paths.append(_path(i, "narrow" if i % 2 else "medium"))
    for i in range(_MAX, _MAX + 120):
        paths.append(_path(i, "wide"))
    return paths


@pytest.mark.asyncio
async def test_class_totals_count_every_path_not_only_the_ones_that_survived_the_cap(monkeypatch):
    fixture = _saturating_fixture()

    async def fake_derive(session, namespaces, cls, hours=24, cap=_MAX):
        # Honour `cap` exactly as the real one does — the endpoint must be the thing that asks for the
        # uncapped list. If it stops passing cap=None this fake truncates and the test fails, which is
        # precisely the regression being guarded.
        ordered = list(fixture)
        return (ordered if cap is None else ordered[:cap]), ["default"]

    monkeypatch.setattr(threats_router, "_derive_paths", fake_derive)
    monkeypatch.setattr(threats_router, "is_synthetic_identity", lambda cls, src: False)
    monkeypatch.setattr(threats_router, "_resolve_namespaces", lambda user, requested: ["default"])

    resp = await threats_router.get_threat_paths(
        ns="all", namespace=None, cls=None, range="24h", include_synthetic=True,
        session=None, user={"sub": "admin", "role": "admin"},
    )

    # The rendered list is still capped — that behaviour is deliberate and must not regress.
    assert len(resp.paths) == _MAX

    # ...but the counts describe the whole estate.
    assert resp.total_paths == len(fixture)
    assert resp.class_totals["wide"] == 120, (
        "`wide` was truncated away entirely by the global cap; counting inside `paths` would report 0 "
        "and tell the operator a class with 120 kill-chains has none"
    )
    assert sum(resp.class_totals.values()) == len(fixture)

    # The discriminating assertion: a tally over the RETURNED paths must disagree with the totals.
    # If these ever match, the fixture stopped saturating the cap and this test went vacuous.
    tallied = {}
    for p in resp.paths:
        tallied[p.cls] = tallied.get(p.cls, 0) + 1
    assert tallied != resp.class_totals, (
        "fixture no longer saturates the cap — below _MAX_PATHS the correct and buggy implementations "
        "agree, so this test would pass without proving anything"
    )


@pytest.mark.asyncio
async def test_class_totals_exclude_synthetic_paths_when_they_are_hidden(monkeypatch):
    """The totals must follow the same visibility rule as the list they label.

    Synthetics are hidden by default. A total that counted them would label a class with paths the
    operator cannot see — the mirror image of the original bug, and just as misleading.
    """
    fixture = [_path(i, "real") for i in range(30)] + [_path(100 + i, "evtrace-probe") for i in range(12)]

    async def fake_derive(session, namespaces, cls, hours=24, cap=_MAX):
        ordered = list(fixture)
        return (ordered if cap is None else ordered[:cap]), ["default"]

    monkeypatch.setattr(threats_router, "_derive_paths", fake_derive)
    monkeypatch.setattr(threats_router, "is_synthetic_identity", lambda cls, src: cls == "evtrace-probe")
    monkeypatch.setattr(threats_router, "_resolve_namespaces", lambda user, requested: ["default"])

    resp = await threats_router.get_threat_paths(
        ns="all", namespace=None, cls=None, range="24h", include_synthetic=False,
        session=None, user={"sub": "admin", "role": "admin"},
    )

    assert resp.synthetic_hidden == 12
    assert "evtrace-probe" not in resp.class_totals
    assert resp.class_totals["real"] == 30
    assert resp.total_paths == 30
