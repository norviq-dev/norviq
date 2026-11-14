# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""``GET /agents`` and ``GET /agents/{id}`` describe one agent the same way.

The list builds each row from the agent_registry roster with the warm ``trust:<id>`` snapshot laid over its
live trust fields (score, category, signals, dominant signal, recommendation), then the freeze and cap from
the store the engine enforces. ``violation_count`` stays the registry's, because the evaluator writes the
snapshot without one (``_safe_set_trust``), so the snapshot's count is always 0.

The detail built its row from the snapshot alone whenever the snapshot was warm, so for the 30 s after
every call it reported 0 violations for an agent the list showed with 97, and ``norviq agent get`` printed
"Violations: 0" for exactly the agent that had just been blocked. It now builds the row the way the list
does, so the two can only differ when the store changes between the two requests.
"""

from __future__ import annotations

import json

import pytest

import norviq.api.routers.agents as agents_mod
from tests.api.test_agents_trust_controls_read import _client, _hdr, _registry, _snapshot, _Store

SID = "spiffe://norviq/ns/chatbot-prod/sa/default"
SIGNALS = {"violation_rate": 0.1, "tool_novelty": 0.3, "scope_drift": 0.2}
FIELDS = ("score", "category", "violation_count", "signals", "dominant_signal", "recommendation",
          "frozen", "trust_cap", "controls")


def _calc() -> str:
    """What TrustCalculator._persist writes to trustcalc:<id>."""
    return json.dumps({"signals": SIGNALS, "dominant_signal": "tool_novelty", "recommendation": "monitor"})


def _row(score: float, category: str, violations: int, frozen: bool = False, cap: float | None = None) -> dict:
    row = _registry(SID, score, category, frozen=frozen, cap=cap)
    row["violation_count"] = violations
    return row


def _both(monkeypatch, store: _Store, registry: list[dict]) -> tuple[dict, dict]:
    client = _client(monkeypatch, store, registry)
    try:
        listed = client.get("/api/v1/agents?namespace=chatbot-prod", headers=_hdr())
        assert listed.status_code == 200, listed.text
        detail = client.get(f"/api/v1/agents/{SID}", headers=_hdr())
        assert detail.status_code == 200, detail.text
        rows = {r["spiffe_id"]: r for r in listed.json()}
        return rows[SID], detail.json()
    finally:
        client.close()


def test_the_detail_reports_the_registry_violation_count_while_the_snapshot_is_warm(monkeypatch) -> None:
    """The measured case: one allowed call left a warm 0.525 snapshot; the registry holds 97 violations."""
    store = _Store({f"trust:{SID}": _snapshot(0.525, "Medium"), f"trustcalc:{SID}": _calc()})
    listed, detail = _both(monkeypatch, store, [_row(0.525, "Medium", 97)])
    assert listed["violation_count"] == 97
    assert detail["violation_count"] == 97
    assert detail["score"] == listed["score"] == 0.525
    assert detail["signals"] == listed["signals"] == SIGNALS


# Every combination of registry snapshot, warm or cold store snapshot, and enforced control. The two reads
# must agree on every trust field in each, so neither can be the one that says "not frozen" or "0 violations".
_REGISTRY = [("Medium", 0.6), ("Unscored", 0.3), ("Frozen", 0.0), ("High", 0.9)]
_CONTROLS = [{}, {"frozen": "1"}, {"cap": "0.4"}]


@pytest.mark.parametrize("category,score", _REGISTRY)
@pytest.mark.parametrize("warm", [True, False])
@pytest.mark.parametrize("controls", _CONTROLS, ids=["none", "frozen", "capped"])
def test_list_and_detail_agree_on_every_trust_field(monkeypatch, category, score, warm, controls) -> None:
    values: dict[str, str] = {}
    if warm:
        values[f"trust:{SID}"] = _snapshot(0.525, "Medium")
        values[f"trustcalc:{SID}"] = _calc()
    if "frozen" in controls:
        values[f"agent_frozen:{SID}"] = "1"
    if "cap" in controls:
        values[f"agent_trust_override:{SID}"] = controls["cap"]
    registry = [_row(score, category, 97, frozen="frozen" in controls,
                     cap=float(controls["cap"]) if "cap" in controls else None)]
    listed, detail = _both(monkeypatch, _Store(values), registry)
    assert {f: detail.get(f) for f in FIELDS} == {f: listed.get(f) for f in FIELDS}
    assert detail["violation_count"] == 97
    if "frozen" in controls:  # a frozen agent reads frozen on both, whatever either snapshot says
        assert (detail["frozen"], detail["score"], detail["category"]) == (True, 0.0, "frozen")
    if "cap" in controls and warm:  # the score the engine uses: min(snapshot, cap)
        assert (detail["trust_cap"], detail["score"]) == (0.4, 0.4)


def test_a_warm_agent_not_yet_in_the_registry_keeps_its_snapshot(monkeypatch) -> None:
    """The registry write is best-effort; an agent whose row is not there yet still reads from the snapshot."""
    store = _Store({f"trust:{SID}": _snapshot(0.525, "Medium"), f"trustcalc:{SID}": _calc()})
    listed, detail = _both(monkeypatch, store, [])
    assert {f: detail.get(f) for f in FIELDS} == {f: listed.get(f) for f in FIELDS}
    assert (detail["score"], detail["signals"]) == (0.525, SIGNALS)


def test_an_unknown_agent_is_still_a_404(monkeypatch) -> None:
    client = _client(monkeypatch, _Store(), [])
    try:
        assert client.get(f"/api/v1/agents/{SID}", headers=_hdr()).status_code == 404
    finally:
        client.close()


def test_the_registry_row_builders_share_one_shape() -> None:
    """The single-agent registry read used to build its own, narrower row (no namespace, class, last seen or
    synthetic flag, and a different category fallback), so a cold detail was not the cold list row."""
    from datetime import datetime, timezone
    from types import SimpleNamespace

    entry = SimpleNamespace(spiffe_id=SID, namespace="chatbot-prod", agent_class="default",
                            last_seen=datetime(2026, 11, 13, tzinfo=timezone.utc), trust_score=0.3,
                            trust_category=None, violation_count=97, frozen=False, trust_cap=None)
    row = agents_mod._registry_row(entry)
    assert row["category"] == "unknown"
    assert (row["namespace"], row["agent_class"], row["violation_count"]) == ("chatbot-prod", "default", 97)
    assert row["last_seen"] == "2026-11-13T00:00:00+00:00"
