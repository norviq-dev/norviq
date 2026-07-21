# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""An enforcing namespace with NO policy loaded now defaults to DENY (deny-by-default PEP), with a
distinct, loudly-logged signal for the not-yet-warmed startup window vs a genuine no-policy namespace.
A load FAILURE (DB error) does NOT route here — it raises and fail-closes via evaluate() (NRVQ-ENG-2000)."""

from __future__ import annotations

from types import SimpleNamespace

from norviq.config import settings
from norviq.engine.evaluator import OPAEvaluator


class _Cache:  # minimal; _no_policy_decision never touches the cache
    pass


def _evaluator(warmed: bool) -> OPAEvaluator:
    ev = OPAEvaluator(_Cache())  # type: ignore[arg-type]
    ev.bind_loader(SimpleNamespace(_warmed=warmed, _policies={}))
    return ev


def test_genuine_no_policy_denies_in_block_mode(monkeypatch) -> None:
    monkeypatch.setattr(settings, "enforcement_mode", "block")
    monkeypatch.setattr(settings, "no_policy_decision", "deny")
    d = _evaluator(warmed=True)._no_policy_decision("ghost-ns:x", "ghost-ns")
    assert d["decision"] == "block" and d["rule_id"] == "no_policy_loaded"


def test_not_warmed_is_distinct_pending(monkeypatch) -> None:
    monkeypatch.setattr(settings, "enforcement_mode", "block")
    monkeypatch.setattr(settings, "no_policy_decision", "deny")
    d = _evaluator(warmed=False)._no_policy_decision("x:y", "x")
    assert d["decision"] == "block" and d["rule_id"] == "policy_load_pending"


def test_audit_mode_still_allows(monkeypatch) -> None:
    monkeypatch.setattr(settings, "enforcement_mode", "audit")
    monkeypatch.setattr(settings, "no_policy_decision", "deny")
    d = _evaluator(warmed=True)._no_policy_decision("x:y", "x")
    assert d["decision"] == "allow" and d["rule_id"] == "default_allow"


def test_explicit_allow_override(monkeypatch) -> None:
    monkeypatch.setattr(settings, "enforcement_mode", "block")
    monkeypatch.setattr(settings, "no_policy_decision", "allow")
    d = _evaluator(warmed=True)._no_policy_decision("x:y", "x")
    assert d["decision"] == "allow"
