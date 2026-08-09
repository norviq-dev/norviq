# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""What an enforcing namespace with NO policy loaded does, and what the two "no policy" cases mean.

The shipped default is now ALLOW: a namespace nobody has written a policy for is not governed, so
there is no customer decision to enforce. Deny-by-default is still available and is the right choice
for a namespace the customer has decided to lock down — it is now an explicit setting rather than the
silent consequence of not having configured anything yet.

Every test below except `test_the_shipped_default_allows` monkeypatches `no_policy_decision`, which is
correct for testing the branches — but it also meant NOTHING pinned the shipped default, and the whole
file passed unchanged when that default was flipped from deny to allow. That gap is what
`test_the_shipped_default_allows` closes.

The not-yet-warmed startup window keeps a distinct, loudly-logged signal from a genuine no-policy
namespace. A load FAILURE (DB error) does NOT route here — it raises and fail-closes via evaluate()
(NRVQ-ENG-2000)."""

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


def test_the_shipped_default_allows(monkeypatch) -> None:
    """Pins the DEFAULT, not a branch — deliberately does not monkeypatch `no_policy_decision`.

    Installing the chart into a namespace and not yet writing a policy must not take that namespace's
    tool calls to zero. Every other test in this file sets the knob explicitly, so before this test
    existed the default could be changed in either direction without a single assertion moving.
    """
    monkeypatch.setattr(settings, "enforcement_mode", "block")
    assert settings.no_policy_decision == "allow"
    d = _evaluator(warmed=True)._no_policy_decision("ghost-ns:x", "ghost-ns")
    assert d["decision"] == "allow", "an ungoverned namespace must not be dropped by default"
