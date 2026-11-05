# SPDX-License-Identifier: Apache-2.0
"""The stock probes wait for the chart baseline to reach the engine, and still demand the exact decision.

On an upgrade the baseline NrvqPolicy moves from audit (0.2.5) to block (0.2.6) and the controller syncs it
asynchronously after `helm --wait`; a single-shot probe could land in that window and report the old posture.
"""
from __future__ import annotations

import importlib.util
import pathlib

_SPEC = importlib.util.spec_from_file_location(
    "verify_release", pathlib.Path(__file__).resolve().parents[2] / "scripts" / "verify_release.py")
vr = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(vr)  # type: ignore[union-attr]


def _sequence(*answers):
    seq = list(answers)

    def evaluate(tool, params):
        return seq.pop(0) if len(seq) > 1 else seq[0]
    return evaluate


def test_a_probe_that_converges_passes_and_reports_the_wait(monkeypatch) -> None:
    monkeypatch.setattr(vr.time, "sleep", lambda s: None)
    ev = _sequence({"decision": "audit", "rule_id": "policy_audit_would_block:strict_default_block"},
                   {"decision": "block", "rule_id": "strict_default_block"})
    ok, got, rule, _ = vr.await_decision(ev, "execute_sql", {}, "block", "strict_default_block", timeout=60)
    assert ok and got == "block" and rule == "strict_default_block"


def test_a_probe_that_never_converges_fails_with_the_last_decision() -> None:
    ev = _sequence({"decision": "audit", "rule_id": "policy_audit_would_block:strict_default_block"})
    ok, got, rule, _ = vr.await_decision(ev, "execute_sql", {}, "block", "strict_default_block",
                                         timeout=0.05, interval=0.01)
    assert not ok and got == "audit" and "policy_audit_would_block" in rule


def test_the_right_decision_with_the_wrong_rule_is_not_a_match() -> None:
    ev = _sequence({"decision": "block", "rule_id": "default_allow"})
    ok, *_ = vr.await_decision(ev, "execute_sql", {}, "block", "strict_default_block", timeout=0.05, interval=0.01)
    assert not ok
