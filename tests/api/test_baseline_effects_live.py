# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The compiled baseline is run through OPA, because string assertions cannot prove rego behaves.

`test_baseline_compiler.py` proves the compiler emits the right REGISTRATION HEADS. That is not the
same as proving the resulting module compiles and decides correctly — and the difference is not
academic here: an all-`monitor` module has no `blocks[...]` heads at all, and a Rego partial set with
zero definitions is undefined rather than empty, so it fails to compile with `var blocks is unsafe`.
Every head could be perfectly correct and the shipped default would still refuse every call.

So each effect is compiled, written to disk, and evaluated by the real `opa` binary.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from norviq.api import baseline

_OPA = shutil.which("opa")
_QUERY_DECISION = "data.norviq.presets.strict.decision"
_QUERY_RULE = "data.norviq.presets.strict.rule_id"

# A genuine attack, a plainly benign call, and the false positive that motivated this whole feature:
# 8 harmless alphanumeric characters in an order id, which the base64 fan-out decodes to random bytes
# containing '|' and the shell rule then matches.
_SQL_ATTACK = {"tool_name": "run_report", "tool_params": {"q": "drop table users"}}
_BENIGN = {"tool_name": "get_order", "tool_params": {"order_id": "ORD-002"}}
# DECOUPLED FROM WHATEVER IS CURRENTLY MISFIRING. This fixture has now been retargeted twice, once
# per detector fix: it was `order_id="fKtHF4vU"` until C2-023 fixed the base64 shell misfire, then
# `delivery_date="2026-08-10"` until BUG-005 gated the date/passport patterns on field context. Each
# time, a test about MONITOR SEMANTICS died because the bug it borrowed had been fixed.
#
# The claim under test never needed a false positive — it needs a DETECTION. `monitor` records rather
# than drops, whatever the detection's merits, so a true positive proves it and cannot rot. The fixed
# false positive is now a permanent regression guard instead (see `_FIXED_FALSE_POSITIVE` below).
_DETECTED = {"tool_name": "get_order", "tool_params": {"customer_ssn": "123-45-6789"}}

# BUG-005, now fixed: every ISO-8601 date parameter used to be classified as a US SSN, so a delivery
# date was blocked and the audit trail blamed an SSN. Kept as a guard — a date is not a birth date
# unless the call says so.
_FIXED_FALSE_POSITIVE = {"tool_name": "get_order", "tool_params": {"delivery_date": "2026-08-10"}}


def _compile_to_disk(effect: str, tmp: Path) -> Path:
    src = baseline.compile("strict", {cid: effect for cid in baseline.control_ids("strict")})
    path = tmp / f"strict_{effect}.rego"
    path.write_text(src, encoding="utf-8")
    return path


def _eval(rego: Path, query: str, inp: dict) -> str:
    proc = subprocess.run(
        ["opa", "eval", "--v0-compatible", "-d", str(rego), "-I", query],
        input=json.dumps(inp), capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


@pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the compiled baseline")
@pytest.mark.parametrize("effect", ["deny", "monitor", "off"])
def test_every_effect_produces_a_module_opa_accepts(effect: str) -> None:
    """`opa check` on each — the guard for the undefined-partial-set trap."""
    with tempfile.TemporaryDirectory() as td:
        rego = _compile_to_disk(effect, Path(td))
        proc = subprocess.run(
            ["opa", "check", "--v0-compatible", str(rego)], capture_output=True, text=True
        )
        assert proc.returncode == 0, f"{effect} produced an uncompilable module:\n{proc.stderr}"


@pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the compiled baseline")
@pytest.mark.parametrize(
    "effect,expected_decision",
    [("deny", "block"), ("monitor", "audit"), ("off", "allow")],
)
def test_a_real_attack_follows_the_configured_effect(effect: str, expected_decision: str) -> None:
    """Detection is identical across effects; only the consequence changes."""
    with tempfile.TemporaryDirectory() as td:
        rego = _compile_to_disk(effect, Path(td))
        assert _eval(rego, _QUERY_DECISION, _SQL_ATTACK) == expected_decision
        if effect != "off":
            # Still attributed to the control that caught it — monitor records WHAT would have blocked.
            assert _eval(rego, _QUERY_RULE, _SQL_ATTACK) == "deny_sql_injection"


@pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the compiled baseline")
@pytest.mark.parametrize("effect", ["deny", "monitor", "off"])
def test_a_benign_call_is_allowed_under_every_effect(effect: str) -> None:
    with tempfile.TemporaryDirectory() as td:
        rego = _compile_to_disk(effect, Path(td))
        assert _eval(rego, _QUERY_DECISION, _BENIGN) == "allow"


@pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the compiled baseline")
def test_a_detection_is_recorded_not_dropped_under_the_default() -> None:
    """The result this feature exists to produce.

    Under the OLD shipped posture — strict, block mode, on every tenant namespace — a detection
    dropped the call. Under the new default it proceeds and is recorded as non-compliant instead.
    That is the difference between a product a customer can install and one they cannot.

    Deliberately uses a TRUE positive. Two earlier versions of this test borrowed whatever detector
    was misfiring at the time, and both died when that detector was fixed — see the `_DETECTED`
    comment. Monitor semantics do not depend on the detection being wrong.
    """
    with tempfile.TemporaryDirectory() as td:
        monitor = _compile_to_disk("monitor", Path(td))
        assert _eval(monitor, _QUERY_DECISION, _DETECTED) == "audit"
        assert _eval(monitor, _QUERY_RULE, _DETECTED) == "pii_detection"

        # And the escape hatch works: an operator who cannot tolerate the noise turns that one control
        # off while keeping the rest ENFORCING. Every other control is named explicitly here, because
        # a partial map defaults the unnamed ones to `monitor` (see the next test) — which would make
        # the isolation claim below pass for the wrong reason.
        effects = {cid: "deny" for cid in baseline.control_ids("strict")}
        effects["pii_detection"] = "off"
        off = Path(td) / "pii_off.rego"
        off.write_text(baseline.compile("strict", effects), encoding="utf-8")

        assert _eval(off, _QUERY_DECISION, _DETECTED) == "allow"
        # Turning that ONE control off must not disarm the others.
        assert _eval(off, _QUERY_DECISION, _SQL_ATTACK) == "block"


def test_the_date_false_positive_stays_fixed_even_when_every_control_enforces() -> None:
    """BUG-005 regression guard, asserted at the STRICTEST setting.

    A delivery date is not a birth date. This is the one that blocked `date_format("2026-01-01")`
    live with "PII (SSN) detected", and it is the reason `pii_detection` could not ship enforcing.
    Checked with every control at `deny`, because that is the configuration it has to survive.
    """
    with tempfile.TemporaryDirectory() as td:
        effects = {cid: "deny" for cid in baseline.control_ids("strict")}
        path = Path(td) / "all_deny.rego"
        path.write_text(baseline.compile("strict", effects), encoding="utf-8")

        assert _eval(path, _QUERY_DECISION, _FIXED_FALSE_POSITIVE) == "allow"
        # The genuine article must still be caught at the same setting, or the fix is just a hole.
        assert _eval(path, _QUERY_DECISION, _DETECTED) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the compiled baseline")
def test_a_partial_effect_map_leaves_the_rest_at_the_default() -> None:
    """Naming one control must not silently re-enforce every other one.

    `compile()` takes a sparse map, so what happens to the controls the caller did NOT mention is a
    real decision: they stay at THEIR shipped default. The alternative — inheriting the preset's
    original severity — would mean a customer flipping one control to `off` quietly promoted every
    other one, including the four that deliberately ship observing.

    Defaults are per control now, so "the rest" is no longer uniformly `audit`. The invariant under
    test is unchanged: naming one control must not move any other one off its own default.
    """
    with tempfile.TemporaryDirectory() as td:
        rego = Path(td) / "partial.rego"
        # The named control must be one the fixture actually TRIPS, or "the one named" is allowed for
        # the wrong reason and this test proves nothing. `_DETECTED` is a real SSN, so it trips
        # `pii_detection` for certain; the old fixture stopped tripping it when BUG-005 was fixed,
        # which is precisely the trap this comment was written to prevent.
        rego.write_text(baseline.compile("strict", {"pii_detection": "off"}), encoding="utf-8")
        assert _eval(rego, _QUERY_DECISION, _DETECTED) == "allow"           # the one named
        # deny_sql_injection is untouched and ships ENFORCING, so the attack blocks — the unnamed
        # controls sit at their own defaults, which is the property being asserted.
        assert _eval(rego, _QUERY_DECISION, _SQL_ATTACK) == "block"
        # ...and a control whose own default is observe-only is still observing, so "the rest went to
        # deny" cannot be what happened.
        assert baseline.shipped_default("scope_violation_dangerous_tool") == "monitor"


@pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the compiled baseline")
def test_all_deny_matches_the_unmodified_preset_decision_for_decision() -> None:
    """Parity against the real preset file, evaluated — not just the same heads on paper."""
    preset = Path(baseline._preset_dir() or ".") / "strict.rego"
    cases = [_SQL_ATTACK, _BENIGN, _DETECTED, _FIXED_FALSE_POSITIVE,
             {"tool_name": "delete_user", "tool_params": {"id": "1"}},
             {"tool_name": "x", "tool_params": {"q": "4111111111111111"}}]
    with tempfile.TemporaryDirectory() as td:
        compiled = _compile_to_disk("deny", Path(td))
        for inp in cases:
            assert _eval(compiled, _QUERY_DECISION, inp) == _eval(preset, _QUERY_DECISION, inp), inp
            assert _eval(compiled, _QUERY_RULE, inp) == _eval(preset, _QUERY_RULE, inp), inp
