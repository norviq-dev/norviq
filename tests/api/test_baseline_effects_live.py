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
# A legitimate lookup that a shipped control misfires on. The VEHICLE changed once, deliberately:
# it used to be `order_id="fKtHF4vU"`, an 8-char identifier that `deny_shell_execution` misfired on
# at roughly 1 in 8 — because the decoded arm of that rule matched bare shell metacharacters against
# base64-decoded bytes. C2-023 fixed the detector, so that payload is correctly allowed now and no
# longer demonstrates anything.
#
# Retargeted to the date->SSN misfire (BUG-005), which is still open and is 100% deterministic rather
# than 1-in-8: `pii_value_detected` matches `^(\d{3}-\d{2}-\d{4}|\d{4}-\d{2}-\d{2}|[A-Z]{2}\d{7})$`,
# so EVERY ISO-8601 date parameter is classified as a US SSN. A stronger fixture for the same claim.
_FALSE_POSITIVE = {"tool_name": "get_order", "tool_params": {"delivery_date": "2026-08-10"}}


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
def test_the_shell_false_positive_is_recorded_not_dropped_under_the_default() -> None:
    """The result this feature exists to produce.

    `get_order(delivery_date="2026-08-10")` is a legitimate lookup that `pii_detection` misfires on,
    for EVERY ISO-8601 date (BUG-005, still open). Under the OLD shipped posture — strict, block mode,
    on every tenant namespace — that call was dropped and the audit trail blamed an SSN. Under the new
    default it proceeds and is recorded as non-compliant instead.

    This does not fix the detector; the false positive is tracked separately. It makes it non-fatal,
    which is the difference between a product a customer can install and one they cannot.

    The fixture moved from the shell misfire to the date misfire when C2-023 fixed the former — see
    the `_FALSE_POSITIVE` comment. The claim under test is unchanged.
    """
    with tempfile.TemporaryDirectory() as td:
        monitor = _compile_to_disk("monitor", Path(td))
        assert _eval(monitor, _QUERY_DECISION, _FALSE_POSITIVE) == "audit"
        assert _eval(monitor, _QUERY_RULE, _FALSE_POSITIVE) == "pii_detection"

        # And the escape hatch works: an operator who cannot tolerate the noise turns that one control
        # off while keeping the rest ENFORCING. Every other control is named explicitly here, because
        # a partial map defaults the unnamed ones to `monitor` (see the next test) — which would make
        # the isolation claim below pass for the wrong reason.
        effects = {cid: "deny" for cid in baseline.control_ids("strict")}
        effects["pii_detection"] = "off"
        off = Path(td) / "shell_off.rego"
        off.write_text(baseline.compile("strict", effects), encoding="utf-8")

        assert _eval(off, _QUERY_DECISION, _FALSE_POSITIVE) == "allow"
        # Turning that ONE control off must not disarm the others.
        assert _eval(off, _QUERY_DECISION, _SQL_ATTACK) == "block"


@pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the compiled baseline")
def test_a_partial_effect_map_leaves_the_rest_at_the_default() -> None:
    """Naming one control must not silently re-enforce every other one.

    `compile()` takes a sparse map, so what happens to the controls the caller did NOT mention is a
    real decision: they stay at the shipped default (`monitor`). The alternative — inheriting the
    preset's original severity — would mean a customer flipping one control to `off` quietly
    promoted the other thirteen to `deny`.
    """
    with tempfile.TemporaryDirectory() as td:
        rego = Path(td) / "partial.rego"
        # The named control must be the one _FALSE_POSITIVE actually trips, or "the one named" is
        # allowed for the wrong reason and this test proves nothing.
        rego.write_text(baseline.compile("strict", {"pii_detection": "off"}), encoding="utf-8")
        assert _eval(rego, _QUERY_DECISION, _FALSE_POSITIVE) == "allow"     # the one named
        assert _eval(rego, _QUERY_DECISION, _SQL_ATTACK) == "audit"        # the rest: default monitor


@pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the compiled baseline")
def test_all_deny_matches_the_unmodified_preset_decision_for_decision() -> None:
    """Parity against the real preset file, evaluated — not just the same heads on paper."""
    preset = Path(baseline._preset_dir() or ".") / "strict.rego"
    cases = [_SQL_ATTACK, _BENIGN, _FALSE_POSITIVE,
             {"tool_name": "delete_user", "tool_params": {"id": "1"}},
             {"tool_name": "x", "tool_params": {"q": "4111111111111111"}}]
    with tempfile.TemporaryDirectory() as td:
        compiled = _compile_to_disk("deny", Path(td))
        for inp in cases:
            assert _eval(compiled, _QUERY_DECISION, inp) == _eval(preset, _QUERY_DECISION, inp), inp
            assert _eval(compiled, _QUERY_RULE, inp) == _eval(preset, _QUERY_RULE, inp), inp
