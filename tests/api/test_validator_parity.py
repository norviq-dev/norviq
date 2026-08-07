# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The CRD path runs TWO validators, and they must not disagree.

`webhook/controller.go validateRego` gates admission; `norviq/api/routers/policies.py
validate_rego_source` gates the write. A CR passes through both, in that order, and divergence is a
defect in either direction:

  * controller STRICTER than the API -> a policy the product would happily store can never be applied
    through the CRD path at all. This was live: the controller capped regex builtins at 5 while the API
    allows 25, and the shipped `strict.rego` preset alone uses 23-26.
  * controller LAXER than the API -> the CR clears admission, goes to the API, and dies with a 422.
    `markDeterministicFailure` (controller.go:523) records that once and NEVER retries, so it cannot
    self-heal: the CR sits in phase=Error forever while the database keeps serving the previous rego.
    Enforcement silently lags the manifest, and the only symptom is one NRVQ-WHK-4025 log line.

Three divergences shipped at once: the regex cap, an absent forbidden-builtin check, and an absent
cross-package `data.` check.

This test reads the Go source rather than executing it, deliberately — it must run in the ordinary
pytest sweep on a machine with no Go toolchain, and its whole job is to fail the moment someone edits
one side's constants without the other. Behavioural coverage lives beside each implementation
(webhook/controller_test.go TestValidateRego*, tests/api/test_shipped_presets_validate.py).
"""

from __future__ import annotations

import pathlib
import re

import pytest

from norviq.api.routers.policies import _FORBIDDEN_REGO_TOKENS

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "webhook" / "controller.go"

pytestmark = pytest.mark.skipif(not CONTROLLER.is_file(), reason="webhook/controller.go not present")


def _go_source() -> str:
    return CONTROLLER.read_text()


def test_regex_cap_matches() -> None:
    """Both sides cap regex builtins at the same number."""
    go = re.search(r"reCount > (\d+)", _go_source())
    assert go, "could not find the regex cap in controller.go"
    py = re.search(
        r"regex_ops > (\d+)", (ROOT / "norviq/api/routers/policies.py").read_text()
    )
    assert py, "could not find the regex cap in policies.py"
    assert go.group(1) == py.group(1), (
        f"regex cap drift: controller.go allows {go.group(1)}, policies.py allows {py.group(1)}. "
        "A stricter controller makes valid policies unappliable via CRD; a laxer one produces a "
        "terminal 422 the retry sweep never revisits."
    )


def test_forbidden_builtin_lists_match() -> None:
    """Every token the API forbids is also forbidden at admission, and vice versa."""
    go_block = re.search(
        r"var forbiddenRegoTokens = \[\]\*regexp\.Regexp\{(.*?)\n\}", _go_source(), re.S
    )
    assert go_block, "controller.go no longer declares forbiddenRegoTokens — did the check get dropped?"
    go_tokens = set(re.findall(r"regexp\.MustCompile\(`([^`]+)`\)", go_block.group(1)))
    py_tokens = set(_FORBIDDEN_REGO_TOKENS)

    only_py = py_tokens - go_tokens
    only_go = go_tokens - py_tokens
    assert not only_py, (
        f"forbidden in the API but NOT at admission: {sorted(only_py)} — such a policy clears the "
        "webhook and then fails terminally at the API."
    )
    assert not only_go, (
        f"forbidden at admission but NOT in the API: {sorted(only_go)} — the controller is stricter "
        "than the product, so a storable policy cannot be applied via CRD."
    )


def test_controller_still_checks_cross_package_data_reads() -> None:
    """The cross-tenant escape (`data.<other package>`) is checked on both sides."""
    src = _go_source()
    assert "rejectForbiddenRego" in src, "controller.go dropped the forbidden/cross-package check"
    assert "regoDataRef" in src and "ownPkg" in src, (
        "controller.go no longer compares `data.` references against the module's own package — the "
        "cross-tenant read via data.norviq.managed.<other key> is unguarded at admission again."
    )


def test_both_sides_admit_deny_by_default() -> None:
    """`default decision = "block"` is a resolver, not a missing one.

    Two shipped templates use it. The controller always accepted it; the API rejected it with 422
    until this was fixed. Assert the API side behaviourally (the Go side is covered by
    TestValidateRegoAdmitsDenyByDefault).
    """
    from norviq.api.routers.policies import validate_rego_source

    validate_rego_source(
        'package norviq\ndefault decision = "block"\n'
        'decision = "allow" { input.tool_name == "read_file" }\n'
        'rule_id = "R-1"\nreason = "deny by default"\n'
    )
