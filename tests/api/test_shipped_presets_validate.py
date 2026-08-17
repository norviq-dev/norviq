# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Every rego this release SHIPS must pass the API's own policy validator.

The presets live in the webhook image; the validator lives in the API. Nothing checked that they agree,
and they can disagree silently — which is exactly what happened:

Adding one rule to `strict.rego` took it from 23 to 26 `regex.*` operations, one over
`validate_rego_source`'s cap of 25. The chart rendered fine, `opa test` passed, `opa parse` passed, and
the drift guard passed. The failure only appeared once the controller tried to POST the preset to a live
API, which answered `422 too many regex operations`. From there:

  * the NrvqPolicy went to phase=Error and the retry sweep re-drove it every 60s, forever;
  * the database kept serving the PREVIOUS rego, so enforcement silently lagged the image;
  * the only symptom was `NRVQ-WHK-4025: API sync failed ... status 422` in controller logs.

A shipped preset that the API refuses to store is a broken artifact, so this asserts the contract in
CI rather than discovering it from a cluster. It is cheap: pure function calls, no cluster, no OPA.

The headroom assertion is deliberate and is the more useful half. Without it the next person to add a
detection rule gets a bare `422` from a cluster instead of a local failure that names the budget.
"""

from __future__ import annotations

import pathlib
import re

import pytest
from fastapi import HTTPException

from norviq.api.routers.policies import _strip_rego_comments, validate_rego_source

ROOT = pathlib.Path(__file__).resolve().parents[2]

# Every rego blob the release actually ships and expects the API to accept: the canonical policy plus
# each webhook preset a NrvqPolicy may name via `spec.preset`.
SHIPPED = [
    ROOT / "comprehensive.rego",
    *sorted(p for p in (ROOT / "webhook" / "presets").glob("*.rego") if not p.name.endswith("_test.rego")),
    # policies/templates/ was NOT in this list, and that omission is why the exact failure this file's
    # docstring describes shipped again — twice. `tool-allowlist-perimeter.rego` and
    # `sql-allowlist-deny-by-default.rego` write deny-by-default as `default decision = "block"` with the
    # allowlist as `decision = "allow" { ... }`. Both pass `opa check` and the Go controller's
    # validateRego; both were refused by validate_rego_source with 422 "must include block or escalate
    # decision". These are copy-me templates — the docs point authors at them — so a template the API
    # will not store is a broken artifact in exactly the sense this file already argues.
    *sorted(p for p in (ROOT / "policies" / "templates").glob("*.rego") if not p.name.endswith("_test.rego")),
]

# Mirrors validate_rego_source. Kept as a literal rather than imported so that RAISING the cap cannot
# silently make this test vacuous — if the cap moves, this constant must move with it, deliberately.
REGEX_OP_CAP = 25

# Same contract as REGEX_OP_CAP, for the same reason. This one is not hypothetical: strict.rego reached
# exactly 500 of the previous 500-line cap, which froze the enforced baseline — a three-line security
# rule could not be shipped — and the symptom would have been the controller retrying forever while the
# cluster kept enforcing the old policy, not a visible error.
REGO_LINE_CAP = 650


def _code_lines(rego: str) -> int:
    """Count the way validate_rego_source does: comments stripped, blanks dropped."""
    return len([ln for ln in _strip_rego_comments(rego).splitlines() if ln.strip()])


def _regex_ops(rego: str) -> int:
    return len(re.findall(r"\bregex\.[a-zA-Z0-9_]+\b", rego)) + len(re.findall(r"\bre_match\s*\(", rego))


def test_the_shipped_set_is_not_empty() -> None:
    """Guards the guard: a glob that silently matches nothing would make every test below pass."""
    assert len(SHIPPED) >= 4, f"expected comprehensive.rego + the presets, found {[p.name for p in SHIPPED]}"


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.name)
def test_shipped_rego_passes_the_api_validator(path: pathlib.Path) -> None:
    """A preset the API will not store is a broken artifact — the controller 422s forever on it."""
    try:
        validate_rego_source(path.read_text(), "block")
    except HTTPException as exc:
        pytest.fail(
            f"{path.name} is shipped but the API refuses it: {exc.status_code} {exc.detail}. "
            "The controller would retry this every 60s while the database keeps enforcing the old rego."
        )


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.name)
def test_shipped_rego_keeps_regex_headroom(path: pathlib.Path) -> None:
    """Fail BEFORE the cap, so adding a rule is a local failure naming the budget, not a cluster 422."""
    ops = _regex_ops(path.read_text())
    assert ops <= REGEX_OP_CAP, (
        f"{path.name} uses {ops} regex ops, over the API's cap of {REGEX_OP_CAP} — it cannot be stored"
    )
    assert ops <= REGEX_OP_CAP - 1, (
        f"{path.name} uses {ops} of {REGEX_OP_CAP} regex ops, leaving no headroom. Combine patterns into "
        "single alternations (one `regex.match` over a list of patterns costs ONE op, regardless of how "
        "many patterns the list holds) rather than ANDing several calls together."
    )


@pytest.mark.parametrize("path", SHIPPED, ids=lambda p: p.name)
def test_shipped_rego_keeps_line_headroom(path: pathlib.Path) -> None:
    """Fail BEFORE the cap. Reaching it freezes the baseline — see REGO_LINE_CAP."""
    lines = _code_lines(path.read_text())
    assert lines <= REGO_LINE_CAP, (
        f"{path.name} has {lines} code lines, over the API's cap of {REGO_LINE_CAP} — it cannot be stored"
    )
    # 10% of the budget, so there is room for a rule rather than for one more line.
    soft = int(REGO_LINE_CAP * 0.9)
    assert lines <= soft, (
        f"{path.name} has {lines} code lines of {REGO_LINE_CAP}, past the {soft}-line headroom mark. "
        "The enforced baseline must keep room to grow: at the cap a new security rule cannot be shipped "
        "at all, and the controller retries the push every 60s while the cluster enforces the old policy."
    )


def test_the_cap_constant_still_matches_the_validator() -> None:
    """If validate_rego_source's caps change, this test must be updated on purpose, not by accident."""
    src = (ROOT / "norviq" / "api" / "routers" / "policies.py").read_text()
    m = re.search(r"regex_ops\s*>\s*(\d+)", src)
    assert m, "could not find the regex-op cap in validate_rego_source — did it move?"
    assert int(m.group(1)) == REGEX_OP_CAP, (
        f"validate_rego_source caps at {m.group(1)} but this test assumes {REGEX_OP_CAP}"
    )
    m = re.search(r"len\(lines\)\s*>\s*(\d+)", src)
    assert m, "could not find the line cap in validate_rego_source — did it move?"
    assert int(m.group(1)) == REGO_LINE_CAP, (
        f"validate_rego_source caps at {m.group(1)} lines but this test assumes {REGO_LINE_CAP}"
    )


# ── overlay scopes cannot be trialled in audit mode ────────────────────────────────────────────────

def test_every_overlay_the_evaluator_collects_is_known_to_the_api() -> None:
    """The API's overlay list must not drift from the evaluator's.

    `_apply_policy_mode` softens a policy's own audit mode for BASE/FLOOR candidates only — overlays
    are excluded by construction. So an overlay accepted in audit mode is stored and badged "audit"
    and then hard-blocks, which is precisely the UI lie `_apply_policy_mode` exists to prevent. If a
    new overlay is added to `_collect_candidates` without being added here, it silently inherits that
    bug; this test is the tripwire.
    """
    import re as _re

    from norviq.api.routers.policies import _OVERLAY_SCOPES, _REMEDIATION_SUFFIX, _is_overlay_scope

    src = (ROOT / "norviq" / "engine" / "evaluator.py").read_text()
    # Every `f"{namespace}:__thing__"` key built next to an `"overlay": True` append.
    collected = set(_re.findall(r'f"\{namespace\}:(__[a-z_]+__)"', src))
    unknown = {s for s in collected if not _is_overlay_scope(s)}
    assert not unknown, (
        f"evaluator collects {sorted(unknown)} but the API does not treat them as overlays, so they "
        f"can be stored in audit mode and will hard-block anyway. Add them to _OVERLAY_SCOPES."
    )
    assert "__guardrail__" in _OVERLAY_SCOPES
    assert _is_overlay_scope(f"payments-agent{_REMEDIATION_SUFFIX}")
    # A real agent class must NOT be caught by this.
    assert not _is_overlay_scope("payments-agent")
    assert not _is_overlay_scope("__baseline__"), (
        "__baseline__ is a base/floor scope, not an overlay — it legitimately carries a mode"
    )
