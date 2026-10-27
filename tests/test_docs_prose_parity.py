"""Prose that names enforcement behaviour must agree with the code it describes.

Two instances of this repo's recurring defect — a control that reads as enforcing while enforcing
nothing — had migrated into the documentation, where nothing diffs it. The chart/configmap/config.py
parity test compares three machine-readable sources to each other and passes; no test read prose.

  * Six pages said five `rule_id`s "stay hard" in monitor/audit mode and cited `_POSTURE_EXEMPT_RULES`.
    The symbol no longer exists (`ImportError`), the set is `_posture_exempt_rules()`, and it holds
    two rules stock, not five: the four engine-health rules were deliberately removed so an outage
    in monitor mode reports rather than blocks. An operator reading the docs believed a namespace in
    audit would still block on `evaluator_error`. It would not.
  * Three pages called the chart's namespace baseline "fail-closed". It ships `enforcementMode:
    audit`, under which every control evaluates and records and the call PROCEEDS.

These tests read the prose. They are deliberately narrow — a sentence, a window, a heading — so a
wording change elsewhere does not fail them, and a change to the thing they guard does.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from norviq.engine.evaluator import _posture_exempt_rules

_ROOT = Path(__file__).resolve().parents[1]

# Every page that tells an operator which rules survive monitor/audit posture.
_EXEMPT_RULE_SITES = (
    "docs/security-model.md",
    "docs/concepts.md",
    "docs/guides/compliance.md",
    "docs/guides/policy-cookbook.md",
    "docs/guides/writing-policies.md",
    "docs/design/THREAT-COVERAGE.md",
)
# Rules that USED to be exempt and are now softened on purpose. If any of these is ever re-added to
# `_posture_exempt_rules`, this tuple is the thing to update — and the docs with it.
_SOFTENED = ("policy_load_pending", "evaluator_error", "evaluator_invalid_payload", "evaluator_timeout")
_RULE_ID = re.compile(r"`([a-z_]+)`")


def _hard_window(text: str) -> str:
    """The prose around the sentence that lists which rules stay hard."""
    # Anchor on the function name, which is specific; "stays hard" also occurs in prose about pack
    # overlays ("stay hard tighten-only"), and concepts.md has that 80 lines before the rule list.
    m = re.search(r"_posture_exempt_rules", text) or re.search(r"stays? hard", text)
    assert m, "page no longer says which rules stay hard — if that is deliberate, remove it from the site list"
    return text[max(0, m.start() - 500):m.end() + 500]


def test_every_page_names_the_live_exemption_function_not_the_dead_symbol():
    for site in _EXEMPT_RULE_SITES:
        text = (_ROOT / site).read_text()
        assert "_POSTURE_EXEMPT_RULES" not in text, (
            f"{site} cites `_POSTURE_EXEMPT_RULES`, which was removed from norviq/engine/evaluator.py; "
            f"the live set is `_posture_exempt_rules()`"
        )
        assert "_posture_exempt_rules" in text, f"{site} should point readers at `_posture_exempt_rules()`"


def test_no_page_claims_a_softened_rule_stays_hard():
    exempt = _posture_exempt_rules()
    for site in _EXEMPT_RULE_SITES:
        window = _hard_window((_ROOT / site).read_text())
        named = set(_RULE_ID.findall(window))
        wrongly_hard = [r for r in _SOFTENED if r in named and r not in exempt and not _says_softens(window, r)]
        assert not wrongly_hard, (
            f"{site} names {wrongly_hard} in its 'stays hard' sentence, but `_posture_exempt_rules()` "
            f"returns {sorted(exempt)}; those rules soften to audit in monitor mode"
        )
        for r in exempt:
            assert r in named, f"{site} does not name `{r}`, which `_posture_exempt_rules()` does keep hard"


def _says_softens(window: str, rule: str) -> bool:
    """The corrected pages mention the softened rules in order to SAY they soften. Accept that."""
    i = window.find(f"`{rule}`")
    return i != -1 and re.search(r"soften|not exempt|removed from the exemption", window[max(0, i - 200):i + 300]) is not None


def test_docs_do_not_call_the_audit_baseline_fail_closed():
    values = yaml.safe_load((_ROOT / "helm/norviq/values.yaml").read_text())
    mode = values["baselineClusterPolicy"]["enforcementMode"]
    assert mode == "audit", f"baseline now ships {mode!r}; re-read the three pages below and decide whether 'fail-closed' is now true"
    for site in ("docs/getting-started.md", "docs/engineering/production-config.md",
                 "docs/engineering/prod-deploy-runbook.md"):
        lines = (_ROOT / site).read_text().splitlines()
        hits = [f"{n+1}: {line.strip()}" for n, line in enumerate(lines)
                if "fail-closed" in line and "baseline" in (line + (lines[n - 1] if n else "")).lower()]
        assert not hits, (
            f"{site} calls the namespace baseline 'fail-closed' while values.yaml ships enforcementMode: "
            f"audit (evaluate, record, proceed):\n  " + "\n  ".join(hits)
        )
