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

import pytest
import yaml

from norviq.api import baseline
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


_BASELINE_PAGES = ("README.md", "docs/getting-started.md", "docs/configuration.md", "docs/concepts.md",
                   "docs/engineering/production-config.md", "docs/engineering/prod-deploy-runbook.md",
                   "examples/chatbot/k8s/README.md")
_STALE_AUDIT_DEFAULT = re.compile(
    r"baseline ships in `?audit|ships in \*\*audit\*\*|in `audit` mode until|baselines? in `audit`\)"
    r"|Each baseline ships in `audit`|which is how the chart's namespace baseline ships, softens")


def test_docs_describe_the_baseline_posture_that_ships():
    """Rewritten for 0.2.6. This asserted the baseline shipped `audit` and carried a tripwire: when that
    changed, re-read these pages and decide whether "fail-closed" had become true. It has not — a
    control only records and an outage still fails open — so the pages must stop describing the
    0.2.5 default, and must still not call the baseline fail-closed."""
    values = yaml.safe_load((_ROOT / "helm/norviq/values.yaml").read_text())
    mode = values["baselineClusterPolicy"]["enforcementMode"]
    assert mode == "block", f"baseline now ships {mode!r}; re-read {_BASELINE_PAGES} and update them and this test"
    for site in _BASELINE_PAGES:
        lines = (_ROOT / site).read_text().splitlines()
        stale = [f"{n+1}: {line.strip()}" for n, line in enumerate(lines)
                 if _STALE_AUDIT_DEFAULT.search(" ".join(lines[max(0, n - 1):n + 1]))]
        assert not stale, f"{site} still describes the 0.2.5 audit default:\n  " + "\n  ".join(stale)
        hits = [f"{n+1}: {line.strip()}" for n, line in enumerate(lines)
                if "fail-closed" in line and "baseline" in (line + _wrapped_from(lines, n)).lower()
                and "not fail-closed" not in line]
        assert not hits, f"{site} calls the namespace baseline 'fail-closed':\n  " + "\n  ".join(hits)


def _wrapped_from(lines: list[str], n: int) -> str:
    """The line a wrapped sentence continues from — none for a markdown table row, which is one unit.

    This read the previous line unconditionally, and a table row is not a continuation of the row above
    it: configuration.md's `config.noPolicyDecision` row ("Set `deny` for fail-closed", about the no-policy
    decision) was flagged as a claim about the baseline once the `config.enforcementMode` row above it
    named `baselineClusterPolicy.enforcementMode`. A row that itself calls the baseline fail-closed is
    still caught, by the row's own text."""
    if not n or lines[n].lstrip().startswith("|"):
        return ""
    return lines[n - 1]


# Every page that describes the shipped baseline posture, and the three ways off it. A page that says the
# baseline enforces and does not say how to stop it is the gap this guards: the operator reads "enforces",
# finds no switch, and turns the whole baseline off with enabled=false.
_OFF_SWITCH_PAGES = ("README.md", "docs/getting-started.md", "docs/configuration.md", "docs/concepts.md",
                     "docs/security-model.md", "docs/engineering/production-config.md", "helm/norviq/README.md")
_OFF_SWITCHES = {
    "install": re.compile(r"baselineClusterPolicy\.enforcementMode=audit"),
    "namespace": re.compile(r"/api/v1/settings\?namespace=<ns>`?\s+with\s+`?\{\s*\"enforcement_mode\":\s*\"audit\"\s*\}"),
    "control": re.compile(r"/api/v1/baseline/controls"),
}


def _unreleased_changelog() -> str:
    text = (_ROOT / "CHANGELOG.md").read_text()
    start = text.index("## [Unreleased]")
    return text[start:text.index("\n## [", start + 1)]


@pytest.mark.parametrize("site", [*_OFF_SWITCH_PAGES, "CHANGELOG.md"])
def test_every_posture_page_names_all_three_ways_off(site: str) -> None:
    text = _unreleased_changelog() if site == "CHANGELOG.md" else (_ROOT / site).read_text()
    missing = [scope for scope, pattern in _OFF_SWITCHES.items() if not pattern.search(text)]
    assert not missing, f"{site} describes the enforcing baseline but not the {missing} way(s) to turn it off"


# `config.enforcementMode` never softened a policy's block (`_resolve_posture` reads only the per-namespace
# mirror; the global mode reaches `_no_policy_decision` and the decision fallback). Two pages offered it as
# a visibility switch, and values-dev.yaml's description said its `audit` made a dev install log instead
# of enforce, which stopped being true the day the baseline began enforcing.
_GLOBAL_MODE_AS_A_SWITCH = re.compile(
    r"`config\.enforcementMode` \| `block` \| `block` \(enforce\) or `audit` \(visibility only\)"
    r"|enforcementMode: audit`?,? so a fresh dev install logs decisions instead of"
    r"|Global default enforcement mode \(individual `NrvqPolicy` objects can override"
    # And it is not a fallback decision: every OPA result path supplies one, and a module with no
    # `decision` is allowed under block and audit alike (measured, server and subprocess mode).
    r"|decision used when a module\s+returns none")


@pytest.mark.parametrize("site", [*_OFF_SWITCH_PAGES, "docs/deployment.md", "helm/norviq/values.yaml"])
def test_no_page_offers_the_global_mode_as_a_way_off(site: str) -> None:
    lines = (_ROOT / site).read_text().splitlines()
    stale = [f"{n+1}: {line.strip()}" for n, line in enumerate(lines)
             if _GLOBAL_MODE_AS_A_SWITCH.search(" ".join(lines[max(0, n - 1):n + 1]))]
    assert not stale, f"{site} offers config.enforcementMode as a way to stop blocking:\n  " + "\n  ".join(stale)


# How many baseline controls act, stated in prose, against the preset that decides it. The pages said
# "17 deny controls ... four monitor controls" after the defaults were read from the preset, which
# authors 20 to act (block or escalate) and one to record; an operator counting on four records got
# three refusals. Every "N of [its|the] 21" on a posture page must be the preset's own count.
_COUNT_SITES = (*_OFF_SWITCH_PAGES, "CHANGELOG.md", "docs/guides/policy-cookbook.md", "helm/norviq/values.yaml",
                "helm/norviq/templates/NOTES.txt", "helm/norviq/templates/baseline-cluster-policy.yaml",
                "ui/src/components/policies/BaselineControls.tsx")
_N_OF_TOTAL = re.compile(r"\b(\d+) of (?:its |the )?(\d+)\b(?=\s+(?:(?://|#)\s*)?(?:controls|are|at|act))")
_STALE_COUNTS = re.compile(r"four `?monitor`? controls|17 `?deny`? controls|seventeen rows|17 of (?:its |the )?21")


@pytest.mark.parametrize("site", _COUNT_SITES)
def test_every_count_of_the_baseline_controls_is_the_presets(site: str) -> None:
    defaults = baseline.default_effects("strict")
    acting, total = sum(1 for eff in defaults.values() if eff == "deny"), len(defaults)
    text = _unreleased_changelog() if site == "CHANGELOG.md" else (_ROOT / site).read_text()
    stale = _STALE_COUNTS.findall(text)
    assert not stale, f"{site} still states the 17/4 split: {stale}"
    wrong = [m.group(0) for m in _N_OF_TOTAL.finditer(text)
             if int(m.group(2)) == total and int(m.group(1)) != acting]
    assert not wrong, f"{site} says {wrong}; the strict preset has {acting} of {total} controls acting by default"

