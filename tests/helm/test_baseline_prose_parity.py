"""The chart described its audit-mode baseline as "fail-closed", in its own words, in two places.

NOTES.txt — printed on every install — said "keep it enabled to preserve fail-closed posture" and
two lines later said audit "provide[s] visibility only and do[es] not enforce blocks". The refusal
message in baseline-cluster-policy.yaml said an empty namespace list would leave agents "without the
fail-closed cluster baseline", while the comment ten lines above it in the same template correctly
said the baseline renders in audit and calls proceed. values.yaml ships enforcementMode: audit.

This is the class fixed in 0.2.3 for README and docs/configuration.md, recurring in the chart. The
chart/configmap/config.py parity test compares three machine-readable sources to each other and
passes; nothing reads the prose. This reads the prose.
"""

from __future__ import annotations

from pathlib import Path

import re

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATES = _ROOT / "helm/norviq/templates"


def test_the_chart_describes_the_baseline_posture_it_ships():
    """Rewritten for 0.2.6, when the baseline began shipping `block`.

    This asserted `audit` and carried a tripwire for the day that changed: re-read NOTES.txt and the
    template and decide whether "fail-closed" had become TRUE, rather than deleting the assertion. Re-read
    and decided: it has not. Twenty controls enforce, but one (`scope_violation_dangerous_tool`) only
    records, and an API outage still follows fallbackMode, which ships `allow`. So the text must say the
    baseline ENFORCES, name `audit` as the way back, and still not call it fail-closed.
    """
    values = yaml.safe_load((_ROOT / "helm/norviq/values.yaml").read_text())
    mode = values["baselineClusterPolicy"]["enforcementMode"]
    assert mode == "block", (
        f"baselineClusterPolicy.enforcementMode now ships as {mode!r}. If that is deliberate, re-read "
        f"NOTES.txt and baseline-cluster-policy.yaml and make them describe it, then update this test."
    )
    notes = (_TEMPLATES / "NOTES.txt").read_text()
    assert re.search(r"ENFORCES|enforces", notes), "NOTES.txt no longer says the baseline enforces"
    assert "enforcementMode=audit" in notes, "NOTES.txt no longer tells an operator how to keep the audit posture"
    for name in ("NOTES.txt", "baseline-cluster-policy.yaml"):
        text = (_TEMPLATES / name).read_text()
        stale = [line.strip() for line in text.splitlines()
                 if re.search(r"ships in audit|records non-compliance and does not block|defaults to `audit`", line)]
        assert not stale, f"{name} still describes the 0.2.5 audit default:\n  " + "\n  ".join(stale)
        hits = [line.strip() for line in text.splitlines() if "fail-closed" in line]
        assert not hits, f"{name} calls the baseline 'fail-closed'; a control only records and outages fail open:\n  " + "\n  ".join(hits)

