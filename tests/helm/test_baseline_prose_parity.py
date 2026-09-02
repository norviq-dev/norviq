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

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_TEMPLATES = _ROOT / "helm/norviq/templates"


def test_the_chart_does_not_call_its_audit_mode_baseline_fail_closed():
    values = yaml.safe_load((_ROOT / "helm/norviq/values.yaml").read_text())
    mode = values["baselineClusterPolicy"]["enforcementMode"]
    assert mode == "audit", (
        f"baselineClusterPolicy.enforcementMode now ships as {mode!r}. If that is deliberate, this "
        f"test's premise has changed: re-read NOTES.txt and baseline-cluster-policy.yaml and decide "
        f"whether 'fail-closed' is now TRUE there, rather than deleting this assertion."
    )
    for name in ("NOTES.txt", "baseline-cluster-policy.yaml"):
        text = (_TEMPLATES / name).read_text()
        hits = [line.strip() for line in text.splitlines() if "fail-closed" in line]
        assert not hits, (
            f"{name} calls the baseline 'fail-closed' while values.yaml ships enforcementMode: audit, "
            f"under which every control evaluates and records and the call PROCEEDS. Say what audit "
            f"mode actually does:\n  " + "\n  ".join(hits)
        )
