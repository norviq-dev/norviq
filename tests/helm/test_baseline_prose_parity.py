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

import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
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


def _rendered_notes(*extra: str) -> str:
    """NOTES.txt as `helm install` would print it. `helm template` skips NOTES.txt, so a copy of the chart
    carries it as the data of a ConfigMap template, rendered with the same values."""
    if shutil.which("helm") is None:
        pytest.skip("helm not on PATH")
    with tempfile.TemporaryDirectory() as td:
        copy = Path(td) / "norviq"
        shutil.copytree(_ROOT / "helm/norviq", copy)
        body = "\n".join("    " + line for line in (copy / "templates/NOTES.txt").read_text().splitlines())
        (copy / "templates/zz-notes-render.yaml").write_text(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: notes-render\ndata:\n  notes: |\n" + body + "\n")
        res = subprocess.run(
            ["helm", "template", "norviq", str(copy), "--show-only", "templates/zz-notes-render.yaml",
             "--set-json", 'policyQuotaNamespaces=["agents"]', *extra], capture_output=True, text=True)
    assert res.returncode == 0, res.stderr[-600:]
    return yaml.safe_load(res.stdout)["data"]["notes"]


def test_notes_says_what_the_install_actually_renders():
    """NOTES.txt is printed after every install. It must agree with the mode the baseline CRs were just
    rendered in — enforcing by default, auditing under the flag — and on an enforcing install it must name
    all three ways off, because that is the moment an operator learns the baseline blocks.

    It printed `enforcementMode=block` for any value but audit; the CRD also admits `escalate`, which the
    engine enforces like block (only `audit` softens a policy), so the rendered value is what it prints."""
    default = _rendered_notes()
    assert "ENFORCES (baselineClusterPolicy.enforcementMode=block" in default and "It is in AUDIT" not in default
    assert "20 of its 21 controls" in default, "NOTES no longer states what the strict baseline does"
    for way_off in ("--set baselineClusterPolicy.enforcementMode=audit", "PUT /api/v1/settings?namespace=<ns>",
                    '"enforcement_mode": "audit"', "PUT /api/v1/baseline/controls", "Monitor or Off"):
        assert way_off in default, f"an enforcing install's NOTES no longer names {way_off!r}"
    audited = _rendered_notes("--set", "baselineClusterPolicy.enforcementMode=audit")
    assert "It is in AUDIT" in audited and "ENFORCES" not in audited
    assert "Baseline controls are saved" in audited, "AUDIT NOTES must say saved controls still enforce"
    escalated = _rendered_notes("--set", "baselineClusterPolicy.enforcementMode=escalate")
    assert "ENFORCES (baselineClusterPolicy.enforcementMode=escalate" in escalated
    assert "enforcementMode=block" not in escalated.split("To turn it off")[0]
    # The console compiles `strict`; next to another preset covers() is False, so its Off and Monitor
    # relax nothing and a save is one more floor. NOTES must not offer it as a way off there.
    moderate = _rendered_notes("--set", "baselineClusterPolicy.preset=moderate")
    assert "one control:" not in moderate and "no per-control switch" in moderate
    moderate_audit = _rendered_notes("--set", "baselineClusterPolicy.preset=moderate",
                                     "--set", "baselineClusterPolicy.enforcementMode=audit")
    assert "replace it" not in moderate_audit and "second floor" in moderate_audit
    assert "replace it" in audited
    off = _rendered_notes("--set", "baselineClusterPolicy.enabled=false")
    assert "ENFORCES" not in off and "It is in AUDIT" not in off and "NAMESPACE BASELINE: none" in off


def test_values_comment_names_the_default_it_sits_above():
    """The comment over `enforcementMode: block` opened "audit (default)" after the default became block."""
    text = (_ROOT / "helm/norviq/values.yaml").read_text()
    block = text[text.index("baselineClusterPolicy:"):text.index("\nimages:")]
    assert "audit (default)" not in block, "values.yaml still calls audit the baseline default"
    assert "block (default" in block
    for way_off in ("Target Settings -> Monitor", "/api/v1/baseline/controls"):
        assert way_off in block, f"values.yaml no longer names {way_off!r} as a way off the baseline"

