# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The chart's defaults silently WIN over norviq/config.py, so they must agree with it.

Found on a live cluster, after a deploy that was supposed to make an ungoverned namespace allow
traffic and did not. `config.no_policy_decision` had been changed to "allow", every unit test agreed,
and the namespace still returned `block / no_policy_loaded` — because
`helm/norviq/templates/configmap.yaml` sets `NRVQ_NO_POLICY_DECISION` from
`.Values.config.noPolicyDecision | default "deny"`, and an env var beats a pydantic default every
time. The Python default was decorative on every real install.

Same shape as the recurring defect in this codebase: two places holding one concept, and the one that
wins is not the one you changed. These tests read both sides and compare, so the next divergence fails
here rather than on a cluster three hours later.

They read the YAML as text rather than rendering with `helm template`, so they run in the hermetic
suite with no helm binary.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from norviq.config import settings

_ROOT = Path(__file__).resolve().parents[2]
_VALUES = _ROOT / "helm" / "norviq" / "values.yaml"
_CONFIGMAP = _ROOT / "helm" / "norviq" / "templates" / "configmap.yaml"
_WEBHOOK = _ROOT / "helm" / "norviq" / "templates" / "webhook-deployment.yaml"


def _template_default(path: Path, env_name: str) -> str:
    """The literal in `{{ .Values.x | default "LITERAL" | quote }}` for one env var.

    Two YAML shapes carry env vars in this chart and both must be readable, or the test passes by
    failing to find the thing it is meant to compare:
        configmap.yaml     NRVQ_X: {{ ... }}
        *-deployment.yaml  - name: NRVQ_X
                             value: {{ ... }}
    """
    text = path.read_text(encoding="utf-8")
    patterns = (
        rf"{re.escape(env_name)}:\s*\{{\{{[^}}]*?\|\s*default\s+\"([^\"]+)\"",           # configmap
        rf"name:\s*{re.escape(env_name)}\s*\n\s*value:\s*\{{\{{[^}}]*?\|\s*default\s+\"([^\"]+)\"",  # deployment
    )
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    raise AssertionError(f"{env_name} not found with a `| default` in {path.name}")


def _values_scalar(key_path: str) -> str:
    """Read a leaf scalar out of values.yaml by its indented key, comments ignored."""
    text = _VALUES.read_text(encoding="utf-8")
    leaf = key_path.rsplit(".", 1)[-1]
    match = re.search(rf"^\s*{re.escape(leaf)}:\s*([A-Za-z0-9_.-]+)", text, re.MULTILINE)
    assert match, f"{key_path} not found in values.yaml"
    return match.group(1)


def test_no_policy_decision_matches_the_code_default() -> None:
    """The one that actually bit: chart said deny, code said allow, chart won."""
    assert _values_scalar("config.noPolicyDecision") == settings.no_policy_decision
    assert _template_default(_CONFIGMAP, "NRVQ_NO_POLICY_DECISION") == settings.no_policy_decision


def test_sidecar_fallback_mode_matches_the_code_default() -> None:
    """Stamped into every injected sidecar by the webhook, so it wins there too."""
    assert _values_scalar("webhook.injection.fallbackMode") == settings.sdk_fallback_mode
    assert _template_default(_WEBHOOK, "NRVQ_SDK_FALLBACK_MODE") == settings.sdk_fallback_mode


def test_the_shipped_posture_is_allow_by_default() -> None:
    """States the product decision outright, so flipping either side is a deliberate act.

    The two tests above only prove the chart and the code AGREE — they would both pass if someone
    set both back to "deny". This one pins which way they agree.
    """
    assert settings.no_policy_decision == "allow", "a namespace with no policy must not be dropped"
    assert settings.sdk_fallback_mode == "allow", "our outage must not become the customer's outage"


@pytest.mark.parametrize(
    "env_name,path",
    [("NRVQ_NO_POLICY_DECISION", _CONFIGMAP), ("NRVQ_SDK_FALLBACK_MODE", _WEBHOOK)],
)
def test_the_defaults_are_documented_where_they_are_set(env_name: str, path: Path) -> None:
    """A bare `| default "x"` with no comment is how this drifted in the first place."""
    text = path.read_text(encoding="utf-8")
    idx = text.index(env_name)
    preceding = text[max(0, idx - 500) : idx]
    assert "config.py" in preceding, (
        f"{env_name} in {path.name} has no comment pointing at norviq/config.py — the next person to "
        "change the Python default will not know this silently overrides it"
    )
