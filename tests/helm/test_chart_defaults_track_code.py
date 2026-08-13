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


# --- the FOURTH place, which is where F-027 was hiding -------------------------------------------
#
# The tests above compare values.yaml, the templates and config.py. The injector binary carries its
# OWN default in webhook/config.go, and it said "block" while all three of those said "allow".
#
# That default never applied, because values.yaml sets fallbackMode explicitly and the chart always
# wins — which is exactly what made it dangerous rather than harmless. It is the branch that runs when
# the chart value is ABSENT: a slimmed values file, a hand-written manifest, a test harness building
# Config{} directly. In that case injected sidecars would silently fail CLOSED and a Norviq outage
# would stop the customer's agents, which is the one outcome this product's posture rules out.
#
# A default nobody exercises is not a safe default; it is an untested branch.

_WEBHOOK_CONFIG_GO = _ROOT / "webhook" / "config.go"


def _go_env_default(env_name: str) -> str:
    """The literal in `envStr("NRVQ_X", "LITERAL")` in the injector's Go config."""
    text = _WEBHOOK_CONFIG_GO.read_text(encoding="utf-8")
    match = re.search(rf'envStr\("{re.escape(env_name)}",\s*"([^"]*)"\)', text)
    assert match, f"{env_name} not found as an envStr default in webhook/config.go"
    return match.group(1)


def test_the_injector_binary_default_matches_the_code_default() -> None:
    assert _go_env_default("NRVQ_SDK_FALLBACK_MODE") == settings.sdk_fallback_mode, (
        "webhook/config.go and norviq/config.py disagree on the sidecar fallback mode. The chart "
        "normally hides this, which is why it must be asserted: the Go default is what an install "
        "that omits the chart value actually gets."
    )


def test_all_four_sources_of_the_fallback_mode_agree() -> None:
    """One concept, four homes. Named individually so a failure says WHICH one drifted."""
    sources = {
        "norviq/config.py": settings.sdk_fallback_mode,
        "values.yaml": _values_scalar("webhook.injection.fallbackMode"),
        "webhook-deployment.yaml": _template_default(_WEBHOOK, "NRVQ_SDK_FALLBACK_MODE"),
        "webhook/config.go": _go_env_default("NRVQ_SDK_FALLBACK_MODE"),
    }
    assert len(set(sources.values())) == 1, f"fallback mode disagrees across its homes: {sources}"


# --- the FIFTH home: the published docs (F-008) --------------------------------------------------
#
# PYPI-README.md is the first thing a new user reads and it is published to PyPI, where it outlives
# any given commit. It stated "Norviq is deny-by-default. With no policy loaded ... the decision is
# `deny`" — the exact opposite of what ships, and had been since the deny->allow flip. A user
# following it would write their first policy expecting a closed door and get an open one.
#
# Asserted against `settings` rather than spot-checked, because the failure mode is drift: whichever
# way a future maintainer moves the default, the README has to move with it.

_PYPI_README = _ROOT / "PYPI-README.md"


def test_the_published_readme_describes_the_shipped_no_policy_posture() -> None:
    text = _PYPI_README.read_text(encoding="utf-8")
    if settings.no_policy_decision == "allow":
        assert "no policy is ALLOWED, not denied" in text, (
            "PYPI-README must tell the reader that an unpolicied scope allows — it is what makes a "
            "typo'd agent_class look like a clean pass instead of an error"
        )
        assert "Norviq is deny-by-default." not in text, (
            "PYPI-README still claims deny-by-default while the product ships allow"
        )
    else:
        assert "deny" in text, "the README must describe a deny default if that is what ships"


def test_the_readme_says_how_to_get_the_other_posture() -> None:
    """Correcting the claim is only half of it — the reader needs the knob, or the honest default
    reads as 'this product does not lock anything down'."""
    text = _PYPI_README.read_text(encoding="utf-8")
    assert "noPolicyDecision" in text and "NRVQ_NO_POLICY_DECISION" in text
