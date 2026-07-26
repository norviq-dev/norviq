# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`helm upgrade --reuse-values` must not hard-fail when the chart adds a new value.

Hit live during a GA rehearsal upgrade:

    Error: UPGRADE FAILED: nil pointer evaluating interface {}.enabled
           at templates/uninstall-finalizer-job.yaml

`--reuse-values` reuses only the USER-SUPPLIED values from the prior release — it does not merge in
values the newer chart added. So any template dereferencing a newly-added map hard-fails, and the
upgrade aborts entirely. This is not hypothetical: `--reuse-values` is the command operators reach for,
and every value added to this chart in future re-introduces the bug unless templates stay nil-tolerant.

Defaulting to TRUE when the key is absent is deliberate. Silently dropping this pre-delete hook would
bring back the stuck-finalizer bug it exists to prevent — CRs left Terminating forever and an
un-uninstallable release — which is a worse outcome than rendering a cleanup job nobody asked for.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

_CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"
_BASE = ["--set", "policyQuotaNamespaces={default}"]

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _render(*extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", "template", "norviq", str(_CHART), *_BASE, *extra], capture_output=True, text=True
    )


def test_upgrade_from_a_release_predating_the_value_still_renders() -> None:
    """The regression: crdFinalizerCleanup absent entirely, as it is in an older release's values."""
    res = _render("--set", "crdFinalizerCleanup=null")
    assert res.returncode == 0, f"--reuse-values upgrade path broke:\n{res.stderr}"
    assert "name: norviq-crd-cleanup" in res.stdout, (
        "the uninstall cleanup hook silently vanished — a later uninstall would hang on stuck finalizers"
    )


def test_explicit_disable_is_still_honoured() -> None:
    """Defaulting-when-absent must not override an operator who deliberately turned it off."""
    res = _render("--set", "crdFinalizerCleanup.enabled=false")
    assert res.returncode == 0, res.stderr
    assert "name: norviq-crd-cleanup" not in res.stdout


def test_default_install_renders_the_hook() -> None:
    res = _render()
    assert res.returncode == 0, res.stderr
    assert "name: norviq-crd-cleanup" in res.stdout


def test_image_override_survives_the_value_being_absent() -> None:
    """The same nil-map dereference applied to the image field one line further down."""
    res = _render("--set", "crdFinalizerCleanup=null")
    assert res.returncode == 0, res.stderr
    assert "kubectl" in res.stdout
