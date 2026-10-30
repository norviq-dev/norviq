# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`--set baselineClusterPolicy.enforcementMode=audit` is the install-time way off the enforcing baseline.

Every page that says the baseline enforces names this flag as the way back, so it has to reach the
object the controller syncs: one NrvqPolicy per namespace in policyQuotaNamespaces, whose
spec.enforcementMode becomes the stored policy's mode (webhook/controller.go buildPolicySyncPayload, then
evaluator._apply_policy_mode). The controller half is TestBuildPolicySyncPayload_ChartBaselineKeepsItsMode,
the engine half tests/engine/test_saved_controls_supersede_the_chart_baseline.py
(test_without_saved_controls_the_chart_baseline_governs: an audit baseline answers
`policy_audit_would_block:<rule>`). This is the chart half.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest
import yaml

CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not on PATH")


def _baselines(*extra: str) -> dict[str, dict]:
    res = subprocess.run(
        ["helm", "template", "norviq", str(CHART), "--set-json", 'policyQuotaNamespaces=["agents","chatbot-prod"]',
         *extra],
        capture_output=True, text=True)
    assert res.returncode == 0, res.stderr[-600:]
    return {doc["spec"]["target"]["namespace"]: doc["spec"] for doc in yaml.safe_load_all(res.stdout)
            if doc and doc.get("kind") == "NrvqPolicy" and doc["metadata"]["name"].startswith("baseline-cluster-guard-")}


def test_a_default_install_renders_an_enforcing_baseline_per_namespace() -> None:
    specs = _baselines()
    assert set(specs) == {"agents", "chatbot-prod"}
    for ns, spec in specs.items():
        assert spec["enforcementMode"] == "block", f"{ns}: {spec}"
        # The shape namespaceBaselineKey re-keys to <ns>:__baseline__: clusterPriority, a namespace, no class.
        assert "clusterPriority" in spec and "agentClass" not in spec["target"], spec


def test_the_install_flag_turns_every_baseline_to_audit() -> None:
    specs = _baselines("--set", "baselineClusterPolicy.enforcementMode=audit")
    assert {ns: s["enforcementMode"] for ns, s in specs.items()} == {"agents": "audit", "chatbot-prod": "audit"}


def test_an_empty_mode_falls_back_to_enforcing_not_to_nothing() -> None:
    """The template's `| default`. An emptied value must not render a CR the CRD rejects or one that audits."""
    specs = _baselines("--set", "baselineClusterPolicy.enforcementMode=")
    assert {s["enforcementMode"] for s in specs.values()} == {"block"}
