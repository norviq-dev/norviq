# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""A Norviq outage must not become a cluster-functionality outage.

`failurePolicy: Fail` is correct for an enforcement product — an agent pod must never start
un-injected. But paired with a namespace-only selector it means Norviq's availability gates the
creation of EVERY pod in a governed namespace: that namespace's database, ingress controller, batch
jobs, none of which are ever injected. An outage drill confirmed it — with the injector scaled to 0,
pod CREATE was rejected in all four governed namespaces.

These tests pin the two properties that bound the blast radius: admission is gated on the pod's
agent-class label, and the system namespaces stay excluded so the webhook can never self-deadlock.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest
import yaml

_CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"
_BASE = ["--set", "baselineClusterPolicy.enabled=false", "--set", "webhook.injection.enabled=true"]

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _template(*extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", "template", "norviq", str(_CHART), *_BASE, *extra], capture_output=True, text=True
    )


def _webhook_config(*extra: str) -> dict:
    """Return the parsed MutatingWebhookConfiguration's single webhook entry."""
    res = _template(*extra)
    assert res.returncode == 0, res.stderr
    for doc in yaml.safe_load_all(res.stdout):
        if doc and doc.get("kind") == "MutatingWebhookConfiguration":
            return doc["webhooks"][0]
    raise AssertionError("no MutatingWebhookConfiguration rendered")


def test_admission_is_gated_on_the_agent_label_by_default() -> None:
    """The blast-radius fix: only pods that declare themselves agents go through the webhook."""
    wh = _webhook_config()
    exprs = wh.get("objectSelector", {}).get("matchExpressions", [])
    assert any(e["key"] == "norviq.io/agent-class" and e["operator"] == "Exists" for e in exprs), (
        "objectSelector does not gate on norviq.io/agent-class — a Norviq outage would block "
        "creation of every unrelated pod in a governed namespace"
    )


def test_fail_closed_default_is_preserved() -> None:
    """Narrowing the selector must not weaken the posture for the pods that ARE agents."""
    assert _webhook_config()["failurePolicy"] == "Fail"


def test_only_pod_create_is_intercepted() -> None:
    """Running pods are never touched, so narrowing takes effect as pods are recreated."""
    rules = _webhook_config()["rules"]
    assert len(rules) == 1
    assert rules[0]["operations"] == ["CREATE"]
    assert rules[0]["resources"] == ["pods"]


def test_system_namespaces_stay_excluded() -> None:
    """The self-deadlock guard: the webhook must never gate the control plane that runs it."""
    exprs = _webhook_config()["namespaceSelector"]["matchExpressions"]
    excluded = {v for e in exprs if e["operator"] == "NotIn" for v in e["values"]}
    for ns in ("kube-system", "kube-public", "kube-node-lease"):
        assert ns in excluded, f"{ns} not excluded — a Norviq outage could break the control plane"


def test_namespace_opt_in_is_still_required() -> None:
    """The label alone must not be enough — an agent pod in an un-enrolled namespace stays untouched."""
    exprs = _webhook_config()["namespaceSelector"]["matchExpressions"]
    assert any(
        e["key"] == "norviq-injection" and e["operator"] == "In" and e["values"] == ["enabled"]
        for e in exprs
    )


def test_namespace_wide_behaviour_is_recoverable() -> None:
    """Operators upgrading from namespace-wide injection need an escape hatch."""
    wh = _webhook_config("--set", "webhook.injection.gateOnlyAgentPods=false")
    assert "objectSelector" not in wh


def test_webhook_replicas_are_spread_across_nodes_by_default() -> None:
    """The fail-closed default's own justification cites HA. Both replicas were observed on ONE node,
    so a single drain would evict both and block pod creation everywhere Norviq governs. The
    constraint is soft (ScheduleAnyway), so single-node clusters still schedule normally."""
    res = _template("--set", "policyQuotaNamespaces={default}")
    assert res.returncode == 0, res.stderr
    for doc in yaml.safe_load_all(res.stdout):
        if doc and doc.get("kind") == "Deployment" and doc["metadata"]["name"] == "norviq-webhook":
            constraints = doc["spec"]["template"]["spec"].get("topologySpreadConstraints", [])
            assert constraints, "webhook has no topology spread — one drain can take out both replicas"
            assert constraints[0]["topologyKey"] == "kubernetes.io/hostname"
            assert constraints[0]["whenUnsatisfiable"] == "ScheduleAnyway"
            return
    raise AssertionError("norviq-webhook Deployment not rendered")
