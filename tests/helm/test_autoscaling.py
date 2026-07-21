# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Autoscaling renders correctly for every scalable component.

The HPA template used to hand-write api + webhook (CPU only) and omit the engine entirely, so the
standalone engine — which is on the enforcement hot path — could never scale. It is now one loop over
the three components with optional CPU and/or memory triggers. These tests pin:

  * a component that turns autoscaling on gets an HPA, and its Deployment drops the static `replicas`
    so the HPA (not a fixed number) owns the count;
  * the engine is included (the specific regression);
  * memory is rendered only when set, so a profile can scale on CPU alone, memory alone, or both;
  * enabling an HPA with NO metric fails the render rather than shipping an invalid object;
  * values-prod gives every scalable component an HA floor (minReplicas >= 2) and a memory trigger.

Skipped when helm isn't on PATH.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest
import yaml

_CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"
_PROD = _CHART / "values-prod.yaml"
# throwaway secrets so the fail-closed strong-secret guards don't block a render-only check
_SECRETS = [
    "--set", "postgresql.password=Throwaway-Pg-000000",
    "--set", "redis.password=Throwaway-Rd-000000",
    "--set", "api.secretKey=Throwaway-Jwt-Secret-For-Tests-0000000000",
]

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _run(*extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", "template", "norviq", str(_CHART),
         "--set", "policyQuotaNamespaces={default}", *extra],
        capture_output=True, text=True,
    )


def _render(*extra: str) -> str:
    res = _run(*extra)
    assert res.returncode == 0, res.stderr
    return res.stdout


def _hpas(rendered: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for doc in yaml.safe_load_all(rendered):
        if doc and doc.get("kind") == "HorizontalPodAutoscaler":
            out[doc["metadata"]["name"]] = doc["spec"]
    return out


def _static_replicas(rendered: str) -> dict[str, bool]:
    out: dict[str, bool] = {}
    for doc in yaml.safe_load_all(rendered):
        if doc and doc.get("kind") == "Deployment" and doc["metadata"]["name"].startswith("norviq-"):
            out[doc["metadata"]["name"]] = "replicas" in doc["spec"]
    return out


def test_default_profile_renders_no_hpa() -> None:
    """Autoscaling is off by default (single-node dev can't autoscale)."""
    assert _hpas(_render()) == {}


def test_prod_scales_api_engine_and_webhook() -> None:
    """The engine HPA is the specific regression — it must exist alongside api and webhook."""
    hpas = _hpas(_render("-f", str(_PROD), *_SECRETS))
    assert set(hpas) == {"norviq-api-hpa", "norviq-engine-hpa", "norviq-webhook-hpa"}


def test_prod_has_ha_floor_and_memory_trigger() -> None:
    hpas = _hpas(_render("-f", str(_PROD), *_SECRETS))
    for name, spec in hpas.items():
        assert spec["minReplicas"] >= 2, f"{name} minReplicas below HA floor"
        metrics = {m["resource"]["name"] for m in spec["metrics"]}
        assert metrics == {"cpu", "memory"}, f"{name} metrics = {metrics}"


def test_autoscaled_deployments_drop_static_replicas() -> None:
    """A Deployment that sets replicas AND is HPA-targeted flaps on every reconcile."""
    reps = _static_replicas(_render("-f", str(_PROD), *_SECRETS))
    assert reps["norviq-api"] is False
    assert reps["norviq-engine"] is False
    assert reps["norviq-webhook"] is False
    assert reps["norviq-ui"] is True  # ui is not autoscaled -> keeps its static replica count


def test_memory_only_and_cpu_only_both_render() -> None:
    cpu_only = _hpas(_render(*_SECRETS, "--set", "api.autoscaling.enabled=true",
                             "--set", "api.autoscaling.targetMemoryUtilizationPercentage="))
    assert {m["resource"]["name"] for m in cpu_only["norviq-api-hpa"]["metrics"]} == {"cpu"}

    mem_only = _hpas(_render(*_SECRETS, "--set", "api.autoscaling.enabled=true",
                             "--set", "api.autoscaling.targetCPUUtilizationPercentage=",
                             "--set", "api.autoscaling.targetMemoryUtilizationPercentage=80"))
    assert {m["resource"]["name"] for m in mem_only["norviq-api-hpa"]["metrics"]} == {"memory"}


def test_hpa_with_no_metric_fails_render() -> None:
    """An HPA needs at least one metric; a metric-less config must fail loudly, not ship broken."""
    res = _run(*_SECRETS, "--set", "api.autoscaling.enabled=true",
               "--set", "api.autoscaling.targetCPUUtilizationPercentage=",
               "--set", "api.autoscaling.targetMemoryUtilizationPercentage=")
    assert res.returncode != 0
    assert "at least one metric" in res.stderr
