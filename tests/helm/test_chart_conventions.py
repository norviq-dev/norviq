# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Helm-chart-quality conventions, pinned so they can't silently regress.

These encode the industry-standard bar an audit brought the chart up to: a values.schema.json that
validates operator input, honoring `helm -n/--namespace`, config-checksum rollout annotations, the
app.kubernetes.io label family, a `helm test` hook, kubeVersion enforcement, and a packaged README +
schema. Skipped when helm isn't on PATH.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

import pytest
import yaml

_CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"
_SECRETS = [
    "--set", "postgresql.password=x", "--set", "redis.password=x",
    "--set", "api.secretKey=xxxxxxxxxxxxxxxxxxxxxxxx",
]

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _run(*extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", "template", "norviq", str(_CHART),
         "--set-json", 'policyQuotaNamespaces=["default"]', *_SECRETS, *extra],
        capture_output=True, text=True,
    )


def _render(*extra: str) -> str:
    res = _run(*extra)
    assert res.returncode == 0, res.stderr[:800]
    return res.stdout


# ---- values.schema.json --------------------------------------------------------------------------

def test_schema_file_exists_and_is_valid_json() -> None:
    schema = _CHART / "values.schema.json"
    assert schema.is_file()
    json.loads(schema.read_text())


@pytest.mark.parametrize("bad", [
    "config.enforcementMode=monitor",   # derived flag, not a value
    "config.enforcementMode=allow",     # not a real mode
    "webhook.injection.sidecarMode=sidecar",
    "webhook.injection.failurePolicy=fail",  # wrong case
    "config.opaMode=wasm",
])
def test_schema_rejects_bad_enums(bad: str) -> None:
    res = _run("--set", bad)
    assert res.returncode != 0, f"schema accepted {bad}"


def test_schema_accepts_every_shipped_profile() -> None:
    for profile in ("values-dev.yaml", "values-light.yaml", "values-prod.yaml"):
        res = _run("-f", str(_CHART / profile))
        assert res.returncode == 0, f"{profile}: {res.stderr[:400]}"


# ---- namespace honors -n -------------------------------------------------------------------------

def test_namespace_follows_release_namespace() -> None:
    rendered = _render("-n", "acme-governance")
    namespaces = {
        d["metadata"]["namespace"]
        for d in yaml.safe_load_all(rendered)
        if d and d.get("metadata", {}).get("namespace")
    }
    # every chart-owned object lands in the -n namespace; the only other value is a tenant
    # namespace from policyQuotaNamespaces (the baseline policy's target), never a hardcoded "norviq"
    assert "acme-governance" in namespaces
    assert "norviq" not in namespaces


def test_no_template_hardcodes_values_namespace() -> None:
    hits = [p.name for p in (_CHART / "templates").rglob("*.yaml")
            if ".Values.namespace" in p.read_text()]
    assert hits == [], f"templates still hardcode .Values.namespace: {hits}"


# ---- checksum rollout ----------------------------------------------------------------------------

def test_config_consuming_deployments_have_checksum_annotations() -> None:
    rendered = _render()
    for doc in yaml.safe_load_all(rendered):
        if not doc or doc.get("kind") != "Deployment":
            continue
        name = doc["metadata"]["name"]
        if name not in ("norviq-api", "norviq-engine"):
            continue
        ann = (doc["spec"]["template"]["metadata"].get("annotations") or {})
        assert "checksum/config" in ann, f"{name} missing checksum/config"
        assert "checksum/secret" in ann, f"{name} missing checksum/secret"


def test_config_checksum_changes_when_config_changes() -> None:
    def api_checksum(*extra: str) -> str:
        for doc in yaml.safe_load_all(_render(*extra)):
            if doc and doc.get("metadata", {}).get("name") == "norviq-api" and doc.get("kind") == "Deployment":
                return doc["spec"]["template"]["metadata"]["annotations"]["checksum/config"]
        raise AssertionError("norviq-api deployment not found")
    assert api_checksum() != api_checksum("--set", "config.enforcementMode=audit")


# ---- labels --------------------------------------------------------------------------------------

def test_workloads_carry_app_kubernetes_io_component() -> None:
    rendered = _render()
    seen = set()
    for doc in yaml.safe_load_all(rendered):
        if doc and doc.get("kind") == "Deployment":
            labels = doc["spec"]["template"]["metadata"].get("labels", {})
            if "app.kubernetes.io/component" in labels:
                seen.add(labels["app.kubernetes.io/component"])
    assert {"api", "engine", "ui", "webhook"} <= seen, f"missing component labels: {seen}"


def test_selectors_stay_stable_not_versioned() -> None:
    """Selector labels must never include app.kubernetes.io/version or helm.sh/chart (they change
    every release and selectors are immutable)."""
    for doc in yaml.safe_load_all(_render()):
        if doc and doc.get("kind") in ("Deployment", "StatefulSet"):
            sel = doc["spec"]["selector"]["matchLabels"]
            assert "app.kubernetes.io/version" not in sel
            assert "helm.sh/chart" not in sel


# ---- helm test hook + packaging ------------------------------------------------------------------

def test_helm_test_hook_present() -> None:
    res = subprocess.run(
        ["helm", "template", "norviq", str(_CHART), "--set-json", 'policyQuotaNamespaces=["default"]',
         *_SECRETS, "--show-only", "templates/tests/test-connection.yaml"],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr[:400]
    doc = yaml.safe_load(res.stdout)
    assert doc["kind"] == "Pod"
    assert doc["metadata"]["annotations"]["helm.sh/hook"] == "test"


def test_kubeversion_is_declared() -> None:
    chart = yaml.safe_load((_CHART / "Chart.yaml").read_text())
    assert chart.get("kubeVersion", "").startswith(">=1.30")


def test_inproc_cache_configmap_defaults_match_values_and_settings() -> None:
    """The ConfigMap `dig` fallbacks must match values.yaml, or a custom values file that omits the
    key silently gets DIFFERENT behaviour than the documented default.

    Written for a real bug: the fallback said 5 while values.yaml said 0, so any user whose values
    file left the key out would have silently enabled the in-process cache.
    """
    from norviq.config import NorviqSettings

    out = _render()
    # Shipped default is OFF — the cache is opt-in.
    assert 'NRVQ_EVALUATOR_INPROC_CACHE_TTL_S: "0"' in out, "chart default must render the cache DISABLED"
    # And the entry cap must agree with the pydantic default rather than drifting from it.
    expected_max = str(NorviqSettings(_env_file=None).evaluator_inproc_cache_max)
    assert f'NRVQ_EVALUATOR_INPROC_CACHE_MAX: "{expected_max}"' in out


@pytest.mark.parametrize("value", ["5", "0"])
def test_inproc_cache_opt_in_is_honoured(value: str) -> None:
    """An explicit value must survive templating. `| default` would swallow an explicit 0 (sprig
    treats 0 as empty), which is why the template uses `dig` — this pins that."""
    out = _render("--set", f"config.inprocCacheTtlS={value}")
    assert f'NRVQ_EVALUATOR_INPROC_CACHE_TTL_S: "{value}"' in out, f"--set {value} not honoured"
