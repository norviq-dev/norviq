# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Observability wiring, air-gapped image mirroring, and the OIDC/tls-proxy polish.

Closes the gap where the chart shipped a Grafana dashboard but nothing scraped the /metrics endpoint
(dashboard showed "No data"), routes third-party images through an optional mirror registry for
air-gapped installs, and fails fast on an OIDC config that can't work. Skipped when helm isn't on PATH.
"""

from __future__ import annotations

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


def _images(rendered: str) -> list[str]:
    out = []
    for doc in yaml.safe_load_all(rendered):
        if not doc:
            continue
        spec = (doc.get("spec", {}).get("template", {}).get("spec", {})
                if doc.get("kind") in ("Deployment", "StatefulSet") else {})
        for c in spec.get("containers", []) + spec.get("initContainers", []):
            if c.get("image"):
                out.append(c["image"])
    return out


# ---- TH-3: air-gapped mirror ---------------------------------------------------------------------

def test_default_third_party_images_are_upstream() -> None:
    imgs = _images(_render())
    assert any(i.startswith("openpolicyagent/opa") for i in imgs)
    assert any(i.startswith("redis:") for i in imgs)
    assert any(i.startswith("postgres:") for i in imgs)


def test_global_registry_mirrors_third_party_not_norviq() -> None:
    imgs = _images(_render("--set", "global.imageRegistry=mirror.example.com"))
    # third-party images get the mirror prefix
    assert any(i == "mirror.example.com/openpolicyagent/opa:1.18.0-static" for i in imgs), imgs
    assert any(i == "mirror.example.com/redis:7-alpine" for i in imgs), imgs
    # norviq images are NOT double-prefixed (they use images.registry, untouched)
    assert not any("mirror.example.com/ghcr.io" in i for i in imgs), imgs


# ---- observability: produce -> collect ------------------------------------------------------------

def test_scrape_annotations_off_by_default_on_by_flag() -> None:
    def api_svc(*extra: str) -> dict:
        for doc in yaml.safe_load_all(_render(*extra)):
            if doc and doc.get("kind") == "Service" and doc["metadata"]["name"] == "norviq-api":
                return doc
        raise AssertionError("norviq-api Service not found")

    off = api_svc().get("metadata", {}).get("annotations") or {}
    assert "prometheus.io/scrape" not in off
    on = api_svc("--set", "otel.metrics.scrapeAnnotations=true")["metadata"]["annotations"]
    assert on["prometheus.io/scrape"] == "true"
    assert on["prometheus.io/path"] == "/metrics"


def test_servicemonitor_gated_and_targets_api_metrics() -> None:
    assert "kind: ServiceMonitor" not in _render()  # off by default
    rendered = _render("--set", "otel.metrics.serviceMonitor.enabled=true")
    sm = next(d for d in yaml.safe_load_all(rendered) if d and d.get("kind") == "ServiceMonitor")
    assert sm["spec"]["selector"]["matchLabels"]["app"] == "norviq-api"
    ep = sm["spec"]["endpoints"][0]
    assert ep["path"] == "/metrics" and ep["port"] == "http"


def test_servicemonitor_additional_labels_applied() -> None:
    rendered = _render(
        "--set", "otel.metrics.serviceMonitor.enabled=true",
        "--set", "otel.metrics.serviceMonitor.additionalLabels.release=kube-prometheus-stack",
    )
    sm = next(d for d in yaml.safe_load_all(rendered) if d and d.get("kind") == "ServiceMonitor")
    assert sm["metadata"]["labels"]["release"] == "kube-prometheus-stack"


# ---- TH-4: OIDC guard ----------------------------------------------------------------------------

@pytest.mark.parametrize("missing", ["issuer", "jwksUrl", "audience"])
def test_oidc_enabled_without_required_field_fails(missing: str) -> None:
    setflags = ["--set", "oidc.enabled=true"]
    for f, v in (("issuer", "https://idp/"), ("jwksUrl", "https://idp/jwks"), ("audience", "aud")):
        if f != missing:
            setflags += ["--set", f"oidc.{f}={v}"]
    res = _run(*setflags)
    assert res.returncode != 0
    assert f"oidc.{missing}" in res.stderr


def test_oidc_fully_configured_renders() -> None:
    res = _run("--set", "oidc.enabled=true", "--set", "oidc.issuer=https://idp/",
               "--set", "oidc.jwksUrl=https://idp/jwks", "--set", "oidc.audience=aud")
    assert res.returncode == 0, res.stderr[:400]


# ---- TH-5: tls-proxy resources knob --------------------------------------------------------------

def test_tls_proxy_resources_are_configurable() -> None:
    rendered = _render("--set", "config.internalTls.proxyResources.limits.memory=200Mi")
    for doc in yaml.safe_load_all(rendered):
        if doc and doc.get("kind") == "Deployment" and doc["metadata"]["name"] == "norviq-api":
            proxy = next(c for c in doc["spec"]["template"]["spec"]["containers"] if c["name"] == "tls-proxy")
            assert proxy["resources"]["limits"]["memory"] == "200Mi"
            return
    raise AssertionError("norviq-api tls-proxy container not found")
