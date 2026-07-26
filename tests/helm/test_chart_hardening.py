# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Helm chart rendering guards (FAIL-ON-BUG regressions).

Three chart-level defects, all rendered via `helm template`:

1. The Deployment must NOT hard-set `spec.replicas` while its HPA is enabled — otherwise every
   reconcile resets the count and fights the autoscaler (scale flapping). Covers the webhook and
   fleet-api Deployments.
2. With `config.requireStrongSecret` on, enabling the fleet hub with the shipped default fleet DB
   password (`norviq_dev`) — or an empty one — must fail the render loudly, so a prod install can
   never silently ship the well-known credential.
3. The PRIMARY datastore credentials are MANAGED, not shipped: the chart used to ship literal defaults
   (`norviq-pg-password` / `norviq-redis-password`) that a stock install wired straight into
   NRVQ_PG_URL / NRVQ_REDIS_URL. They are now generated on first install and reused on upgrade, so a
   default `helm install` needs no flags AND publishes no known credential.

Skipped (not failed) when the `helm` binary isn't on PATH, so the suite still runs in minimal envs.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import yaml

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
_CHART = _REPO_ROOT / "helm" / "norviq"
_PROD_VALUES = _CHART / "values-prod.yaml"

# The baseline-cluster-policy guard is unrelated to what we test here; disabling it keeps a bare
# `helm template` renderable without wiring policyQuotaNamespaces.
_BASELINE_OFF = ["--set", "baselineClusterPolicy.enabled=false"]

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _template(*extra: str, show_only: str | None = None) -> subprocess.CompletedProcess[str]:
    cmd = ["helm", "template", "norviq", str(_CHART), *_BASELINE_OFF, *extra]
    if show_only is not None:
        cmd += ["--show-only", show_only]
    return subprocess.run(cmd, capture_output=True, text=True)


def _deployment_has_replicas(manifest: str) -> bool:
    """True if a `replicas:` key appears in a `kind: Deployment` block (ignores StatefulSets)."""
    in_deployment = False
    for line in manifest.splitlines():
        stripped = line.strip()
        if stripped.startswith("kind:"):
            in_deployment = stripped == "kind: Deployment"
        elif in_deployment and stripped.startswith("replicas:"):
            return True
    return False


# --- (1) replicas must be omitted when the HPA owns the count -------------------------------------


def test_webhook_replicas_present_when_hpa_off() -> None:
    """Base values (webhook.autoscaling.enabled=false) → Deployment carries an explicit replica count."""
    res = _template(show_only="templates/webhook-deployment.yaml")
    assert res.returncode == 0, res.stderr
    assert _deployment_has_replicas(res.stdout)


def test_webhook_replicas_omitted_when_hpa_on() -> None:
    """HPA on → Deployment must NOT set replicas (old code hard-set it and fought the autoscaler)."""
    res = _template(
        "--set", "webhook.autoscaling.enabled=true",
        show_only="templates/webhook-deployment.yaml",
    )
    assert res.returncode == 0, res.stderr
    assert not _deployment_has_replicas(res.stdout)


_STRONG_FLEET = [
    "--set", "fleet.hub.enabled=true",
    "--set", "fleet.hub.postgresql.password=Str0ngFleetPw",
    "--set", "fleet.hub.pgUrl=postgresql://norviq:Str0ngFleetPw@fleet-postgresql-ha-rw:5432/norviq_fleet",
]


def test_fleet_api_replicas_present_when_hpa_off() -> None:
    res = _template(
        *_STRONG_FLEET,
        "--set", "fleet.hub.autoscaling.enabled=false",
        show_only="templates/fleet-hub.yaml",
    )
    assert res.returncode == 0, res.stderr
    assert _deployment_has_replicas(res.stdout)


def test_fleet_api_replicas_omitted_when_hpa_on() -> None:
    """HPA on → fleet-api Deployment must NOT set replicas (StatefulSet replicas are unaffected)."""
    res = _template(
        *_STRONG_FLEET,
        "--set", "fleet.hub.autoscaling.enabled=true",
        show_only="templates/fleet-hub.yaml",
    )
    assert res.returncode == 0, res.stderr
    assert not _deployment_has_replicas(res.stdout)


# --- (2) requireStrongSecret must reject the shipped-default fleet DB credential -------------------


def test_fleet_hub_shipped_default_password_fails_render() -> None:
    """requireStrongSecret + the base default `norviq_dev` → render must FAIL loudly."""
    res = _template("--set", "fleet.hub.enabled=true", "--set", "config.requireStrongSecret=true")
    assert res.returncode != 0
    assert "norviq_dev" in res.stderr


def test_prod_overlay_fleet_hub_empty_credential_fails_render() -> None:
    """values-prod blanks the fleet credential → enabling the hub without supplying one FAILS.

    The prod overlay also turns HA on and blanks the primary datastore passwords (a prod install
    supplies its own), so those are provided here to isolate the FLEET guard under test."""
    res = _template(
        "--values", str(_PROD_VALUES),
        "--set", "postgresql.password=S7r0ng-Pg-Passw0rd",
        "--set", "redis.password=S7r0ng-Redis-Passw0rd",
        "--set", "fleet.hub.enabled=true",
    )
    assert res.returncode != 0
    assert "requireStrongSecret" in res.stderr


def test_fleet_hub_strong_credential_renders() -> None:
    """A supplied strong fleet credential renders cleanly (guard doesn't false-positive)."""
    res = _template(*_STRONG_FLEET, "--set", "config.requireStrongSecret=true")
    assert res.returncode == 0, res.stderr


# --- (3) primary datastore credentials are generated, never shipped -------------------------------


def _secret_data(manifest: str) -> dict:
    for doc in yaml.safe_load_all(manifest):
        if doc and doc.get("kind") == "Secret" and doc["metadata"]["name"] == "norviq-secrets":
            return doc.get("stringData") or {}
    raise AssertionError("norviq-secrets not rendered")


def test_stock_install_needs_no_credential_flags() -> None:
    """A default `helm install` must just work — breaking that is not how a chart bundling its own
    datastores behaves (and was the regression this section replaced)."""
    res = _template()
    assert res.returncode == 0, res.stderr


def test_no_published_default_credential_is_ever_rendered() -> None:
    """The historical literals must not appear anywhere in a default render."""
    res = _template()
    assert res.returncode == 0, res.stderr
    assert "norviq-pg-password" not in res.stdout
    assert "norviq-redis-password" not in res.stdout


def test_generated_credentials_are_strong_and_shared_with_the_statefulsets() -> None:
    """The generated value must be strong AND the same one the datastore pods are started with —
    if the URL and the StatefulSet ever drifted, the API could not reach its own database."""
    res = _template()
    data = _secret_data(res.stdout)
    pg, redis = data["NRVQ_PG_PASSWORD"], data["NRVQ_REDIS_PASSWORD"]
    assert len(pg) >= 24 and len(redis) >= 24
    assert pg != redis
    assert pg in data["NRVQ_PG_URL"]
    assert redis in data["NRVQ_REDIS_URL"]
    # Both StatefulSets take it from that same Secret key, never from a literal.
    for doc in yaml.safe_load_all(res.stdout):
        if not doc or doc.get("kind") != "StatefulSet":
            continue
        for c in doc["spec"]["template"]["spec"]["containers"]:
            for env in c.get("env") or []:
                if env["name"] in ("POSTGRES_PASSWORD", "REDIS_PASSWORD"):
                    ref = env.get("valueFrom", {}).get("secretKeyRef", {})
                    assert ref.get("name") == "norviq-secrets", f"{env['name']} not from the Secret"
                    assert "value" not in env, f"{env['name']} still inlines a literal"


def test_explicit_credentials_win_over_generation() -> None:
    """An operator-supplied credential (or a sealed secret) is always used verbatim."""
    res = _template("--set", "postgresql.password=MyOwnPgPw", "--set", "redis.password=MyOwnRedisPw")
    data = _secret_data(res.stdout)
    assert data["NRVQ_PG_PASSWORD"] == "MyOwnPgPw"
    assert data["NRVQ_REDIS_PASSWORD"] == "MyOwnRedisPw"


def test_generated_credentials_differ_between_releases() -> None:
    """Two fresh installs must not get the same password (i.e. it is random, not derived)."""
    a = _secret_data(_template().stdout)["NRVQ_PG_PASSWORD"]
    b = _secret_data(_template().stdout)["NRVQ_PG_PASSWORD"]
    assert a != b


def test_ha_requires_an_explicit_credential() -> None:
    """HA manages its own credential material and cannot use the chart-generated value, so it must say
    so loudly rather than silently rendering an empty password."""
    pg = _template("--set", "postgresql.ha.enabled=true")
    assert pg.returncode != 0 and "postgresql.password" in pg.stderr
    rd = _template("--set", "redis.ha.enabled=true")
    assert rd.returncode != 0 and "redis.password" in rd.stderr
