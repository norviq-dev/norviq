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
3. The same guard for the PRIMARY datastores: `postgresql.password` / `redis.password` must reject the
   shipped defaults (`norviq-pg-password` / `norviq-redis-password`), not just an empty value. Checking
   only for empty was an incomplete guard — values.yaml ships NON-empty literals, so a stock install
   with the hardened default posture rendered a published credential straight into NRVQ_PG_URL /
   NRVQ_REDIS_URL, for datastores that hold the policy store, the audit log and the bcrypt admin hash.

Skipped (not failed) when the `helm` binary isn't on PATH, so the suite still runs in minimal envs.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest
from tests.conftest import HELM_STRONG_DATASTORES

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
_CHART = _REPO_ROOT / "helm" / "norviq"
_PROD_VALUES = _CHART / "values-prod.yaml"

# The baseline-cluster-policy guard is unrelated to what we test here; disabling it keeps a bare
# `helm template` renderable without wiring policyQuotaNamespaces.
_BASELINE_OFF = ["--set", "baselineClusterPolicy.enabled=false"]

# requireStrongSecret (on by default) now refuses to render the SHIPPED-DEFAULT primary datastore
# credentials, not just empty ones — so every test that isn't specifically exercising that guard has to
# supply real ones, exactly as a real install must. `_template_raw` skips them for the guard tests below.
_STRONG_DATASTORES = HELM_STRONG_DATASTORES

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _template_raw(*extra: str, show_only: str | None = None) -> subprocess.CompletedProcess[str]:
    """Render with NO datastore credentials supplied — i.e. exactly what a stock `helm install` does."""
    cmd = ["helm", "template", "norviq", str(_CHART), *_BASELINE_OFF, *extra]
    if show_only is not None:
        cmd += ["--show-only", show_only]
    return subprocess.run(cmd, capture_output=True, text=True)


def _template(*extra: str, show_only: str | None = None) -> subprocess.CompletedProcess[str]:
    """Render with strong datastore credentials supplied (the normal, non-guard case)."""
    return _template_raw(*_STRONG_DATASTORES, *extra, show_only=show_only)


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
    """values-prod blanks the fleet credential → enabling the hub without supplying one FAILS."""
    res = _template(
        "--values", str(_PROD_VALUES),
        "--set", "fleet.hub.enabled=true",
    )
    assert res.returncode != 0
    assert "requireStrongSecret" in res.stderr


def test_fleet_hub_strong_credential_renders() -> None:
    """A supplied strong fleet credential renders cleanly (guard doesn't false-positive)."""
    res = _template(*_STRONG_FLEET, "--set", "config.requireStrongSecret=true")
    assert res.returncode == 0, res.stderr


# --- (3) requireStrongSecret must reject the shipped-default PRIMARY datastore credentials ---------
# Regression for the published-default-credential finding. The fleet store already had this guard
# (section 2); the primary store checked only for an empty value, so the shipped literal sailed through.


def test_stock_install_with_shipped_default_pg_password_fails_render() -> None:
    """The default values + the DEFAULT requireStrongSecret=true must NOT render a known credential."""
    res = _template_raw()
    assert res.returncode != 0, "stock render must fail rather than ship the published default DB password"
    assert "norviq-pg-password" in res.stderr


def test_shipped_default_redis_password_fails_render() -> None:
    """Same for the cache: supplying a strong DB password must not let the default redis one through."""
    res = _template_raw("--set", "postgresql.password=S7r0ng-Pg-Passw0rd")
    assert res.returncode != 0
    assert "norviq-redis-password" in res.stderr


def test_empty_datastore_password_still_fails_render() -> None:
    """The pre-existing empty-password guard must not regress (values-prod blanks both)."""
    res = _template_raw("--set", "postgresql.password=")
    assert res.returncode != 0
    assert "postgresql.password is empty" in res.stderr


def test_strong_datastore_credentials_render_cleanly() -> None:
    """Supplying real credentials renders, and the published defaults appear nowhere in the output."""
    res = _template_raw(*_STRONG_DATASTORES)
    assert res.returncode == 0, res.stderr
    assert "norviq-pg-password" not in res.stdout
    assert "norviq-redis-password" not in res.stdout
    assert "S7r0ng-Pg-Passw0rd" in res.stdout  # the operator's credential IS what gets wired


def test_dev_escape_hatch_still_renders_with_defaults() -> None:
    """requireStrongSecret=false remains the documented throwaway-cluster path (unchanged behaviour)."""
    res = _template_raw("--set", "config.requireStrongSecret=false")
    assert res.returncode == 0, res.stderr
    assert "norviq-pg-password" in res.stdout  # explicitly opted out of the guard
