# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Helm/supply-chain hardening guards, batch P3 (FAIL-ON-BUG regressions).

Covers four defects from the pre-GA hunt (DEFECT-LEDGER), each of which fails against the pre-fix
tree and passes after:

* DEF-004 (P1): a stock PROD install still rendered NRVQ_PG_URL / NRVQ_REDIS_URL with the well-known
  shipped default DB/Redis passwords. The prod overlay now blanks them and secret.yaml grows a
  `config.requireStrongSecret` `{{ fail }}` gate that refuses to render an empty main-datastore
  credential — forcing the operator to supply a strong one. The single-node dev defaults are
  non-empty, so a plain `helm install` is unaffected.
* DEF-029 (P3): the primary app containers shipped NO securityContext and relied on an external
  PodSecurity/Kyverno mutation. The webhook container now carries the restricted profile.
* DEF-002 (P3): only Dockerfile.api stamped build provenance; engine/ui/webhook now carry the same
  NRVQ_BUILD_GIT_SHA env + org.opencontainers.image.revision label (+ /app/.build_git_sha for
  engine/webhook).
* DEF-042 (P3): the wait-for-api comment falsely claimed failurePolicy=Ignore; it now attributes the
  no-deadlock guarantee to the namespaceSelector excluding the control-plane namespace.

Helm-dependent tests skip (not fail) when the `helm` binary isn't on PATH; the Dockerfile/comment
file checks are pure reads and always run.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest
import yaml

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
_CHART = _REPO_ROOT / "helm" / "norviq"
_PROD_VALUES = _CHART / "values-prod.yaml"

# The baseline-cluster-policy guard is unrelated to what we test here; disabling it keeps a bare
# `helm template` renderable without wiring policyQuotaNamespaces.
_BASELINE_OFF = ["--set", "baselineClusterPolicy.enabled=false"]

requires_helm = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _template(*extra: str, show_only: str | None = None) -> subprocess.CompletedProcess[str]:
    cmd = ["helm", "template", "norviq", str(_CHART), *_BASELINE_OFF, *extra]
    if show_only is not None:
        cmd += ["--show-only", show_only]
    return subprocess.run(cmd, capture_output=True, text=True)


def _docs(manifest: str) -> list[dict]:
    return [d for d in yaml.safe_load_all(manifest) if d]


def _primary_container(manifest: str, deployment: str, container: str) -> dict:
    for d in _docs(manifest):
        if d.get("kind") == "Deployment" and d["metadata"]["name"] == deployment:
            for c in d["spec"]["template"]["spec"]["containers"]:
                if c["name"] == container:
                    return c
    raise AssertionError(f"container {container!r} not found in Deployment {deployment!r}")


# --- DEF-004: prod install must not ship the default main-datastore credentials --------------------


@requires_helm
def test_def004_prod_overlay_blank_db_password_fails_render() -> None:
    """PROD overlay blanks postgresql/redis.password → requireStrongSecret gate must FAIL the render.

    Pre-fix: values-prod did not blank the passwords and secret.yaml had no gate, so this render
    succeeded and NRVQ_PG_URL embedded `norviq-pg-password` (the whole defect). Post-fix it aborts.
    """
    res = _template("--values", str(_PROD_VALUES))
    assert res.returncode != 0, "prod overlay must refuse to render without a supplied DB password"
    assert "postgresql.password" in res.stderr
    assert "requireStrongSecret" in res.stderr


@requires_helm
def test_def004_prod_overlay_blank_redis_password_fails_render() -> None:
    """With a strong PG password supplied but redis still blank, the redis gate fires."""
    res = _template(
        "--values", str(_PROD_VALUES),
        "--set", "postgresql.password=Str0ngPgPw",
    )
    assert res.returncode != 0
    assert "redis.password" in res.stderr


@requires_helm
def test_def004_prod_overlay_strong_credentials_render_no_default() -> None:
    """Supplying strong DB + Redis passwords renders, and the shipped defaults never appear."""
    res = _template(
        "--values", str(_PROD_VALUES),
        "--set", "postgresql.password=Str0ngPgPw",
        "--set", "redis.password=Str0ngRedisPw",
        show_only="templates/secret.yaml",
    )
    assert res.returncode == 0, res.stderr
    assert "norviq-pg-password" not in res.stdout
    assert "norviq-redis-password" not in res.stdout
    assert "Str0ngPgPw" in res.stdout and "Str0ngRedisPw" in res.stdout


@requires_helm
def test_def004_dev_default_still_renders() -> None:
    """The single-node dev defaults are non-empty, so the gate must NOT false-positive on them."""
    res = _template(show_only="templates/secret.yaml")
    assert res.returncode == 0, res.stderr
    assert "NRVQ_PG_URL" in res.stdout


# --- DEF-029: primary containers must carry a restricted securityContext --------------------------


@requires_helm
def test_def029_webhook_container_has_hardened_securitycontext() -> None:
    """The webhook primary container (not just its initContainer) carries the restricted profile.

    Pre-fix only the wait-for-api initContainer had a securityContext; the `webhook` container had
    none, so this assertion failed.
    """
    res = _template(show_only="templates/webhook-deployment.yaml")
    assert res.returncode == 0, res.stderr
    sc = _primary_container(res.stdout, "norviq-webhook", "webhook").get("securityContext")
    assert sc is not None, "webhook container must declare a securityContext"
    assert sc.get("runAsNonRoot") is True
    assert sc.get("allowPrivilegeEscalation") is False
    assert sc.get("readOnlyRootFilesystem") is True
    assert sc.get("capabilities", {}).get("drop") == ["ALL"]
    assert sc.get("seccompProfile", {}).get("type") == "RuntimeDefault"


@requires_helm
def test_def029_securitycontext_toggle_off() -> None:
    """securityContext.enabled=false defers to a cluster-level policy (no block rendered)."""
    res = _template(
        "--set", "securityContext.enabled=false",
        show_only="templates/webhook-deployment.yaml",
    )
    assert res.returncode == 0, res.stderr
    assert _primary_container(res.stdout, "norviq-webhook", "webhook").get("securityContext") is None


# --- DEF-002: uniform build provenance across all four shipped images ------------------------------


def _dockerfile(name: str) -> str:
    return (_REPO_ROOT / name).read_text(encoding="utf-8")


def test_def002_engine_dockerfile_stamps_provenance() -> None:
    src = _dockerfile("Dockerfile.engine")
    assert "ARG NRVQ_GIT_SHA" in src
    assert "ENV NRVQ_BUILD_GIT_SHA=${NRVQ_GIT_SHA}" in src
    assert "LABEL org.opencontainers.image.revision=${NRVQ_GIT_SHA}" in src
    assert "/app/.build_git_sha" in src


def test_def002_ui_dockerfile_stamps_provenance() -> None:
    src = _dockerfile("Dockerfile.ui")
    assert "ENV NRVQ_BUILD_GIT_SHA=${NRVQ_GIT_SHA}" in src
    assert "LABEL org.opencontainers.image.revision=${NRVQ_GIT_SHA}" in src


def test_def002_webhook_dockerfile_stamps_provenance() -> None:
    src = _dockerfile("webhook/Dockerfile")
    assert "ENV NRVQ_BUILD_GIT_SHA=${NRVQ_GIT_SHA}" in src
    assert "LABEL org.opencontainers.image.revision=${NRVQ_GIT_SHA}" in src
    # distroless final stage has no shell → the file is written in the builder and COPYed over.
    assert "/build/.build_git_sha" in src
    assert "/app/.build_git_sha" in src


# --- DEF-042: the wait-for-api comment must not claim failurePolicy=Ignore -------------------------


def test_def042_stale_failurepolicy_ignore_comment_removed() -> None:
    src = (_CHART / "templates" / "webhook-deployment.yaml").read_text(encoding="utf-8")
    assert "failurePolicy=Ignore" not in src, "stale/false failurePolicy=Ignore claim must be gone"
    assert "namespaceSelector" in src, "comment must attribute the guarantee to the namespaceSelector"


@requires_helm
def test_def042_rendered_failurepolicy_defaults_fail() -> None:
    """Corroborates the corrected comment: the injector actually defaults to failurePolicy: Fail."""
    res = _template(
        "--set", "webhook.injection.enabled=true",
        show_only="templates/webhook-config.yaml",
    )
    assert res.returncode == 0, res.stderr
    doc = next(d for d in _docs(res.stdout) if d.get("kind") == "MutatingWebhookConfiguration")
    assert doc["webhooks"][0]["failurePolicy"] == "Fail"
