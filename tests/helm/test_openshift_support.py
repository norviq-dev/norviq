# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""OpenShift / restricted-SCC support.

OpenShift assigns each namespace a UID RANGE (~1000650000+) and admits pods with a UID from that range
plus GID 0, so a chart that PINS runAsUser is rejected by the default restricted-v2 SCC whatever value
it pins. `openshift.enabled` makes the chart omit runAsUser/fsGroup and let the platform assign, while
KEEPING runAsNonRoot: true — the guarantee is unchanged, we just stop dictating WHICH non-root user.

Verified on kind under enforced PodSecurity `restricted` (the closest available approximation of a
restricted SCC): the install completes and the TLS hooks generate norviq-api-tls / norviq-webhook-tls
NON-ROOT, which is what previously failed — the old hooks ran `apk add openssl` as root because the
alpine/k8s image lacked openssl, and `runAsUser: 0` is rejected outright.

The bundled Postgres/Redis are excluded by design, not oversight: their official entrypoints start as
ROOT to chown the data dir before dropping to postgres(70)/redis(999). Forcing runAsNonRoot on them
breaks startup, and an arbitrary OpenShift UID cannot own PGDATA at all. Production already replaces
them (values-prod.yaml). The guard makes that a loud render failure rather than two StatefulSets stuck
in a rejection loop with nothing pointing at the cause.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest
import yaml


def _pod_specs(rendered: str):
    """Every podSpec in the render — Deployments, StatefulSets and hook Jobs alike.

    Parsed, not grepped: the templates legitimately DISCUSS `runAsUser: 0` in comments explaining why
    it was removed, and a ConfigMap embeds a pod template as text. A raw grep matches both and reports
    failures that are really prose.
    """
    for doc in yaml.safe_load_all(rendered):
        if not isinstance(doc, dict):
            continue
        spec = (doc.get("spec", {}).get("template", {}) or {}).get("spec")
        if isinstance(spec, dict):
            yield doc.get("kind"), doc.get("metadata", {}).get("name", "?"), spec


def _pinned_uids(rendered: str):
    """(location, uid) for every pinned runAsUser, pod-level and container-level."""
    for kind, name, spec in _pod_specs(rendered):
        sc = spec.get("securityContext") or {}
        if "runAsUser" in sc:
            yield f"{kind}/{name}", sc["runAsUser"]
        for c in (spec.get("initContainers") or []) + (spec.get("containers") or []):
            csc = c.get("securityContext") or {}
            if "runAsUser" in csc:
                yield f"{kind}/{name}/{c['name']}", csc["runAsUser"]

_CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"
_BASE = ["--set", "policyQuotaNamespaces={default}", "--set", "webhook.injection.enabled=true"]
_EXTERNAL = [
    "--set", "postgresql.enabled=false", "--set", "postgresql.host=pg.example.com",
    "--set", "redis.enabled=false", "--set", "redis.host=redis.example.com",
]

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _render(*extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", "template", "norviq", str(_CHART), *_BASE, *extra], capture_output=True, text=True
    )


def test_default_install_is_unchanged() -> None:
    """openshift.enabled defaults false: every existing install must render exactly as before."""
    res = _render()
    assert res.returncode == 0, res.stderr
    assert "runAsUser: 65532" in res.stdout, "pinned UIDs should remain on vanilla/AKS/EKS/GKE"


def test_openshift_mode_omits_every_pinned_uid() -> None:
    """A single pinned UID anywhere is enough for restricted-v2 to reject that pod."""
    res = _render("--set", "openshift.enabled=true", *_EXTERNAL)
    assert res.returncode == 0, res.stderr
    survivors = list(_pinned_uids(res.stdout))
    assert not survivors, f"pinned runAsUser survived openshift.enabled=true: {survivors}"


def test_openshift_mode_keeps_run_as_non_root() -> None:
    """Omitting the UID must not weaken the guarantee — the platform still enforces non-root."""
    res = _render("--set", "openshift.enabled=true", *_EXTERNAL)
    assert res.returncode == 0, res.stderr
    assert "runAsNonRoot: true" in res.stdout


def test_no_root_pods_in_either_mode() -> None:
    """The regression that blocked OpenShift entirely: the TLS hooks ran `runAsUser: 0`, which
    restricted-v2 rejects, so `helm install` died at the pre-install hook — nothing deployed at all."""
    for extra in ([], ["--set", "openshift.enabled=true", *_EXTERNAL]):
        res = _render(*extra)
        assert res.returncode == 0, res.stderr
        roots = [loc for loc, uid in _pinned_uids(res.stdout) if uid == 0]
        assert not roots, f"root pod rendered: {roots}"


def test_cert_hooks_use_the_first_party_bootstrap_image() -> None:
    """kubectl AND openssl baked in, so the hooks need neither a runtime `apk add` nor root — and the
    install path gains no network dependency (it must work air-gapped)."""
    res = _render()
    assert res.returncode == 0, res.stderr
    images = {c["image"] for _k, _n, sp in _pod_specs(res.stdout)
              for c in (sp.get("initContainers") or []) + (sp.get("containers") or [])}
    assert any("norviq-engine:bootstrap-" in i for i in images), images
    # Checked against real image fields, not the whole render: a template COMMENT still mentions
    # alpine/k8s to explain why it was replaced, and a text grep would match that prose.
    assert not any("alpine/k8s" in i for i in images), "a cert hook still uses the image lacking openssl"


def test_bundled_datastores_are_refused_under_openshift() -> None:
    """Loud render failure beats a 'successful' install whose StatefulSets never schedule."""
    res = _render("--set", "openshift.enabled=true")
    assert res.returncode != 0, "bundled datastores were allowed under openshift.enabled=true"
    assert "postgresql, redis" in res.stderr
    # The message must carry the remedy, not just the diagnosis.
    assert "postgresql.host" in res.stderr and "values-prod.yaml" in res.stderr


def test_external_datastores_are_the_supported_openshift_path() -> None:
    res = _render("--set", "openshift.enabled=true", *_EXTERNAL)
    assert res.returncode == 0, res.stderr


def test_guard_is_inert_when_openshift_is_off() -> None:
    """The bundled datastores stay perfectly valid for dev/vanilla installs."""
    assert _render().returncode == 0
