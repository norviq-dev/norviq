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
    """Every podSpec in the render — Deployments, StatefulSets, hook Jobs AND bare Pods.

    Parsed, not grepped: the templates legitimately DISCUSS `runAsUser: 0` in comments explaining why
    it was removed, and a ConfigMap embeds a pod template as text. A raw grep matches both and reports
    failures that are really prose.

    A bare `Pod` carries its podSpec at `.spec`, NOT `.spec.template.spec` — only workload controllers
    wrap it in a template. Walking just the wrapped shape silently skipped the `helm test` hook Pod,
    which kept a pinned `runAsUser` through openshift.enabled=true and was still reported as passing.
    That is the worst kind of test gap: it made a real hole look covered. `helm test norviq` is the
    command the README and the release runbook tell operators to run to confirm a release serves
    traffic, so the one pod left broken on OpenShift was the verification step itself.
    """
    for doc in yaml.safe_load_all(rendered):
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        name = doc.get("metadata", {}).get("name", "?")
        if kind == "Pod":
            spec = doc.get("spec")
            if isinstance(spec, dict):
                yield kind, name, spec
            continue
        spec = (doc.get("spec", {}).get("template", {}) or {}).get("spec")
        if isinstance(spec, dict):
            yield kind, name, spec


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


# --- uninstall hook image ------------------------------------------------------------------------
# `helm uninstall` was BROKEN for every 0.1.4 user: the pre-delete hook defaulted to
# `bitnami/kubectl:1.31`, and Bitnami removed those tags from Docker Hub in 2025. The pull 404s, the
# pod sits in ImagePullBackOff, and the uninstall dies on a deadline. That hook is what releases the
# norviq.io finalizers, so its failure strands every CR in Terminating — and a later reinstall adopts
# the tombstones, leaving the cluster blocking every tool call on `no_policy_loaded` while looking
# healthy. Found by deploying the published chart on AKS as a user would.
#
# The rule these tests encode: NO install- or uninstall-blocking hook may default to a third-party
# image. A first-party image cannot be deleted out from under us by an upstream.

def _hook_images(rendered: str, hook_substr: str) -> list[str]:
    out = []
    for doc in yaml.safe_load_all(rendered):
        if not isinstance(doc, dict):
            continue
        ann = (doc.get("metadata", {}) or {}).get("annotations") or {}
        if hook_substr not in (ann.get("helm.sh/hook") or ""):
            continue
        spec = doc.get("spec", {})
        ps = spec.get("template", {}).get("spec") if "template" in spec else spec
        if not isinstance(ps, dict):
            continue
        for c in (ps.get("containers") or []) + (ps.get("initContainers") or []):
            out.append(c["image"])
    return out


def test_uninstall_hook_does_not_default_to_a_third_party_image() -> None:
    """The exact regression: a vanished upstream tag must not be able to break `helm uninstall`."""
    res = _render("--set", "crdFinalizerCleanup.enabled=true")
    assert res.returncode == 0, res.stderr
    images = _hook_images(res.stdout, "pre-delete")
    assert images, "the crd-cleanup pre-delete hook did not render"
    for img in images:
        assert "bitnami/kubectl" not in img, f"uninstall hook is back on the removed image: {img}"
        assert "norviq-engine" in img, f"uninstall hook must default to the first-party image, got {img}"


def test_no_lifecycle_hook_defaults_to_a_third_party_image() -> None:
    """Same rule for every hook that can block install or upgrade, not just the one that bit us."""
    res = _render("--set", "crdFinalizerCleanup.enabled=true", "--set", "webhook.injection.enabled=true")
    assert res.returncode == 0, res.stderr
    for hook in ("pre-install", "post-install", "pre-delete"):
        for img in _hook_images(res.stdout, hook):
            assert "norviq-engine" in img, f"{hook} hook uses a third-party image: {img}"


def test_operator_can_still_pin_their_own_cleanup_image() -> None:
    """Defaulting to first-party must not remove the escape hatch for an air-gapped mirror."""
    res = _render("--set", "crdFinalizerCleanup.enabled=true",
                  "--set", "crdFinalizerCleanup.image=myco/kubectl:1.30")
    assert res.returncode == 0, res.stderr
    assert any("myco/kubectl:1.30" in i for i in _hook_images(res.stdout, "pre-delete"))
