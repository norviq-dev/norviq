# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The checks verify_release.py runs after `helm upgrade` must not pass for the wrong reason.

The review of the first version found two ways they could.

* check_store_after_upgrade said it sampled the store twice, 15s apart. It slept and then took both
  samples back to back. Spacing them out alone changed nothing for a crash, though: restartCount only
  rises, so the second sample decided either way. What neither version saw was a store pod REPLACED inside
  the window, whose new container starts again at restartCount 0. It now compares the pod's uid and the
  container's ID across the two samples.
* check_api_after_upgrade called the API rolled out when readyReplicas equalled updatedReplicas, which
  holds while old replicas are still counted. It then sent /readyz to any non-terminating API pod,
  which mid-rollout can be an old one. An old pod answering healthily is exactly the false pass an
  upgrade gate cannot afford.

kubectl and the port-forward are faked, so nothing here needs a cluster.
"""

from __future__ import annotations

import json
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))  # release scripts are not a package; import them by path
import verify_release as vr  # noqa: E402

STORE_IMAGE = "valkey/valkey:8.1-alpine@sha256:" + "2" * 64


def _ok(stdout: object = "", rc: int = 0) -> subprocess.CompletedProcess[str]:
    out = stdout if isinstance(stdout, str) else json.dumps(stdout)
    return subprocess.CompletedProcess(["kubectl"], rc, out, "")


@pytest.fixture(autouse=True)
def _fresh_results():
    vr.results.clear()
    yield
    vr.results.clear()


# ---- the store ----------------------------------------------------------------------------------------


def _store_pod(restarts: int, uid: str = "pod-a", container: str = "containerd://aaa") -> dict:
    return {"metadata": {"uid": uid},
            "spec": {"containers": [{"name": "redis", "image": STORE_IMAGE}]},
            "status": {"containerStatuses": [{"name": "redis", "ready": True, "restartCount": restarts,
                                              "containerID": container}]}}


def _patch_store(monkeypatch, events: list[str], restarts_after_sleep: int = 0,
                 pod_after_sleep: dict | None = None) -> None:
    slept = []

    def kubectl(_ctx, *args, timeout=300):
        if args[:2] == ("get", "pod"):
            events.append("sample")
            if slept and pod_after_sleep is not None:
                return _ok(pod_after_sleep)
            return _ok(_store_pod(restarts_after_sleep if slept else 0))
        return _ok("Valkey ... # Can't handle RDB format version 12")  # logs

    def sleep(seconds):
        events.append(f"sleep {seconds}")
        slept.append(seconds)

    monkeypatch.setattr(vr, "kubectl", kubectl)
    monkeypatch.setattr(vr, "_candidate_store_image", lambda _chart: STORE_IMAGE)
    monkeypatch.setattr(vr, "wait_until", lambda fn, timeout, interval=2.0: True)
    monkeypatch.setattr(vr.time, "sleep", sleep)


def test_the_store_is_sampled_twice_with_the_wait_between_the_samples(monkeypatch) -> None:
    events: list[str] = []
    _patch_store(monkeypatch, events, restarts_after_sleep=0)
    vr.check_store_after_upgrade("kind-x", Path("chart"))
    assert events == ["sample", "sleep 15", "sample"], (
        f"the two samples must bracket the 15s wait, got {events}"
    )
    assert vr.results[-1][1] is True, vr.results


def test_a_store_that_restarts_inside_the_window_fails_with_its_log(monkeypatch) -> None:
    events: list[str] = []
    _patch_store(monkeypatch, events, restarts_after_sleep=1)
    vr.check_store_after_upgrade("kind-x", Path("chart"))
    name, ok, detail = vr.results[-1]
    assert not ok and "restarts=1" in detail and "RDB format version 12" in detail, detail


def test_a_store_pod_replaced_inside_the_window_fails(monkeypatch) -> None:
    """A new pod's container starts at restartCount 0 and Ready, so both samples looked healthy."""
    events: list[str] = []
    _patch_store(monkeypatch, events, pod_after_sleep=_store_pod(0, uid="pod-b", container="containerd://bbb"))
    vr.check_store_after_upgrade("kind-x", Path("chart"))
    name, ok, detail = vr.results[-1]
    assert not ok, f"a store pod replaced between the samples passed the check: {detail}"
    assert "replaced within 15s" in detail and "RDB format version 12" in detail, detail


def test_a_store_container_replaced_in_place_fails_even_if_restart_count_reads_zero(monkeypatch) -> None:
    events: list[str] = []
    _patch_store(monkeypatch, events, pod_after_sleep=_store_pod(0, container="containerd://bbb"))
    vr.check_store_after_upgrade("kind-x", Path("chart"))
    assert vr.results[-1][1] is False, vr.results


# ---- the API ------------------------------------------------------------------------------------------


def _rs(name: str, revision: str, pod_hash: str, owner: str = "norviq-api") -> dict:
    return {"metadata": {"name": name, "labels": {"pod-template-hash": pod_hash},
                         "annotations": {"deployment.kubernetes.io/revision": revision},
                         "ownerReferences": [{"kind": "Deployment", "name": owner}]}}


def _pod(name: str, pod_hash: str, terminating: bool = False) -> dict:
    meta: dict = {"name": name, "labels": {"pod-template-hash": pod_hash}}
    if terminating:
        meta["deletionTimestamp"] = "2026-10-30T00:00:00Z"
    return {"metadata": meta}


# Mid-rollout: revision 3 is current. The old ReplicaSet's pod is listed FIRST and is not terminating.
# readyReplicas == updatedReplicas == spec.replicas although status.replicas still counts the old pod,
# which is the state the old readiness comparison called "rolled out".
DEPLOY = {"metadata": {"annotations": {"deployment.kubernetes.io/revision": "3"}},
          "spec": {"replicas": 2},
          "status": {"replicas": 3, "readyReplicas": 2, "updatedReplicas": 2, "availableReplicas": 2}}
REPLICASETS = {"items": [_rs("norviq-api-old", "2", "aaa"), _rs("norviq-api-new", "3", "bbb"),
                         _rs("someone-else", "3", "ccc", owner="not-norviq")]}
PODS = {"items": [_pod("norviq-api-old-1", "aaa"), _pod("norviq-api-new-1", "bbb"),
                  _pod("norviq-api-new-2", "bbb", terminating=True), _pod("foreign-1", "ccc")]}


def _patch_api(monkeypatch, rollout_rc: int) -> dict:
    seen: dict = {"forwarded": [], "kubectl": []}

    def kubectl(_ctx, *args, timeout=300):
        seen["kubectl"].append(args)
        if args[:2] == ("rollout", "status"):
            return _ok('deployment "norviq-api" successfully rolled out' if rollout_rc == 0
                       else "Waiting for deployment spec update to be observed...", rc=rollout_rc)
        if args[:2] == ("get", "deploy"):
            return _ok(DEPLOY)
        if args[:2] == ("get", "rs"):
            return _ok(REPLICASETS)
        if args[:2] == ("get", "pods"):
            return _ok(PODS)
        return _ok("", rc=1)

    @contextmanager
    def port_forward(_ctx, pod, port, target=8080):
        seen["forwarded"].append(pod)
        yield type("PF", (), {"port": port})()

    monkeypatch.setattr(vr, "kubectl", kubectl)
    monkeypatch.setattr(vr, "_PortForward", port_forward)
    monkeypatch.setattr(vr, "_api", lambda port, path, *a, **k: {"status": "ready", "redis": True})
    monkeypatch.setattr(vr, "wait_until", lambda fn, timeout, interval=2.0: fn())
    return seen


def test_readyz_goes_to_a_pod_of_the_current_replicaset(monkeypatch) -> None:
    seen = _patch_api(monkeypatch, rollout_rc=0)
    vr.check_api_after_upgrade("kind-x")
    assert seen["forwarded"] == ["norviq-api-new-1"], (
        f"/readyz went to {seen['forwarded']}. Only a pod of the Deployment's current revision can vouch "
        f"for the upgraded API; the old ReplicaSet's pod, a terminating one and another owner's are not it"
    )
    assert vr.results[-1][1] is True, vr.results


def test_an_unfinished_rollout_fails_however_the_replica_counts_look(monkeypatch) -> None:
    seen = _patch_api(monkeypatch, rollout_rc=1)
    vr.check_api_after_upgrade("kind-x")
    assert any(a[:2] == ("rollout", "status") for a in seen["kubectl"]), "kubectl rollout status was not used"
    assert vr.results[-1][1] is False, (
        "the check passed while `kubectl rollout status` said the rollout was not done (an old replica was "
        "still counted)"
    )
    assert not seen["forwarded"], "a /readyz from mid-rollout proves nothing about the upgraded API"


# ---- mutants the first tests left alive ----------------------------------------------------------------
# Each test below fails with one part of the check removed: the uid comparison, the health of the first
# sample, the deletionTimestamp filter. Each existing test changed more than one of those at once, so
# removing any single part still passed them.


def test_a_new_pod_fails_even_if_its_container_id_reads_the_same(monkeypatch) -> None:
    """Only the uid differs. Without the uid comparison this passed."""
    events: list[str] = []
    _patch_store(monkeypatch, events, pod_after_sleep=_store_pod(0, uid="pod-b"))
    vr.check_store_after_upgrade("kind-x", Path("chart"))
    name, ok, detail = vr.results[-1]
    assert not ok and "replaced within 15s" in detail, detail


def test_a_first_sample_that_was_never_healthy_fails(monkeypatch) -> None:
    """wait_until gave up (120 s) with the store not Ready; it turned Ready, same pod and container, by the
    second sample. Judging the second sample alone passed a store that missed its deadline."""
    events: list[str] = []
    not_ready = _store_pod(0)
    not_ready["status"]["containerStatuses"][0]["ready"] = False
    _patch_store(monkeypatch, events)
    slept: list[float] = []

    def kubectl(_ctx, *args, timeout=300):
        if args[:2] == ("get", "pod"):
            return _ok(_store_pod(0) if slept else not_ready)
        return _ok("Valkey ... loading")

    monkeypatch.setattr(vr, "kubectl", kubectl)
    monkeypatch.setattr(vr.time, "sleep", lambda s: slept.append(s))
    monkeypatch.setattr(vr, "wait_until", lambda fn, timeout, interval=2.0: fn())
    vr.check_store_after_upgrade("kind-x", Path("chart"))
    assert vr.results[-1][1] is False, vr.results


def test_a_terminating_pod_of_the_current_revision_is_never_probed(monkeypatch) -> None:
    """Listed first and of the current ReplicaSet: only the deletionTimestamp filter keeps it out."""
    _patch_api(monkeypatch, rollout_rc=0)
    pods = {"items": [_pod("norviq-api-new-2", "bbb", terminating=True), _pod("norviq-api-new-1", "bbb")]}
    real = vr.kubectl

    def kubectl(ctx, *args, timeout=300):
        return _ok(pods) if args[:2] == ("get", "pods") else real(ctx, *args, timeout=timeout)

    monkeypatch.setattr(vr, "kubectl", kubectl)
    assert vr._current_api_pods("kind-x") == ["norviq-api-new-1"]


# ---- the stage-2 tenant policy is gone before stage 3 ------------------------------------------------
#
# The upgrade path creates the tenant policy in stage 2 so the upgrade can be shown to keep it. Stage 3's
# expectations are those of a stock install, and the fresh path never has a tenant policy live there.
# Left in place, the strict tenant policy (priority 400, whole namespace) correctly outranks both probes,
# and the gate failed on the upgrade path only: the controls switch read block, and the propagation
# probe read allow on replica B.

_STAGES = ("check_stamped_shape", "install_published", "create_tenant_policy", "seed_bundled_store",
           "upgrade_to_candidate", "check_store_after_upgrade", "check_api_after_upgrade",
           "check_upgrade_preserved", "check_injection", "check_replica_propagation", "check_helm_test",
           "check_uninstall")


def _run_upgrade_main(monkeypatch, policy_lingers: bool = False) -> list[str]:
    events: list[str] = []

    for name in _STAGES:
        monkeypatch.setattr(vr, name, lambda *a, _n=name, **k: events.append(_n) or True)
    monkeypatch.setattr(vr, "check_enforcement", lambda *a, **k: events.append("check_enforcement") or "tok")
    monkeypatch.setattr(vr, "snapshot", lambda *a, **k: {})
    monkeypatch.setattr(vr, "stamp", lambda version, workdir: workdir)
    monkeypatch.setattr(vr, "resolve_upgrade_source", lambda requested, candidate: "0.2.5")
    monkeypatch.setattr(vr, "run", lambda *a, **k: _ok())
    monkeypatch.setattr(vr.shutil, "which", lambda tool: f"/usr/bin/{tool}")
    monkeypatch.setattr(vr, "wait_until", lambda fn, timeout, interval=2.0: fn())
    deleted: list[bool] = []

    def kubectl(_ctx, *args, timeout=300):
        if args[:2] == ("delete", "nrvqpolicy") and vr.POLICY in args and vr.TENANT in args:
            events.append("delete tenant policy")
            deleted.append(True)
            return _ok()
        if args[:2] == ("get", "nrvqpolicy"):
            if deleted and not policy_lingers:
                return subprocess.CompletedProcess(["kubectl"], 1, "", 'Error from server (NotFound): '
                                                   f'nrvqpolicies.norviq.io "{vr.POLICY}" not found')
            return _ok(f"nrvqpolicy.norviq.io/{vr.POLICY}")
        return _ok()

    monkeypatch.setattr(vr, "kubectl", kubectl)
    monkeypatch.setattr(sys, "argv", ["verify_release.py", "--version", "0.2.6", "--skip-create", "--keep"])
    vr.main()
    return events


def test_the_upgrade_path_removes_its_tenant_policy_before_the_stock_probes(monkeypatch) -> None:
    events = _run_upgrade_main(monkeypatch)
    assert "delete tenant policy" in events
    # After its survival is asserted, before any stage-3 decision is.
    assert events.index("check_upgrade_preserved") < events.index("delete tenant policy") \
        < events.index("check_enforcement") < events.index("check_replica_propagation")
    # Stage 4 still exercises the uninstall with a finalizer-bearing policy (it creates its own).
    assert events.index("check_uninstall") > events.index("check_replica_propagation")
    assert ("the pre-upgrade tenant policy is removed before the stock probes", True) in \
        [(n, ok) for n, ok, _ in vr.results]


def test_a_tenant_policy_that_never_goes_away_fails_the_gate(monkeypatch) -> None:
    _run_upgrade_main(monkeypatch, policy_lingers=True)
    assert ("the pre-upgrade tenant policy is removed before the stock probes", False) in \
        [(n, ok) for n, ok, _ in vr.results]
