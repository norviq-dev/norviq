# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The injected sidecar must actually RUN — not just render correctly.

Every enforcement proof we had ran through the control plane (`POST /evaluate` -> API -> OPA), which
bypasses the sidecar entirely. So the PEP *data plane* — the injected container that actually
intercepts an agent's tool calls — could be dead while every API-level test, dashboard and audit query
stayed green. It was: an injected sidecar crash-looped for hours with
"No usable temporary directory found" (readOnlyRootFilesystem + no writable scratch) while the control
plane reported healthy.

Two blind spots made that invisible and both are closed here:
  1. Pod-health checks only ever looked at the product namespace (`norviq`), where everything was Ready.
     The broken pod was in a TENANT namespace.
  2. Unit tests assert the injected *spec*; nothing asserted the resulting container survives start.

Read-only. Skips cleanly when there is no cluster, no injection-enabled namespace, or no injected pod
(a cluster with no agent workloads is a legitimate state, not a failure).

Select a context with NRVQ_TEST_KUBE_CONTEXT; otherwise the current kubectl context is used.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

SIDECAR_CONTAINER = "norviq-sidecar"
INJECTION_LABEL = "norviq-injection=enabled"
# app label of the ephemeral pod created by tests/integration/test_data_plane_enforcement.py — excluded
# below so the two suites can run in the same session without sampling each other's transient state.
PROBE_APP_LABEL = "norviq-dataplane-probe"

pytestmark = pytest.mark.skipif(shutil.which("kubectl") is None, reason="kubectl not on PATH")


def _kubectl(*args: str) -> subprocess.CompletedProcess[str]:
    ctx = os.environ.get("NRVQ_TEST_KUBE_CONTEXT")
    cmd = ["kubectl", *(["--context", ctx] if ctx else []), "--request-timeout=15s", *args]
    return subprocess.run(cmd, capture_output=True, text=True)


def _injection_namespaces() -> list[str]:
    res = _kubectl("get", "ns", "-l", INJECTION_LABEL, "-o", "json")
    if res.returncode != 0:
        pytest.skip(f"no reachable cluster: {res.stderr.strip()[:120]}")
    return [item["metadata"]["name"] for item in json.loads(res.stdout).get("items", [])]


def _injected_pods(namespace: str) -> list[dict]:
    res = _kubectl("get", "pods", "-n", namespace, "-o", "json")
    if res.returncode != 0:
        return []
    pods = json.loads(res.stdout).get("items", [])
    return [
        p for p in pods
        if any(c.get("name") == SIDECAR_CONTAINER for c in p["spec"].get("containers", []))
        and not _is_ephemeral_probe(p)
    ]


def _is_ephemeral_probe(pod: dict) -> bool:
    """True for the throwaway pod test_data_plane_enforcement.py creates.

    That pod is deliberately short-lived, so when the two suites run together this one would sample it
    mid-creation (sidecar not Ready yet) or mid-termination and report a false CrashLoop/NotReady —
    a flake that says 'the PEP is down' when nothing is wrong. Steady-state workloads only.
    """
    meta = pod.get("metadata", {})
    if (meta.get("labels") or {}).get("app") == PROBE_APP_LABEL:
        return True
    return meta.get("deletionTimestamp") is not None


def _sidecar_status(pod: dict) -> dict | None:
    for status in pod.get("status", {}).get("containerStatuses", []) or []:
        if status.get("name") == SIDECAR_CONTAINER:
            return status
    return None


def _all_injected_pods() -> list[tuple[str, dict]]:
    namespaces = _injection_namespaces()
    if not namespaces:
        pytest.skip(f"no namespaces labelled {INJECTION_LABEL}")
    found = [(ns, pod) for ns in namespaces for pod in _injected_pods(ns)]
    if not found:
        pytest.skip("no injected agent workloads deployed (valid empty state)")
    return found


def test_injected_sidecar_is_not_crashlooping() -> None:
    """The exact shape of the regression: the sidecar dies at start and never serves a decision."""
    failures = []
    for namespace, pod in _all_injected_pods():
        status = _sidecar_status(pod)
        if status is None:
            continue
        waiting = (status.get("state") or {}).get("waiting") or {}
        reason = waiting.get("reason", "")
        if reason in {"CrashLoopBackOff", "RunContainerError", "CreateContainerConfigError"}:
            failures.append(
                f"{namespace}/{pod['metadata']['name']}: sidecar {reason} "
                f"(restarts={status.get('restartCount')}) — the PEP data plane is down: "
                f"{waiting.get('message', '')[:160]}"
            )
    assert not failures, "injected enforcement sidecar is not running:\n  " + "\n  ".join(failures)


def test_injected_sidecar_reports_ready() -> None:
    """A NotReady sidecar means the workload never passes its readiness gate."""
    not_ready = [
        f"{ns}/{pod['metadata']['name']} (restarts={(_sidecar_status(pod) or {}).get('restartCount')})"
        for ns, pod in _all_injected_pods()
        if (_sidecar_status(pod) or {}).get("ready") is False
    ]
    assert not not_ready, "injected sidecar present but not Ready: " + ", ".join(not_ready)


def test_injected_sidecar_has_a_writable_scratch_mount() -> None:
    """Root cause guard: readOnlyRootFilesystem with no writable path kills the mTLS cert load."""
    offenders = []
    for namespace, pod in _all_injected_pods():
        for container in pod["spec"].get("containers", []):
            if container.get("name") != SIDECAR_CONTAINER:
                continue
            read_only = (container.get("securityContext") or {}).get("readOnlyRootFilesystem")
            mounts = {m.get("mountPath") for m in container.get("volumeMounts", []) or []}
            if read_only and "/tmp" not in mounts:
                offenders.append(f"{namespace}/{pod['metadata']['name']} mounts={sorted(mounts)}")
    assert not offenders, (
        "sidecar has readOnlyRootFilesystem but no writable /tmp — it cannot materialize its mTLS "
        "cert and will crash at start: " + ", ".join(offenders)
    )
