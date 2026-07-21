# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The OPA sidecar must never be reachable from another pod.

OPA's admin API (``/v1/policies``) is unauthenticated by default AND read-WRITE: anything that can
reach :8181 can rewrite or delete the loaded policy — i.e. silently disable the PDP that is supposed to
govern it. That is the exact adversary Norviq exists to stop (a compromised agent workload), so a
cluster-reachable bind is a full enforcement bypass, not a hardening nit.

It shipped as ``--addr=0.0.0.0:8181`` and no test caught it because every auth probe came from OUTSIDE
through the API Service (which correctly 401s). :8181 is exposed by no Service at all, so it is
invisible to a port-forward — you only see it by hitting another pod's IP from inside the cluster.

The app talks to its own sidecar over ``NRVQ_OPA_URL=http://localhost:<port>`` (configmap.yaml), so
loopback costs nothing. Skipped when helm isn't on PATH.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest
import yaml

_CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _render(*extra: str) -> str:
    res = subprocess.run(
        ["helm", "template", "norviq", str(_CHART),
         "--set", "policyQuotaNamespaces={default,chatbot-prod}", *extra],
        capture_output=True, text=True,
    )
    assert res.returncode == 0, res.stderr
    return res.stdout


def _opa_containers(rendered: str) -> list[tuple[str, list[str]]]:
    out: list[tuple[str, list[str]]] = []
    for doc in yaml.safe_load_all(rendered):
        if not doc or doc.get("kind") not in ("Deployment", "StatefulSet"):
            continue
        spec = doc["spec"]["template"]["spec"]
        for container in spec.get("containers", []):
            if container.get("name") == "opa":
                out.append((doc["metadata"]["name"], list(container.get("args", []))))
    return out


def test_opa_sidecars_are_rendered() -> None:
    """Guard the guard: if OPA stops rendering, the assertions below would pass vacuously."""
    assert len(_opa_containers(_render())) == 2


def test_opa_never_binds_all_interfaces() -> None:
    for name, args in _opa_containers(_render()):
        addr = [a for a in args if a.startswith("--addr=")]
        assert addr, f"{name}: OPA has no explicit --addr; it would default to a non-loopback bind"
        assert addr[0].startswith("--addr=127.0.0.1:"), (
            f"{name}: OPA admin API must bind loopback only, got {addr[0]}. "
            "Binding 0.0.0.0 exposes an unauthenticated read-write policy API to every pod."
        )
        assert "0.0.0.0" not in " ".join(args), f"{name}: 0.0.0.0 still present in OPA args: {args}"


def test_opa_v0_compatibility_flag_is_preserved() -> None:
    """The policies are v0 rego; dropping this flag silently breaks every decision."""
    for name, args in _opa_containers(_render()):
        assert "--v0-compatible" in args, f"{name}: --v0-compatible missing from OPA args: {args}"


def test_opa_port_is_not_published_by_any_service() -> None:
    """Defense in depth: even loopback-bound, :8181 must not be fronted by a Service."""
    for doc in yaml.safe_load_all(_render()):
        if not doc or doc.get("kind") != "Service":
            continue
        for port in doc["spec"].get("ports", []):
            assert int(port.get("port", 0)) != 8181, (
                f"Service {doc['metadata']['name']} publishes the OPA admin port 8181"
            )
