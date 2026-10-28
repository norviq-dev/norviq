# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Only the standalone engine accepts off-pod evaluation callers, and only with a token.

The engine Deployment is the one workload whose HTTP fallback sits behind a Service. It must render
NRVQ_SIDECAR_REMOTE_CALLERS=token (authenticate them); no other workload may set it, because a process
without the signing key would have nothing real to verify a token against.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import yaml

_CHART = Path(__file__).resolve().parents[2] / "helm" / "norviq"


def _docs(*extra: str) -> list[dict]:
    out = subprocess.run(["helm", "template", "norviq", str(_CHART), "-n", "norviq",
                          "--set", "policyQuotaNamespaces={default}", *extra],
                         check=True, capture_output=True, text=True).stdout
    return [d for d in yaml.safe_load_all(out) if isinstance(d, dict) and "kind" in d]


def _env(container: dict) -> dict:
    return {e["name"]: e.get("value") for e in container.get("env", [])}


def test_the_engine_authenticates_off_pod_callers() -> None:
    engine = next(d for d in _docs() if d["kind"] == "Deployment" and d["metadata"]["name"] == "norviq-engine")
    c = next(c for c in engine["spec"]["template"]["spec"]["containers"] if c["name"] == "engine")
    assert _env(c).get("NRVQ_SIDECAR_REMOTE_CALLERS") == "token"
    assert any(ref.get("secretRef", {}).get("name") == "norviq-secrets" for ref in c.get("envFrom", [])), \
        "token mode needs the signing key from norviq-secrets"


def test_no_other_workload_sets_it() -> None:
    for d in _docs("--set", "webhook.injection.enabled=true"):
        if d["kind"] not in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
            continue
        for c in d["spec"]["template"]["spec"].get("containers", []):
            if d["metadata"]["name"] == "norviq-engine" and c["name"] == "engine":
                continue
            assert "NRVQ_SIDECAR_REMOTE_CALLERS" not in _env(c), f"{d['metadata']['name']}/{c['name']}"
    cm = next(d for d in _docs() if d["kind"] == "ConfigMap" and d["metadata"]["name"] == "norviq-config")
    assert "NRVQ_SIDECAR_REMOTE_CALLERS" not in cm["data"], "in the shared ConfigMap it would reach every envFrom"
