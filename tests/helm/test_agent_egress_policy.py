# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Defense-in-depth: the opt-in agent-egress NetworkPolicy renders correctly.

Norviq's tool-call PEP is cooperative (the agent executes tools itself), so this default-deny egress
policy bounds the runtime blast radius at the network layer — an agent pod may reach ONLY the norviq API,
DNS, and an operator-approved tool allowlist. These render guards assert it is off by default, shaped
correctly when enabled, and fails loudly on a mis-scoped config. Skipped when helm isn't on PATH.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

_CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"
_BASE = ["--set", "baselineClusterPolicy.enabled=false"]

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm binary not on PATH")


def _template(*extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["helm", "template", "norviq", str(_CHART), *_BASE, *extra], capture_output=True, text=True)


def test_egress_policy_absent_by_default() -> None:
    res = _template("--set", "policyQuotaNamespaces={prod-agents}")
    assert res.returncode == 0, res.stderr
    assert "kind: NetworkPolicy" not in res.stdout


def test_egress_policy_rendered_when_enabled() -> None:
    res = _template(
        "--set", "policyQuotaNamespaces={prod-agents,analytics}",
        "--set", "agentEgressPolicy.enabled=true",
        "--set", "agentEgressPolicy.allowedCIDRs={10.20.0.0/16}",
        "--set", "agentEgressPolicy.allowedPorts={443}",
    )
    assert res.returncode == 0, res.stderr
    out = res.stdout
    # one policy per tenant namespace, egress-only
    assert out.count("kind: NetworkPolicy") == 2
    assert "namespace: prod-agents" in out and "namespace: analytics" in out
    assert "- Egress" in out and "podSelector: {}" in out
    # allows exactly DNS + the norviq API + the operator allowlist (no blanket allow)
    assert "port: 53" in out
    assert "app: norviq-api" in out
    assert 'cidr: "10.20.0.0/16"' in out and "port: 443" in out


def test_egress_policy_fails_when_no_namespaces() -> None:
    """FAIL-ON-BUG: enabled with no namespaces would silently protect nothing → render must fail."""
    res = _template("--set", "agentEgressPolicy.enabled=true")
    assert res.returncode != 0
    assert "no namespaces to lock down" in res.stderr


def test_egress_policy_refuses_control_plane_namespace() -> None:
    """Targeting the norviq control-plane namespace would break the control plane → render must fail."""
    res = _template(
        "--set", "agentEgressPolicy.enabled=true",
        "--set", "agentEgressPolicy.namespaces={norviq}",
    )
    assert res.returncode != 0
    assert "must not target the norviq control-plane" in res.stderr


# --- engine=cilium: FQDN (hostname) egress allowlisting -------------------------------------------


def test_cilium_engine_renders_fqdn_policy() -> None:
    res = _template(
        "--set", "policyQuotaNamespaces={prod-agents}",
        "--set", "agentEgressPolicy.enabled=true",
        "--set", "agentEgressPolicy.engine=cilium",
        "--set", "agentEgressPolicy.allowedFQDNs={api.openai.com}",
        "--set", "agentEgressPolicy.allowedFQDNPatterns={*.googleapis.com}",
        "--set", "agentEgressPolicy.allowedPorts={443}",
    )
    assert res.returncode == 0, res.stderr
    out = res.stdout
    assert "kind: CiliumNetworkPolicy" in out
    # the standard NetworkPolicy must NOT also render (engines are mutually exclusive)
    assert "\nkind: NetworkPolicy" not in out
    # FQDN allowlist + the MANDATORY DNS-visibility rule (without it toFQDNs resolves nothing)
    assert 'matchName: "api.openai.com"' in out and 'matchPattern: "*.googleapis.com"' in out
    assert "toFQDNs:" in out
    assert "rules:" in out and "dns:" in out and 'matchPattern: "*"' in out
    # control plane still reachable; port restriction applied
    assert "app: norviq-api" in out and 'port: "443"' in out


def test_invalid_engine_fails() -> None:
    res = _template(
        "--set", "agentEgressPolicy.enabled=true",
        "--set", "agentEgressPolicy.namespaces={prod-agents}",
        "--set", "agentEgressPolicy.engine=bogus",
    )
    assert res.returncode != 0
    assert "engine must be" in res.stderr
