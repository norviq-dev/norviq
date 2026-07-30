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
import yaml

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
    """Targeting the norviq control-plane namespace would break the control plane → render must fail.

    The guard is release-namespace-aware (`eq $ns .Release.Namespace`), so the control-plane
    namespace is whatever `-n` selects — here `norviq`."""
    res = _template(
        "-n", "norviq",
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
    # values.schema.json now rejects the bad enum before the chart's own runtime `fail` — either
    # gate is acceptable, both name the valid values.
    assert "networkpolicy" in res.stderr and "cilium" in res.stderr


# ---------------------------------------------------------------------------------------------------
# embeddedDatastores: the allowlist must name pods that EXIST in the chosen datastore shape.
#
# Validated live on Calico, which is the point — kindnet silently ignores NetworkPolicy, so none of
# this had ever actually run. With the lockdown active: allowlisted egress returned HTTP 200,
# de-allowlisted egress was dropped, the injected sidecar stayed Ready and kept enforcing (dangerous
# call dropped, benign forwarded), and DNS + the norviq API remained reachable.
#
# The defect: the embeddedDatastores rule named `app: norviq-postgresql` / `app: norviq-redis`
# unconditionally, but those labels exist only on the BUNDLED StatefulSets.
#
#     bundled   app: norviq-postgresql / app: norviq-redis
#     HA        cnpg.io/cluster (CloudNativePG) — verified live, a real CNPG pod carries
#               {cnpg.io/cluster, cnpg.io/instanceName, cnpg.io/instanceRole, cnpg.io/podRole, role}
#               and NO app: label. The old selector matched 0 of 3 CNPG pods; the new one matched 3.
#               Redis HA likewise carries the Spotahome operator's own labels.
#     external  no pod in this cluster at all — no selector can ever match it.
#
# A podSelector matching nothing grants nothing, and under default-deny that is indistinguishable from
# a network outage. Proven end-to-end against a real CNPG cluster: with the bundled-shaped rule the
# agent could not reach the CNPG primary (curl exit 28, dropped); with the HA-shaped rule the same
# call connected (exit 52), while external egress stayed dropped.
# ---------------------------------------------------------------------------------------------------


_EGRESS_BASE = ["--set-json", 'policyQuotaNamespaces=["agents"]',
                "--set", "agentEgressPolicy.enabled=true",
                "--set", "agentEgressPolicy.embeddedDatastores=true"]
_HA = ["--set", "postgresql.ha.enabled=true", "--set", "postgresql.password=Str0ngPg1",
       "--set", "redis.ha.enabled=true", "--set", "redis.password=Str0ngRedis1"]
_EXTERNAL = ["--set", "postgresql.enabled=false", "--set", "postgresql.host=db.example.com",
             "--set", "redis.enabled=false", "--set", "redis.host=cache.example.com"]


def _render_egress(extra: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(["helm", "template", "norviq", str(_CHART), *_EGRESS_BASE, *extra],
                          capture_output=True, text=True)


def _selectors(rendered: str, engine: str) -> list[dict]:
    """Every pod/endpoint selector the lockdown policy allowlists."""
    kind = "CiliumNetworkPolicy" if engine == "cilium" else "NetworkPolicy"
    out: list[dict] = []
    for doc in yaml.safe_load_all(rendered):
        if not doc or doc.get("kind") != kind:
            continue
        if doc["metadata"]["name"] != "norviq-agent-egress-lockdown":
            continue
        for rule in doc["spec"].get("egress", []):
            for target in rule.get("to", []) + rule.get("toEndpoints", []):
                if "podSelector" in target:
                    out.append(target["podSelector"].get("matchLabels", {}))
                elif "matchLabels" in target:
                    out.append(target["matchLabels"])
                elif "namespaceSelector" not in target and "ipBlock" not in target:
                    out.append(target)
    return out


@pytest.mark.parametrize("engine", ["networkpolicy", "cilium"])
def test_bundled_datastores_are_allowlisted_by_their_real_labels(engine: str) -> None:
    res = _render_egress(["--set", f"agentEgressPolicy.engine={engine}"])
    assert res.returncode == 0, res.stderr[-500:]
    flat = _selectors(res.stdout, engine)
    for want in ("norviq-postgresql", "norviq-redis"):
        assert any(s.get("app") == want for s in flat), (
            f"{engine}: bundled {want} is not allowlisted — the embedded sidecar cannot reach it"
        )


@pytest.mark.parametrize("engine", ["networkpolicy", "cilium"])
def test_ha_datastores_are_allowlisted_by_the_OPERATORS_labels(engine: str) -> None:
    """The regression, named. `app: norviq-*` matches no operator-created pod."""
    res = _render_egress([*_HA, "--set", f"agentEgressPolicy.engine={engine}"])
    assert res.returncode == 0, res.stderr[-500:]
    flat = _selectors(res.stdout, engine)

    assert any(s.get("cnpg.io/cluster") for s in flat), (
        f"{engine}: HA Postgres allowlisted by {flat} — CNPG pods carry cnpg.io/cluster, "
        "so this rule matches NOTHING and the embedded sidecar is stranded"
    )
    assert any("redisfailovers.databases.spotahome.com/name" in s for s in flat), (
        f"{engine}: HA Redis allowlisted by {flat} — Spotahome pods carry its own labels"
    )
    # And the labels that DON'T exist in this shape must be gone, not merely accompanied.
    assert not any(s.get("app") in {"norviq-postgresql", "norviq-redis"} for s in flat), (
        f"{engine}: still allowlisting a bundled-only label under HA: {flat}"
    )


@pytest.mark.parametrize("engine", ["networkpolicy", "cilium"])
def test_ha_rule_follows_a_failover_instead_of_pinning_one_pod(engine: str) -> None:
    """Both operators move the writable role between pods; pinning it breaks on the first failover."""
    res = _render_egress([*_HA, "--set", f"agentEgressPolicy.engine={engine}"])
    flat = _selectors(res.stdout, engine)
    for s in flat:
        assert s.get("role") != "primary", f"{engine}: pinned to the current CNPG primary: {s}"
        assert "redisfailovers-role" not in s, f"{engine}: pinned to the current Redis master: {s}"


def test_mixed_shape_picks_each_datastore_independently() -> None:
    """Bundled Postgres + HA Redis is a legitimate combination; each side needs its own labels."""
    res = _render_egress(["--set", "redis.ha.enabled=true", "--set", "redis.password=Str0ngRedis1"])
    assert res.returncode == 0, res.stderr[-500:]
    flat = _selectors(res.stdout, "networkpolicy")
    assert any(s.get("app") == "norviq-postgresql" for s in flat), f"bundled pg lost: {flat}"
    assert any("redisfailovers.databases.spotahome.com/name" in s for s in flat), f"HA redis lost: {flat}"
    assert not any(s.get("app") == "norviq-redis" for s in flat), f"stale bundled redis label: {flat}"


@pytest.mark.parametrize("engine", ["networkpolicy", "cilium"])
def test_external_datastores_fail_loudly_rather_than_rendering_a_useless_rule(engine: str) -> None:
    """No selector can reach a datastore outside the cluster, so silence would strand the sidecar."""
    res = _render_egress([*_EXTERNAL, "--set", f"agentEgressPolicy.engine={engine}"])
    assert res.returncode != 0, (
        f"{engine}: rendered a policy that cannot possibly reach an external datastore"
    )
    assert "allowedCIDRs" in res.stderr, f"{engine}: the error must name the fix, got: {res.stderr[-300:]}"


@pytest.mark.parametrize("engine", ["networkpolicy", "cilium"])
def test_external_datastores_render_once_the_operator_allowlists_them(engine: str) -> None:
    extra = ["--set", f"agentEgressPolicy.engine={engine}",
             "--set-json", 'agentEgressPolicy.allowedCIDRs=["10.0.0.0/8"]']
    res = _render_egress([*_EXTERNAL, *extra])
    assert res.returncode == 0, (
        f"{engine}: an explicit CIDR allowlist should satisfy the guard: {res.stderr[-400:]}"
    )
