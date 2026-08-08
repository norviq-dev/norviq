# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The consumer half of the workload chain: identity must carry the workload the injector resolved.

`AgentIdentity.workload` existed and `_collect_candidates` read it to build
`<ns>:deployment:<workload>` — but no production construction ever set it. Both resolver paths built
the identity without it, so every request from every injected pod carried "". The workload tier could
not match anything, while the console offered it, the CRD accepted `target.kind/name`, the CLI could
apply to it and every surface reported the resulting policy Active.

The producer half (deriving it from the pod's owner and injecting NRVQ_WORKLOAD) is pinned in
webhook/injector_workload_test.go. These pin that the sidecar actually reads it.
"""

from __future__ import annotations

import pytest

from norviq.engine.identity import SPIFFEResolver


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("NRVQ_NAMESPACE", "analytics")
    monkeypatch.setenv("NRVQ_AGENT_CLASS", "payments")
    monkeypatch.setenv("NRVQ_SERVICE_ACCOUNT", "agent")
    return monkeypatch


def test_mock_resolver_carries_the_injected_workload(env) -> None:
    env.setenv("NRVQ_WORKLOAD", "checkout")
    assert SPIFFEResolver()._mock_resolve().workload == "checkout"


def test_mock_resolver_leaves_workload_empty_when_not_injected(env) -> None:
    env.delenv("NRVQ_WORKLOAD", raising=False)
    assert SPIFFEResolver()._mock_resolve().workload == ""


def test_both_resolver_paths_read_the_variable() -> None:
    """The SPIFFE path is the one that runs with real SVIDs; it must not be the forgotten branch.
    Asserted on source because exercising it needs a live workload API."""
    import inspect

    src = inspect.getsource(SPIFFEResolver)
    assert src.count('os.environ.get("NRVQ_WORKLOAD"') == 2, (
        "both _resolve (SPIFFE) and _mock_resolve must populate workload — one of them regressed"
    )


def test_the_key_the_evaluator_builds_matches_what_a_workload_policy_stores(env) -> None:
    """End-to-end shape check across the two components that must agree: the identity the sidecar
    sends, and the loader key a workload-targeted policy is stored under."""
    from norviq.api.routers.policies import PolicyCreate, resolve_policy_key

    env.setenv("NRVQ_WORKLOAD", "checkout")
    identity = SPIFFEResolver()._mock_resolve()

    body = PolicyCreate(
        namespace="analytics", agent_class="", rego_source='package p\ndefault decision = "allow"\n',
        policy_name="whatever-the-cr-is-called",
        target={"kind": "Deployment", "name": "checkout", "namespace": "analytics"},
    )
    stored = f"{identity.namespace}:{resolve_policy_key(body)}"
    looked_up = f"{identity.namespace}:deployment:{identity.workload}"
    assert stored == looked_up == "analytics:deployment:checkout"
