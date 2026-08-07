# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The CRD -> loader-key path, which nothing covered before and which was broken end to end.

`webhook/controller.go buildPolicySyncPayload` sets `payload.PolicyName = u.GetName()` for EVERY
NrvqPolicy, unconditionally. `resolve_policy_key` used to check `policy_name` BEFORE the target, so a
workload- or namespace-targeted CR was stored under its own metadata.name — a key
`evaluator._collect_candidates` never looks up. Both shipped examples were therefore inert:

    crds/examples/policy-custom-rego.yaml        target kind/name -> stored at <ns>:custom-sql-guard
    crds/examples/policy-namespace-baseline.yaml target namespace -> stored at <ns>:prod-baseline

while the engine looked for `<ns>:deployment:<workload>` and `<ns>:namespace:<ns>`. The policy loaded,
the CR went Ready, the catalog listed it, and it never once took part in a decision.

These tests pin the precedence: a usable target OUTRANKS policy_name, because policy_name is a display
name the controller always supplies, whereas a target is an explicit statement of what to govern.
`agent_class` still wins over everything (the console posts the loader key there directly, and the
controller sets it to `__baseline__` for a cluster-priority namespace baseline).
"""

from __future__ import annotations

import pytest

from norviq.api.routers.policies import PolicyCreate, resolve_policy_key

REGO = 'package norviq.policy\ndefault decision = "allow"\n'


def _body(**kw) -> PolicyCreate:
    base = dict(namespace="chatbot-prod", agent_class="", rego_source=REGO)
    base.update(kw)
    return PolicyCreate(**base)


def _controller_payload(name: str, target: dict | None) -> PolicyCreate:
    """Exactly what buildPolicySyncPayload sends: policy_name ALWAYS set, target copied through with
    its namespace defaulted to the CR's namespace."""
    if target is not None:
        target = {**target}
        target.setdefault("namespace", "chatbot-prod")
    agent_class = (target or {}).get("agentClass", "") or ""
    return _body(agent_class=agent_class, policy_name=name, target=target)


# ---- the two shipped examples that were inert ----------------------------------------------------

def test_workload_target_keys_to_the_key_the_engine_looks_up() -> None:
    # crds/examples/policy-custom-rego.yaml
    body = _controller_payload("custom-sql-guard", {"kind": "Deployment", "name": "billing-api"})
    assert resolve_policy_key(body) == "deployment:billing-api"


def test_namespace_target_keys_to_the_key_the_engine_looks_up() -> None:
    # crds/examples/policy-namespace-baseline.yaml — priority 50, NO clusterPriority, so the
    # controller's namespaceBaselineKey() declines it and it arrives as a plain namespace target.
    body = _controller_payload("prod-baseline", {"namespace": "chatbot-prod"})
    assert resolve_policy_key(body) == "namespace:chatbot-prod"


@pytest.mark.parametrize("kind,expected", [
    ("Deployment", "deployment:billing-api"),
    ("deployment", "deployment:billing-api"),
    ("DEPLOYMENT", "deployment:billing-api"),
])
def test_workload_kind_is_case_normalized(kind: str, expected: str) -> None:
    assert resolve_policy_key(_controller_payload("n", {"kind": kind, "name": "billing-api"})) == expected


# ---- precedence, pinned ---------------------------------------------------------------------------

def test_agent_class_still_outranks_a_target() -> None:
    """The console posts the resolved loader key as agent_class, and the controller sets agent_class
    to __baseline__ for a cluster-priority namespace baseline. Neither may be overridden by a target."""
    body = _controller_payload("some-name", {"agentClass": "support-agent", "kind": "Deployment", "name": "x"})
    assert resolve_policy_key(body) == "support-agent"

    baseline = _body(agent_class="__baseline__", policy_name="cluster-baseline",
                     target={"namespace": "chatbot-prod"})
    assert resolve_policy_key(baseline) == "__baseline__"


def test_policy_name_is_still_the_fallback_when_there_is_no_usable_target() -> None:
    assert resolve_policy_key(_controller_payload("named-only", None)) == "named-only"
    # a target that names nothing usable falls through to policy_name too
    assert resolve_policy_key(_body(policy_name="named-only", target={})) == "named-only"


def test_partial_workload_target_does_not_mint_a_half_key() -> None:
    """kind without name (or name without kind) must NOT produce `deployment:` — it falls through to
    the namespace branch, which the controller always populates."""
    assert resolve_policy_key(_controller_payload("n", {"kind": "Deployment"})) == "namespace:chatbot-prod"
    assert resolve_policy_key(_controller_payload("n", {"name": "billing-api"})) == "namespace:chatbot-prod"


def test_no_class_no_name_no_target_is_still_a_422() -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        resolve_policy_key(_body())
    assert exc.value.status_code == 422


# ---- the engine really does look up these keys ----------------------------------------------------

def test_keys_match_the_strings_the_evaluator_builds() -> None:
    """Guards against fixing the key and drifting the lookup. `_collect_candidates` builds
    `<ns>:namespace:<ns>` and `<ns>:deployment:<workload>`; the loader stores `<ns>:<resolved key>`."""
    import inspect

    from norviq.engine.evaluator import OPAEvaluator

    src = inspect.getsource(OPAEvaluator._collect_candidates)
    assert 'f"{namespace}:namespace:{namespace}"' in src
    assert 'f"{namespace}:deployment:{workload}"' in src

    ns_body = _controller_payload("prod-baseline", {"namespace": "chatbot-prod"})
    wl_body = _controller_payload("custom-sql-guard", {"kind": "Deployment", "name": "billing-api"})
    assert f"chatbot-prod:{resolve_policy_key(ns_body)}" == "chatbot-prod:namespace:chatbot-prod"
    assert f"chatbot-prod:{resolve_policy_key(wl_body)}" == "chatbot-prod:deployment:billing-api"
