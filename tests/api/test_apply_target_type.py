# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`target_type` must decide where an apply lands.

POST /policies/{ns}/{class}/apply accepted `target_type`, echoed it in the 200 response and wrote it to
the audit log (`NRVQ-API-7015`) — while calling `apply_to_target` with the SOURCE agent_class as the
destination key, unconditionally. So `--target-type workload` reported a successful apply and produced
a class policy. A knob that is logged but not read is worse than an absent one: the audit trail then
records an intent the system never carried out, and the operator holds written evidence of a control
they do not have.

These run against the pure `resolve_apply_target_key` rather than the endpoint on purpose. The endpoint
needs a live Postgres (`real_db` SKIPS when `NRVQ_PG_URL` is unset), so endpoint-level tests would have
been silently absent on most machines — which is how the defect survived. The destination keys asserted
here are the ones `evaluator._collect_candidates` actually resolves.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from norviq.api.routers.policies import ApplyRequest, resolve_apply_target_key


def _req(**kw) -> ApplyRequest:
    base = dict(target_type="agent_class", target_namespace="payments")
    base.update(kw)
    return ApplyRequest(**base)


def test_workload_lands_on_the_key_the_engine_looks_up() -> None:
    key = resolve_apply_target_key(
        _req(target_type="workload", target_name="billing-api", target_kind="deployment"), "planner"
    )
    assert key == "deployment:billing-api"


def test_namespace_lands_on_the_namespace_key() -> None:
    assert resolve_apply_target_key(_req(target_type="namespace"), "planner") == "namespace:payments"


@pytest.mark.parametrize("target_type", ["agent_class", "class", ""])
def test_class_apply_is_unchanged(target_type: str) -> None:
    """The default path is the one the console uses — it must keep behaving exactly as before."""
    assert resolve_apply_target_key(_req(target_type=target_type), "planner") == "planner"


def test_workload_defaults_to_deployment_kind() -> None:
    key = resolve_apply_target_key(_req(target_type="workload", target_name="billing-api"), "planner")
    assert key == "deployment:billing-api"


def test_workload_without_a_name_is_refused_not_silently_downgraded() -> None:
    """The defect's signature: no name meant no workload key, so the apply quietly became a class
    apply that answered 200. Refusing is the only honest response."""
    with pytest.raises(HTTPException) as exc:
        resolve_apply_target_key(_req(target_type="workload", target_name="  "), "planner")
    assert exc.value.status_code == 422
    assert "target_name" in str(exc.value.detail)


@pytest.mark.parametrize("kind", ["statefulset", "daemonset", "rollout"])
def test_unenforceable_workload_kind_is_refused(kind: str) -> None:
    """`resolve_policy_key` would happily mint `statefulset:foo`, but the evaluator only resolves
    `deployment:<name>` — accepting it would store a row nothing reads, which is the same silent no-op
    this fix exists to remove."""
    with pytest.raises(HTTPException) as exc:
        resolve_apply_target_key(
            _req(target_type="workload", target_name="billing-api", target_kind=kind), "planner"
        )
    assert exc.value.status_code == 422


def test_unknown_target_type_is_refused() -> None:
    with pytest.raises(HTTPException) as exc:
        resolve_apply_target_key(_req(target_type="cluster"), "planner")
    assert exc.value.status_code == 422


def test_case_and_whitespace_are_normalized() -> None:
    assert resolve_apply_target_key(_req(target_type="  NAMESPACE "), "planner") == "namespace:payments"
    assert resolve_apply_target_key(
        _req(target_type="Workload", target_name=" billing-api ", target_kind="Deployment"), "planner"
    ) == "deployment:billing-api"


def test_endpoint_uses_the_resolved_key_for_both_write_and_readback() -> None:
    """Guards the wiring. The endpoint previously re-read the persisted entry under the SOURCE class,
    so even a corrected write would have been reported from the wrong row."""
    import inspect

    from norviq.api.routers import policies

    src = inspect.getsource(policies.apply_policy)
    assert "resolve_apply_target_key(body, agent_class)" in src
    assert "loader.get_entry(body.target_namespace, target_key)" in src
