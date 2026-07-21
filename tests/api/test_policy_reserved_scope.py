# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""The generic POST /api/v1/policies must reject a direct write to the managed `__pack__` scope (it is
owned by the packs router and silently wiped by _materialize), pointing the caller at the packs enable API.
`__guardrail__` (operator-loaded) and normal class policies are NOT rejected by this guard."""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app

_VALID_REGO = 'package norviq.x\ndefault decision = "allow"\nrule_id = "r"\nreason = "x"\ndecision = "block" { input.tool_name == "drop_table" }\n'


class _StubLoader:
    def __init__(self) -> None:
        self.created: list[tuple[str, str]] = []
        self.deleted: list[tuple[str, str]] = []
        self.rolled_back: list[tuple[str, str, int]] = []

    async def create(self, namespace, agent_class, rego_source, **kw):
        self.created.append((namespace, agent_class))
        return 1

    async def delete(self, namespace, agent_class):
        self.deleted.append((namespace, agent_class))
        return True

    def get_versions(self, namespace, agent_class):
        return []

    async def rollback(self, namespace, agent_class, target_version):
        self.rolled_back.append((namespace, agent_class, target_version))
        return "package norviq.x\n"


class _NoSettingsSession:
    """No persisted settings row -> apply_mode falls back to enforce (the apply-mode gate is a no-op for this test)."""

    async def execute(self, stmt):
        _ = stmt
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    async def close(self) -> None:
        return None


_ADMIN = {"role": "admin", "namespace": "default", "sub": "admin"}


def _client(user: dict | None = None) -> tuple[TestClient, _StubLoader]:
    app = create_app()
    loader = _StubLoader()
    app.state.loader = loader
    principal = user or _ADMIN
    app.dependency_overrides[get_current_user] = lambda: principal

    async def _session():
        yield _NoSettingsSession()

    app.dependency_overrides[get_session] = _session
    return TestClient(app), loader


def test_direct_pack_write_is_rejected():
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "__pack__",
                                                 "rego_source": _VALID_REGO, "priority": 800})
    assert resp.status_code == 422
    assert "policy-packs" in resp.json()["detail"]      # points at the real enable path
    assert loader.created == []                          # never reached loader.create


def test_guardrail_scope_is_allowed():
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "__guardrail__",
                                                 "rego_source": _VALID_REGO, "priority": 800})
    assert resp.status_code == 200                       # operator-loaded guardrail still works
    assert ("default", "__guardrail__") in loader.created


def test_normal_class_policy_is_allowed():
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "finance-agent",
                                                 "rego_source": _VALID_REGO, "priority": 100})
    assert resp.status_code == 200
    assert ("default", "finance-agent") in loader.created


def test_apply_to_reserved_scope_is_rejected():
    # The apply path (sibling of create) must also reject __pack__/__baseline__ — it returned 200 before.
    client, _ = _client()
    body = {"target_type": "agent_class", "target_namespace": "default"}
    for scope in ("__pack__", "__baseline__"):
        resp = client.post(f"/api/v1/policies/default/{scope}/apply", json=body)
        assert resp.status_code == 422, scope
        assert "managed scope" in resp.json()["detail"]


def test_delete_reserved_scope_is_rejected():
    # DELETE had NO reserved-scope guard (create/apply do) — a raw DELETE of a managed scope would move the
    # namespace fallback floor. Every managed class + the reserved __cluster__ ns must be refused (422) and must
    # NEVER reach loader.delete.
    client, loader = _client()
    for scope in ("__baseline__", "__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__"):
        resp = client.delete(f"/api/v1/policies/default/{scope}")
        assert resp.status_code == 422, scope
        assert "managed scope" in resp.json()["detail"]
    resp = client.delete("/api/v1/policies/__cluster__/anything")
    assert resp.status_code == 422


# --- create/apply reject __pack_weaken__; apply rejects a reserved TARGET namespace ------------

def test_create_pack_weaken_is_rejected():
    # A direct create of __pack_weaken__ bypasses the packs router's OPA validation + weaken audit + gate.
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "__pack_weaken__",
                                                 "rego_source": _VALID_REGO, "priority": 900})
    assert resp.status_code == 422
    assert loader.created == []


def test_apply_pack_weaken_and_guardrail_are_rejected():
    # Apply previously covered only __pack__/__pack_override__/__baseline__ — weaken/guardrail slipped through.
    client, _ = _client()
    body = {"target_type": "agent_class", "target_namespace": "default"}
    for scope in ("__pack_weaken__", "__guardrail__"):
        resp = client.post(f"/api/v1/policies/default/{scope}/apply", json=body)
        assert resp.status_code == 422, scope


def test_apply_into_reserved_target_namespace_is_rejected():
    # Apply never checked target_namespace — it could write into the managed __cluster__ scope create refuses.
    client, _ = _client()
    resp = client.post("/api/v1/policies/default/finance-agent/apply",
                       json={"target_type": "agent_class", "target_namespace": "__cluster__"})
    assert resp.status_code == 422


# --- create is gated by the dry-run-only namespace posture (like apply) ------------------------

class _DryRunOnlySession:
    async def execute(self, stmt):
        _ = stmt
        return SimpleNamespace(scalar_one_or_none=lambda: SimpleNamespace(apply_mode="dry_run_only"))

    async def close(self) -> None:
        return None


def test_create_in_dry_run_only_namespace_is_rejected():
    app = create_app()
    loader = _StubLoader()
    app.state.loader = loader
    app.dependency_overrides[get_current_user] = lambda: _ADMIN

    async def _session():
        yield _DryRunOnlySession()

    app.dependency_overrides[get_session] = _session
    client = TestClient(app)
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "finance-agent",
                                                 "rego_source": _VALID_REGO, "priority": 100})
    assert resp.status_code == 409                       # the apply-mode gate now covers create, not just apply
    assert loader.created == []


# --- dry-run is namespace-scoped (a tenant cannot replay another namespace) --------------------

def test_dry_run_is_namespace_scoped_for_a_tenant():
    tenant = {"role": "viewer", "namespace": "team-a", "sub": "t"}
    client, _ = _client(user=tenant)
    # replaying a DIFFERENT namespace's traffic must 403
    resp = client.post("/api/v1/policies/dry-run", json={"namespace": "payments", "agent_class": "x",
                                                        "rego_source": _VALID_REGO})
    assert resp.status_code == 403


def test_delete_normal_class_reaches_loader():
    # A normal class delete is allowed and reaches loader.delete (returns True -> 200 with the audited scope).
    client, loader = _client()
    resp = client.delete("/api/v1/policies/default/finance-agent")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    assert ("default", "finance-agent") in loader.deleted


# --- create/rollback reserved-scope parity + API-key write-scope (IDOR) ---

_SVC_KEY_DEFAULT = {"role": "service", "namespace": "default", "sub": "apikey:abc123"}
_SVC_JWT_CONTROLLER = {"role": "service", "namespace": "default", "sub": "norviq-webhook"}


def test_create_cluster_namespace_is_rejected():
    # PARITY: delete guarded the reserved __cluster__ namespace; create did NOT — a direct write moved the
    # cluster-wide baseline floor. It must now be refused (422) before reaching the loader.
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "__cluster__", "agent_class": "anything",
                                                 "rego_source": _VALID_REGO, "priority": 800})
    assert resp.status_code == 422
    assert "cluster-baseline" in resp.json()["detail"]
    assert loader.created == []                          # short-circuits before loader.create


def test_rollback_reserved_scope_is_rejected():
    # PARITY: rollback had NO reserved-scope guard (create/delete/apply do) — rolling __baseline__ back to a prior
    # version moves the fallback floor out-of-band. Every managed class + the __cluster__ ns must be refused (422)
    # and NEVER reach loader.rollback.
    client, loader = _client()
    for scope in ("__baseline__", "__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__"):
        resp = client.post(f"/api/v1/policies/default/{scope}/rollback", json={"target_version": 1})
        assert resp.status_code == 422, scope
        assert "managed scope" in resp.json()["detail"]
    resp = client.post("/api/v1/policies/__cluster__/anything/rollback", json={"target_version": 1})
    assert resp.status_code == 422
    assert loader.rolled_back == []                      # guard short-circuits before the loader


def test_rollback_normal_class_reaches_loader():
    client, loader = _client()
    resp = client.post("/api/v1/policies/default/finance-agent/rollback", json={"target_version": 2})
    assert resp.status_code == 200
    assert ("default", "finance-agent", 2) in loader.rolled_back


def test_scoped_apikey_cross_tenant_create_is_403():
    # IDOR: an admin-issued service-role API key scoped to `default` must not CREATE a policy in another namespace.
    client, loader = _client(_SVC_KEY_DEFAULT)
    resp = client.post("/api/v1/policies", json={"namespace": "tenant-b", "agent_class": "finance-agent",
                                                 "rego_source": _VALID_REGO, "priority": 100})
    assert resp.status_code == 403
    assert loader.created == []                          # never reached the loader


def test_scoped_apikey_cross_tenant_delete_is_403():
    client, loader = _client(_SVC_KEY_DEFAULT)
    resp = client.delete("/api/v1/policies/tenant-b/finance-agent")
    assert resp.status_code == 403
    assert loader.deleted == []


def test_scoped_apikey_same_namespace_create_is_allowed():
    # The scoped key CAN write inside its own namespace (least-privilege, not a lockout).
    client, loader = _client(_SVC_KEY_DEFAULT)
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "finance-agent",
                                                 "rego_source": _VALID_REGO, "priority": 100})
    assert resp.status_code == 200
    assert ("default", "finance-agent") in loader.created


def test_controller_service_jwt_cross_namespace_is_allowed():
    # The webhook controller authenticates with a service JWT (sub 'norviq-webhook', NOT 'apikey:...') and
    # legitimately syncs policies cross-namespace — it must stay EXEMPT from the API-key scope guard.
    client, loader = _client(_SVC_JWT_CONTROLLER)
    resp = client.post("/api/v1/policies", json={"namespace": "tenant-b", "agent_class": "finance-agent",
                                                 "rego_source": _VALID_REGO, "priority": 100})
    assert resp.status_code == 200
    assert ("tenant-b", "finance-agent") in loader.created


# --- Confirm-gated revert of operator-authored reserved scopes -----------------------------------
# create ALLOWS __baseline__/__guardrail__ but DELETE refused ALL reserved scopes -> they were un-revertable.
# `?confirm_managed=true` is the supported admin-only revert; the seeded cluster baseline + pack overlays stay
# protected; the no-flag path is byte-identical to before (guarded by the tests above).


def test_confirm_managed_reverts_operator_baseline_and_guardrail():
    client, loader = _client()
    for scope in ("__baseline__", "__guardrail__"):
        resp = client.delete(f"/api/v1/policies/default/{scope}?confirm_managed=true")
        assert resp.status_code == 200, scope             # pre-fix: 422 (un-revertable)
        assert resp.json()["deleted"] is True
        assert ("default", scope) in loader.deleted        # reaches the loader (removes all layers)


def test_confirm_managed_still_refuses_cluster_namespace():
    client, loader = _client()
    resp = client.delete("/api/v1/policies/__cluster__/__baseline__?confirm_managed=true")
    assert resp.status_code == 422                          # the seeded cluster baseline is never deletable
    assert loader.deleted == []


def test_confirm_managed_still_refuses_pack_overlays():
    client, loader = _client()
    for scope in ("__pack__", "__pack_override__", "__pack_weaken__"):
        resp = client.delete(f"/api/v1/policies/default/{scope}?confirm_managed=true")
        assert resp.status_code == 422, scope              # revert these via the packs router, not a raw delete
        assert "policy-packs" in resp.json()["detail"]
    assert loader.deleted == []


def test_confirm_managed_requires_admin_not_service():
    # A service identity (webhook / scoped key) must NOT move a namespace's fallback floor even with the flag.
    client, loader = _client(_SVC_JWT_CONTROLLER)
    resp = client.delete("/api/v1/policies/default/__baseline__?confirm_managed=true")
    assert resp.status_code == 403
    assert loader.deleted == []


def test_no_confirm_flag_is_byte_identical_422():
    # Regression guard: without the flag the reserved-delete behavior is unchanged (existing tests cover the set).
    client, loader = _client()
    resp = client.delete("/api/v1/policies/default/__baseline__")
    assert resp.status_code == 422
    assert loader.deleted == []


# --- Per-class compliance remediation overlay ("<class>__remediation__") ----------------------------
# A compliance-remediation draft, once applied, must land at this DYNAMIC per-class key, never the real
# class's own (ns, class) key — that would let "Review & Apply" replace the class's comprehensive policy
# (the data-loss bug). It follows the `__guardrail__` precedent: directly writable via create, reserved from
# a raw delete, but operator-revertable via `confirm_managed=true` + admin — which touches ONLY the overlay
# row, never the base class.


def test_create_remediation_overlay_is_allowed():
    # Follows the __guardrail__ precedent — directly writable via the generic policy endpoint (this is how
    # the Policy Catalog's "Review & Apply" persists a reviewed compliance draft, see mitre.py).
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "report-gen__remediation__",
                                                 "rego_source": _VALID_REGO, "priority": 1})
    assert resp.status_code == 200
    assert ("default", "report-gen__remediation__") in loader.created


def test_create_remediation_overlay_never_touches_base_class():
    # Creating the overlay must not also create/touch the base "report-gen" key — they are distinct scopes.
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "report-gen__remediation__",
                                                 "rego_source": _VALID_REGO, "priority": 1})
    assert resp.status_code == 200
    assert ("default", "report-gen") not in loader.created


def test_delete_remediation_overlay_without_confirm_is_rejected():
    # Raw DELETE (no confirm_managed) is refused, exactly like __guardrail__/__baseline__ — never a silent drop.
    client, loader = _client()
    resp = client.delete("/api/v1/policies/default/report-gen__remediation__")
    assert resp.status_code == 422
    assert "managed scope" in resp.json()["detail"]
    assert loader.deleted == []


def test_delete_remediation_overlay_with_confirm_managed_reverts_only_the_overlay():
    # The supported revert path: confirm_managed=true + admin deletes ONLY the overlay row.
    client, loader = _client()
    resp = client.delete("/api/v1/policies/default/report-gen__remediation__?confirm_managed=true")
    assert resp.status_code == 200
    assert resp.json()["deleted"] is True
    assert ("default", "report-gen__remediation__") in loader.deleted
    assert ("default", "report-gen") not in loader.deleted  # base class policy is never touched


def test_delete_remediation_overlay_confirm_managed_requires_admin_not_service():
    client, loader = _client(_SVC_JWT_CONTROLLER)
    resp = client.delete("/api/v1/policies/default/report-gen__remediation__?confirm_managed=true")
    assert resp.status_code == 403
    assert loader.deleted == []


def test_rollback_remediation_overlay_is_rejected():
    # Parity with __guardrail__/__baseline__: rollback never gets a confirm_managed carve-out.
    client, loader = _client()
    resp = client.post("/api/v1/policies/default/report-gen__remediation__/rollback", json={"target_version": 1})
    assert resp.status_code == 422
    assert loader.rolled_back == []


def test_bare_remediation_suffix_class_is_not_treated_as_an_overlay():
    # Edge case: the literal class name "__remediation__" (suffix with nothing real in front of it) is not a
    # valid per-class overlay key — it must be treated as an ordinary (if oddly named) class, not reserved.
    client, loader = _client()
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "__remediation__",
                                                 "rego_source": _VALID_REGO, "priority": 1})
    assert resp.status_code == 200
    assert ("default", "__remediation__") in loader.created


# --- Security: priority-band enforcement --------------------------------------------------------
# The CRD caps a namespace policy at priority 0-499 and reserves the clusterPriority band (500-1000) for
# cluster admins, but the API's create path enforced NO bound — a namespace-scoped service-role API key
# (which passes require_admin_or_service and is floored to its own namespace, but is NOT an admin) could POST
# priority=800 (200 OK) and shadow control-plane policy for its namespace via highest-priority-wins. The band
# is now enforced: only a human admin or the control-plane webhook controller may write >= 500.


def test_scoped_apikey_cannot_set_cluster_priority_band():
    # The live-confirmed vector: a namespace-scoped service key POSTing priority=800 must now be refused (422)
    # and never reach the loader.
    client, loader = _client(_SVC_KEY_DEFAULT)
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "finance-agent",
                                                 "rego_source": _VALID_REGO, "priority": 800})
    assert resp.status_code == 422
    assert "clusterPriority" in resp.json()["detail"]     # points at the reserved admin band
    assert loader.created == []                            # short-circuits before loader.create


def test_scoped_apikey_namespace_band_still_succeeds():
    # Existing valid behavior is preserved: a scoped key writing inside the namespace band (0-499) succeeds.
    client, loader = _client(_SVC_KEY_DEFAULT)
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "finance-agent",
                                                 "rego_source": _VALID_REGO, "priority": 100})
    assert resp.status_code == 200
    assert ("default", "finance-agent") in loader.created


def test_priority_band_boundaries_for_non_admin():
    # 499 is the top of the namespace band (allowed); 500 is the first clusterPriority value (rejected).
    client, loader = _client(_SVC_KEY_DEFAULT)
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "a",
                                                 "rego_source": _VALID_REGO, "priority": 499})
    assert resp.status_code == 200
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "b",
                                                 "rego_source": _VALID_REGO, "priority": 500})
    assert resp.status_code == 422


def test_admin_may_set_cluster_priority_band():
    # An admin is authorized for the clusterPriority band (500-1000) — this is the intended admin override.
    client, loader = _client()  # defaults to _ADMIN
    resp = client.post("/api/v1/policies", json={"namespace": "default", "agent_class": "finance-agent",
                                                 "rego_source": _VALID_REGO, "priority": 800})
    assert resp.status_code == 200
    assert ("default", "finance-agent") in loader.created


def test_webhook_controller_may_sync_cluster_priority_band():
    # Existing valid behavior: the control-plane webhook controller (sub 'norviq-webhook') syncs admin-authored
    # clusterPriority CRDs (500-1000) via this endpoint — it must stay exempt from the namespace-band floor.
    client, loader = _client(_SVC_JWT_CONTROLLER)
    resp = client.post("/api/v1/policies", json={"namespace": "tenant-b", "agent_class": "finance-agent",
                                                 "rego_source": _VALID_REGO, "priority": 800})
    assert resp.status_code == 200
    assert ("tenant-b", "finance-agent") in loader.created
