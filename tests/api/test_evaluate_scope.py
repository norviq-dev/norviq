# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""/evaluate binds the evaluated namespace to the CALLER; scoped_namespace denies the
empty-claim least-privilege floor. The agent's own service/workload credential (hot path) is unaffected."""

from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from norviq.api import auth as auth_mod
from norviq.api.main import create_app
from norviq.config import settings
from norviq.sdk.core.decisions import PolicyDecision


def _token(
    role: str = "admin",
    namespace: str = "default",
    agent_class: str | None = None,
    spiffe_id: str | None = None,
) -> str:
    claims = {"sub": f"{role}-{namespace}", "role": role, "exp": int(time.time()) + 3600}
    if namespace is not None:
        claims["namespace"] = namespace
    # Identity binding claims (absent = an unbound legacy credential).
    if agent_class is not None:
        claims["agent_class"] = agent_class
    if spiffe_id is not None:
        claims["spiffe_id"] = spiffe_id
    return jwt.encode(claims, settings.api_secret_key, algorithm="HS256")


def _client() -> TestClient:
    app = create_app()

    async def _evaluate(_event):
        return PolicyDecision(decision="allow", rule_id="default_allow", trust_score=0.8)

    app.state.evaluator = SimpleNamespace(evaluate=_evaluate)
    app.state.emitter = None
    app.state.audit_hub = None
    return TestClient(app)


def _eval(client: TestClient, token: str, ns: str) -> int:
    body = {
        "tool_name": "get_order",
        "tool_params": {},
        "agent_identity": {"spiffe_id": f"spiffe://norviq/ns/{ns}/sa/x", "namespace": ns, "agent_class": "x"},
        "session_id": "s",
    }
    return client.post("/api/v1/evaluate", json=body, headers={"Authorization": f"Bearer {token}"}).status_code


def test_viewer_cross_namespace_evaluate_forbidden() -> None:
    """A viewer scoped to team-a may not evaluate in another tenant."""
    client = _client()
    assert _eval(client, _token("viewer", "team-a"), "payments") == 403


def test_viewer_same_namespace_evaluate_ok() -> None:
    client = _client()
    assert _eval(client, _token("viewer", "team-a"), "team-a") == 200


def test_admin_any_namespace_ok() -> None:
    client = _client()
    assert _eval(client, _token("admin", "default"), "payments") == 200


def test_service_any_namespace_ok_hotpath() -> None:
    """The agent's own service/workload credential (sidecar/SDK/break-glass) is the trusted hot path."""
    client = _client()
    assert _eval(client, _token("service", ""), "payments") == 200


def test_viewer_empty_claim_evaluate_forbidden() -> None:
    """The empty-claim floor user has no namespace scope -> 403."""
    client = _client()
    assert _eval(client, _token("viewer", ""), "payments") == 403


# --- No-claim floor unit coverage of scoped_namespace directly ---
def test_scoped_namespace_empty_floor_denied() -> None:
    with pytest.raises(HTTPException) as exc:
        auth_mod.scoped_namespace({"role": "viewer", "namespace": ""}, "payments")
    assert exc.value.status_code == 403


def test_scoped_namespace_service_empty_allowed() -> None:
    assert auth_mod.scoped_namespace({"role": "service", "namespace": ""}, "payments") == "payments"


def test_scoped_namespace_admin_any() -> None:
    assert auth_mod.scoped_namespace({"role": "admin", "namespace": ""}, "payments") == "payments"


def test_scoped_namespace_mapped_viewer_match() -> None:
    assert auth_mod.scoped_namespace({"role": "viewer", "namespace": "team-a"}, "team-a") == "team-a"
    with pytest.raises(HTTPException):
        auth_mod.scoped_namespace({"role": "viewer", "namespace": "team-a"}, "payments")


# --- Identity binding: agent_class / spiffe_id are policy-selection inputs, not free-form labels ----
# Regression for the disclosed policy-bypass: /evaluate bound ONLY `namespace` to the caller, so a
# namespace-scoped credential could assert a DIFFERENT `agent_class` in the same agent_identity dict and
# be authorized under that class's (looser) Rego program — and could assert a different `spiffe_id` to
# dodge its own `agent_frozen:` kill-switch / trust score. Binding mirrors scoped_namespace: a claim that
# is present must match; an absent claim stays unbound (legacy credentials keep working) unless strict
# mode is on.


def _eval_as(client: TestClient, token: str, ns: str, agent_class: str, spiffe_id: str = "") -> int:
    body = {
        "tool_name": "shell",
        "tool_params": {},
        "agent_identity": {
            "spiffe_id": spiffe_id or f"spiffe://norviq/ns/{ns}/sa/x",
            "namespace": ns,
            "agent_class": agent_class,
        },
        "session_id": "s",
    }
    return client.post("/api/v1/evaluate", json=body, headers={"Authorization": f"Bearer {token}"}).status_code


def test_bound_credential_cannot_spoof_agent_class() -> None:
    """THE BYPASS: a credential bound to 'restrictive' may not evaluate as the looser 'permissive'."""
    client = _client()
    token = _token("service", "nsA", agent_class="restrictive")
    assert _eval_as(client, token, "nsA", "permissive") == 403


def test_bound_credential_own_agent_class_allowed() -> None:
    """The same bound credential evaluating as its OWN class is the untouched hot path."""
    client = _client()
    token = _token("service", "nsA", agent_class="restrictive")
    assert _eval_as(client, token, "nsA", "restrictive") == 200


def test_unbound_credential_is_backward_compatible() -> None:
    """A legacy credential with no agent_class claim keeps working (ratchet, not a breaking change)."""
    client = _client()
    assert _eval_as(client, _token("service", "nsA"), "nsA", "anything") == 200


def test_bound_credential_cannot_spoof_spiffe_id() -> None:
    """Freeze/kill-switch evasion: agent_frozen: and the trust score are keyed by spiffe_id, so a bound
    credential may not assert a different one to shed a freeze."""
    client = _client()
    token = _token("service", "nsA", spiffe_id="spiffe://norviq/ns/nsA/sa/frozen-agent")
    assert _eval_as(client, token, "nsA", "x", spiffe_id="spiffe://norviq/ns/nsA/sa/some-other-agent") == 403
    assert _eval_as(client, token, "nsA", "x", spiffe_id="spiffe://norviq/ns/nsA/sa/frozen-agent") == 200


def test_admin_may_evaluate_as_any_identity() -> None:
    """Admin keeps the cross-scope bypass it already has for namespace (console what-if / red team)."""
    client = _client()
    assert _eval_as(client, _token("admin", "default", agent_class="ops"), "payments", "anything") == 200


def test_strict_mode_requires_a_bound_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ratchet: with strict binding on, an UNBOUND non-admin credential can no longer assert a class."""
    monkeypatch.setattr(settings, "auth_require_bound_agent_identity", True)
    client = _client()
    assert _eval_as(client, _token("service", "nsA"), "nsA", "permissive") == 403
    # Bound on agent_class ALONE is not enough — the kill-switch key (spiffe_id) must be bound too.
    assert _eval_as(client, _token("service", "nsA", agent_class="permissive"), "nsA", "permissive") == 403
    # A fully provisioned credential still works in strict mode.
    full = _token("service", "nsA", agent_class="permissive", spiffe_id="spiffe://nsA/a")
    assert _eval_as(client, full, "nsA", "permissive", spiffe_id="spiffe://nsA/a") == 200


def test_binding_is_exact_not_fuzzy() -> None:
    """Comparison is exact: case variants, padding and non-string types must not slip past the pin."""
    bound = {"role": "service", "namespace": "nsA", "agent_class": "restrictive"}
    for spoof in ("RESTRICTIVE", " restrictive ", "restrictive\n", ["permissive"], {"x": 1}):
        with pytest.raises(HTTPException) as exc:
            auth_mod.scoped_identity(bound, {"agent_class": spoof})
        assert exc.value.status_code == 403
    auth_mod.scoped_identity(bound, {"agent_class": "restrictive"})  # the real one still passes


def test_workload_is_bound_too() -> None:
    """`workload` selects the workload-tier program (ns:deployment:<name>), so it is pinned as well."""
    bound = {"role": "service", "namespace": "nsA", "workload": "deploy-a"}
    with pytest.raises(HTTPException) as exc:
        auth_mod.scoped_identity(bound, {"workload": "deploy-privileged"})
    assert exc.value.status_code == 403


def test_bound_credential_cannot_self_select_a_workload_tier() -> None:
    """No issuer mints a `workload` claim today, so a bound credential naming any deployment would pull
    in that tier's program. Since the workload tier is purely ADDITIVE, an unclaimed workload resolves to
    empty (tier dropped) — the safe direction — rather than to whatever the body asked for."""
    bound = {"role": "service", "namespace": "nsA", "agent_class": "restrictive", "spiffe_id": "spiffe://nsA/me"}
    assert auth_mod.scoped_identity(bound, {"workload": "deploy-privileged"})["workload"] == ""
    # An UNBOUND (legacy) credential is untouched — no behavior change pre-provisioning.
    unbound = {"role": "service", "namespace": "nsA"}
    assert auth_mod.scoped_identity(unbound, {"workload": "deploy-x"})["workload"] == "deploy-x"


def test_omitted_or_empty_field_is_replaced_by_the_claim() -> None:
    """OMISSION must not be an escape hatch. Dropping `agent_class` is as powerful as substituting it:
    the class program stops being a candidate while `__baseline__` / `__cluster__:__baseline__` remain,
    so the caller silently falls back to the LOOSER baseline (and sheds its tighten-only __remediation__
    overlay + the scope-drift trust penalty). The claim is therefore authoritative — it is written back
    over an empty/absent body value rather than merely compared against it."""
    bound = {
        "role": "service",
        "namespace": "nsA",
        "agent_class": "restrictive",
        "spiffe_id": "spiffe://nsA/me",
        "workload": "deploy-a",
    }
    resolved = auth_mod.scoped_identity(bound, {"agent_class": "", "workload": ""})
    assert resolved["agent_class"] == "restrictive"
    assert resolved["workload"] == "deploy-a"
    assert resolved["spiffe_id"] == "spiffe://nsA/me"
    # Same when the fields are absent entirely.
    assert auth_mod.scoped_identity(bound, {})["agent_class"] == "restrictive"
    # ...and an UNBOUND credential is still passed through untouched (backward compat).
    unbound = {"role": "service", "namespace": "nsA"}
    assert auth_mod.scoped_identity(unbound, {"agent_class": "anything"})["agent_class"] == "anything"


def test_evaluate_uses_the_bound_class_when_body_omits_it() -> None:
    """End-to-end: the evaluator must receive the CREDENTIAL's class, not the body's empty one."""
    app = create_app()
    seen: dict = {}

    async def _evaluate(event):
        seen["agent_class"] = event.agent_identity.agent_class
        seen["namespace"] = event.agent_identity.namespace
        return PolicyDecision(decision="allow", rule_id="x", trust_score=0.5)

    app.state.evaluator = SimpleNamespace(evaluate=_evaluate)
    app.state.emitter = None
    app.state.audit_hub = None
    client = TestClient(app)
    token = _token("service", "nsA", agent_class="restrictive")
    body = {
        "tool_name": "shell",
        "tool_params": {},
        "agent_identity": {"spiffe_id": "spiffe://nsA/a", "namespace": "nsA", "agent_class": ""},
        "session_id": "s",
    }
    assert client.post("/api/v1/evaluate", json=body, headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert seen["agent_class"] == "restrictive"  # NOT "" — the baseline-downgrade is closed


def test_strict_ratchet_requires_every_required_field() -> None:
    """A token bound on agent_class but NOT spiffe_id must not satisfy the ratchet — otherwise a
    partially bound sidecar token passes while its kill-switch stays evadable."""
    partial = {"role": "service", "namespace": "nsA", "agent_class": "restrictive"}
    auth_mod.scoped_identity(partial, {})  # tolerated while the ratchet is off
    import norviq.config as _cfg

    _cfg.settings.auth_require_bound_agent_identity = True
    try:
        with pytest.raises(HTTPException) as exc:
            auth_mod.scoped_identity(partial, {})
        assert exc.value.status_code == 403
        # Fully bound passes.
        full = {**partial, "spiffe_id": "spiffe://nsA/me"}
        assert auth_mod.scoped_identity(full, {})["spiffe_id"] == "spiffe://nsA/me"
        # A HUMAN session is not subject to the machine ratchet (console Policy Tester keeps working).
        assert auth_mod.scoped_identity({"role": "viewer", "namespace": "nsA"}, {"agent_class": "x"})
    finally:
        _cfg.settings.auth_require_bound_agent_identity = False


def test_obs1_missing_spiffe_id_returns_422() -> None:
    """A malformed agent_identity (no spiffe_id) is a 422 client error, not a raw 500."""
    client = _client()
    body = {
        "tool_name": "get_order",
        "tool_params": {},
        "agent_identity": {"namespace": "default", "agent_class": "x"},  # missing required spiffe_id
        "session_id": "s",
    }
    resp = client.post("/api/v1/evaluate", json=body, headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 422


def test_perf1_oversized_body_returns_413() -> None:
    """A request body over the configured limit is rejected with 413 before evaluation."""
    client = _client()
    huge = "A" * (settings.max_request_body_bytes + 1024)
    body = {
        "tool_name": "get_order",
        "tool_params": {"blob": huge},
        "agent_identity": {"spiffe_id": "spiffe://norviq/ns/default/sa/x", "namespace": "default", "agent_class": "x"},
        "session_id": "s",
    }
    resp = client.post("/api/v1/evaluate", json=body, headers={"Authorization": f"Bearer {_token()}"})
    assert resp.status_code == 413


def test_perf1_normal_body_passes() -> None:
    """A normal-size body is unaffected by the limit."""
    client = _client()
    assert _eval(client, _token("admin", "default"), "default") == 200


# --- The SVID-attested namespace (issue #2 residual) ------------------------------------------------
#
# scoped_namespace deliberately trusts a MACHINE principal with an EMPTY namespace claim to evaluate
# whatever namespace the request BODY names — the hot path needed that latitude. The consequence was
# that an unbound service token could evaluate as any tenant, picking the Rego program, the trust
# score's identity and the audit tenant by writing a different string in the body.
#
# The closure needs no new attestation channel: `spiffe_id` is already one of the credential-bound
# identity fields, and a Norviq SVID encodes its namespace as spiffe://norviq/ns/<ns>/sa/<sa>. So the
# workload's own attested identity names its namespace and the body cannot choose it.
#
# Note what was already safe: the webhook mints sidecar tokens WITH a non-empty `namespace` claim
# (webhook/injector.go), so scoped_namespace already pinned the injected-sidecar path. These tests cover
# the credentials that carry no namespace claim.


def _capturing_client() -> tuple[TestClient, list]:
    """Client that records the ToolCallEvent the evaluator actually received.

    Asserting the status code alone would not prove the fix: a 200 says the request was allowed, not
    which namespace was enforced. The whole defect was evaluating under the WRONG namespace.
    """
    seen: list = []
    app = create_app()

    async def _evaluate(event):
        seen.append(event)
        return PolicyDecision(decision="allow", rule_id="default_allow", trust_score=0.8)

    app.state.evaluator = SimpleNamespace(evaluate=_evaluate)
    app.state.emitter = None
    app.state.audit_hub = None
    return TestClient(app), seen


def _eval_with_body_ns(
    client: TestClient, token: str, body_ns: str | None, body_svid: str = "spiffe://norviq/ns/team-a/sa/bot"
) -> int:
    """Evaluate with only the NAMESPACE varying.

    The body's spiffe_id mirrors the token's claim on purpose. scoped_identity already 403s on a
    spiffe_id mismatch (NRVQ-AUTH-14019), so a body SVID that disagreed with the claim would make every
    case here fail for that unrelated reason and prove nothing about the namespace.
    """
    identity = {"spiffe_id": body_svid, "agent_class": "x"}
    if body_ns is not None:
        identity["namespace"] = body_ns
    resp = client.post(
        "/api/v1/evaluate",
        json={"tool_name": "get_order", "tool_params": {}, "agent_identity": identity, "session_id": "s"},
        headers={"Authorization": f"Bearer {token}"},
    )
    return resp.status_code


def test_unbound_service_token_cannot_evaluate_another_tenant_when_its_svid_says_otherwise() -> None:
    """THE residual, closed: no namespace claim, but the SVID attests team-a — payments is refused."""
    client, _ = _capturing_client()
    token = _token("service", "", spiffe_id="spiffe://norviq/ns/team-a/sa/bot")
    assert _eval_with_body_ns(client, token, "payments") == 403


def test_attested_namespace_is_what_gets_enforced_not_the_body() -> None:
    """The SVID's namespace must be USED, not merely validated — a 200 alone proves nothing."""
    client, seen = _capturing_client()
    token = _token("service", "", spiffe_id="spiffe://norviq/ns/team-a/sa/bot")
    # Body omits namespace entirely: previously this evaluated under whatever the body implied.
    assert _eval_with_body_ns(client, token, None) == 200
    assert seen, "the evaluator was never called"
    assert seen[-1].agent_identity.namespace == "team-a", (
        f"enforced namespace was {seen[-1].agent_identity.namespace!r}, not the attested team-a"
    )


def test_attested_namespace_matching_the_body_is_allowed() -> None:
    client, seen = _capturing_client()
    token = _token("service", "", spiffe_id="spiffe://norviq/ns/team-a/sa/bot")
    assert _eval_with_body_ns(client, token, "team-a") == 200
    assert seen[-1].agent_identity.namespace == "team-a"


def test_a_foreign_trust_domain_attests_nothing() -> None:
    """`spiffe://evil/ns/payments/sa/x` must not be usable to claim the payments namespace.

    The loose scan in routers/agents.py (find "ns" anywhere in the path) would accept this, which is why
    the authorization path uses the engine's strict parser — it pins the trust domain and the exact
    4-segment shape. Behaviour falls back to scoped_namespace, i.e. unchanged.
    """
    client, _ = _capturing_client()
    svid = "spiffe://evil/ns/payments/sa/x"
    token = _token("service", "", spiffe_id=svid)
    assert _eval_with_body_ns(client, token, "payments", body_svid=svid) == 200  # unchanged, not newly blocked


def test_a_credential_that_disagrees_with_itself_is_refused() -> None:
    """A namespace claim of team-a with an SVID for payments is misissued — refuse, don't guess."""
    client, _ = _capturing_client()
    svid = "spiffe://norviq/ns/payments/sa/bot"
    token = _token("service", "team-a", spiffe_id=svid)
    assert _eval_with_body_ns(client, token, "team-a", body_svid=svid) == 403


def test_the_existing_hot_path_is_unchanged_when_nothing_is_attestable() -> None:
    """No namespace claim AND no SVID claim: exactly the prior behaviour, by design.

    This residual is closed by `auth_require_bound_agent_identity` (which REFUSES such a credential
    outright), not here — deriving a namespace from nothing is not possible.
    """
    client, _ = _capturing_client()
    assert _eval_with_body_ns(client, _token("service", ""), "payments") == 200


def test_admin_keeps_its_cross_namespace_latitude() -> None:
    """Console what-if / red-team simulate evaluate as other identities on purpose."""
    client, _ = _capturing_client()
    token = _token("admin", "default", spiffe_id="spiffe://norviq/ns/team-a/sa/bot")
    assert _eval_with_body_ns(client, token, "payments") == 200  # admin bypasses both bindings


def test_workload_api_mode_sidecars_are_unaffected() -> None:
    """In workload-api mode the webhook deliberately omits spiffe_id (it is not predictable), so the
    attested path must be a no-op there rather than a 403 on every call."""
    client, _ = _capturing_client()
    assert auth_mod.attested_namespace({"role": "service", "namespace": "team-a"}, "team-a") == ""


@pytest.mark.parametrize("svid", ["", "not-a-spiffe-id", "spiffe://norviq/ns//sa/x", "spiffe://norviq/x/y/z/w"])
def test_unparseable_svids_attest_nothing(svid: str) -> None:
    assert auth_mod.attested_namespace({"role": "service", "spiffe_id": svid}, "payments") == ""
