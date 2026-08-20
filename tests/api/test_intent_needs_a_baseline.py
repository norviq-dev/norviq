# SPDX-License-Identifier: Apache-2.0
"""A generated intent policy is refused in a namespace with nothing inspecting content.

An intent policy is DEFAULT-DENY over an allowlist of tool NAMES. It reads no arguments — that is the
baseline's job, and `generate_intent_rego` is explicitly tighten-only so a baseline `block` wins the
most-restrictive tie-break. The promise holds only where a baseline exists, and nothing said so.

In a namespace with neither a cluster guard (`__baseline__`) nor a tuned controls floor
(`__controls__`), `_collect_candidates` returns exactly one module and its allow is the whole
decision. An allowlisted tool then carries a prompt injection straight through. The console still
calls it positive security, the un-allowlisted tools really are blocked, and the only thing not
happening is the one an operator would assume from the words — which is why this is refused at apply
rather than documented.
"""

from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app

# The marker the guard keys on is the generated package name, so this mirrors a real draft.
_INTENT_REGO = """package norviq.intent.support_agent

default decision = "block"
default rule_id = "intent_default_deny"
default reason = "Blocked: tool is not in the intended allowlist"

allow_names := {"search_kb"}
in_allowlist { allow_names[lower(input.tool_name)] }
allow_intent { input.agent.agent_class == "support-agent"; in_allowlist }
decision = "allow" { allow_intent }
rule_id = "intent_allow_support_agent" { allow_intent }
"""

# Same shape the sibling router tests use — validate_policy_create requires a block/escalate arm.
_PLAIN_REGO = (
    'package norviq.managed.finance\n'
    'default decision = "allow"\n'
    'rule_id = "r"\n'
    'reason = "x"\n'
    'decision = "block" { input.tool_name == "drop_table" }\n'
)

_ADMIN = {"role": "admin", "namespace": "default", "sub": "admin"}


class _StubLoader:
    def __init__(self) -> None:
        self.created: list[tuple[str, str]] = []

    async def create(self, namespace, agent_class, rego_source, **kw):
        _ = (rego_source, kw)
        self.created.append((namespace, agent_class))
        return {"version": 1}


class _Session:
    """Answers the two queries the create path makes: the settings row, and the baseline scopes."""

    def __init__(self, baseline_scopes: list[str]) -> None:
        self._scopes = baseline_scopes

    async def execute(self, stmt):
        _ = stmt
        return SimpleNamespace(
            scalar_one_or_none=lambda: None,                      # no settings row -> apply_mode enforce
            scalars=lambda: SimpleNamespace(all=lambda: self._scopes),
        )

    async def close(self) -> None:
        return None


def _client(baseline_scopes: list[str]) -> tuple[TestClient, _StubLoader]:
    app = create_app()
    loader = _StubLoader()
    app.state.loader = loader
    app.dependency_overrides[get_current_user] = lambda: _ADMIN

    async def _session():
        yield _Session(baseline_scopes)

    app.dependency_overrides[get_session] = _session
    return TestClient(app), loader


def _post(client: TestClient, rego: str) -> object:
    return client.post(
        "/api/v1/policies",
        json={"namespace": "bare-ns", "agent_class": "support-agent", "rego_source": rego, "priority": 100},
    )


def test_an_intent_policy_is_refused_where_nothing_inspects_content():
    client, loader = _client(baseline_scopes=[])
    resp = _post(client, _INTENT_REGO)

    assert resp.status_code == 409, f"expected a refusal, got {resp.status_code} {resp.text[:300]}"
    detail = resp.json()["detail"]
    # The message has to be actionable: name the cause AND the way out. An operator who only reads the
    # first line should still know what to do.
    assert "no baseline" in detail
    assert "TOOL NAME" in detail
    assert "baseline/controls" in detail or "Baseline controls" in detail
    assert loader.created == [], "the policy must not reach the loader"


def test_the_same_policy_is_accepted_once_a_baseline_exists():
    """The control arm. A guard that refuses everything would satisfy the test above."""
    for scope in ("__baseline__", "__controls__"):
        client, loader = _client(baseline_scopes=[scope])
        resp = _post(client, _INTENT_REGO)
        assert resp.status_code == 200, f"with {scope} present: {resp.status_code} {resp.text[:300]}"
        assert ("bare-ns", "support-agent") in loader.created


def test_an_ordinary_policy_is_untouched_by_the_guard():
    """Only INTENT policies are gated. A hand-written class policy has never claimed to be default-deny
    over an allowlist, so a namespace with no baseline is the operator's own call there."""
    client, loader = _client(baseline_scopes=[])
    resp = _post(client, _PLAIN_REGO)
    assert resp.status_code == 200, resp.text[:300]
    assert ("bare-ns", "support-agent") in loader.created
