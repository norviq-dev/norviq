# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Fail-closed guarantee for non-dict JSON bodies on the sidecar HTTP fallback.

Residual: the JSON decode is guarded (returns a drop on undecodable bodies) and the
interceptor call is wrapped in a fail-closed try/except, but the param-coercion lines
(``str(data.get("tool_name", ""))`` etc.) sit OUTSIDE any try/except. A *valid-JSON* body that
is not an object -- a list, string, number, or null -- has no ``.get``, so those lines raise
AttributeError and FastAPI returns a bare HTTP 500 with no ``action`` field instead of the
mandated fail-closed drop. These tests fail on the unguarded code (500) and pass once the type
guard is added (200 + action=drop).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import AgentIdentity
from norviq.sdk.core.interceptor import ToolInterceptor
from norviq.sidecar.http_fallback import create_http_fallback


class _AllowEval:
    """Stub evaluator that would ALLOW anything -- proves the drop is from the guard, not policy."""

    async def evaluate(self, event: object) -> PolicyDecision:
        return PolicyDecision(decision="allow")


class _FakeResolver:
    async def resolve(self) -> AgentIdentity:
        return AgentIdentity(spiffe_id="spiffe://x/y", namespace="ns")


@pytest.fixture
def client() -> TestClient:
    """Real create_http_fallback app with an allow-everything evaluator + stub resolver."""
    app = create_http_fallback(ToolInterceptor(_AllowEval(), _FakeResolver()), None, _FakeResolver())
    # raise_server_exceptions=False so an unhandled 500 surfaces as a response, not a test crash.
    return TestClient(app, raise_server_exceptions=False)


@pytest.mark.parametrize(
    "body",
    [
        [1, 2, 3],       # JSON array
        ["rm", "-rf"],   # JSON array of strings
        "hello",         # JSON string
        42,              # JSON number
        True,            # JSON boolean
        None,            # JSON null
    ],
    ids=["array", "array_strings", "string", "number", "bool", "null"],
)
def test_non_dict_json_body_fails_closed(client: TestClient, body: object) -> None:
    """A valid-JSON non-object body must DROP (200 action=drop), never 500 (fail-open bypass)."""
    resp = client.post("/v1/evaluate", json=body)
    assert resp.status_code == 200, (resp.status_code, resp.text)
    payload = resp.json()
    assert payload.get("action") == "drop", payload
    assert payload.get("error") == "invalid_json_body", payload
    # The drop must NOT carry a decision block -- it is rejected before any evaluation.
    assert "decision" not in payload, payload


def test_valid_dict_body_still_forwards(client: TestClient) -> None:
    """Regression guard: a well-formed dict body is unaffected by the type guard."""
    resp = client.post("/v1/evaluate", json={"tool_name": "read_file", "tool_params": {"p": "/x"}})
    assert resp.status_code == 200, (resp.status_code, resp.text)
    payload = resp.json()
    assert payload.get("action") == "forward", payload
