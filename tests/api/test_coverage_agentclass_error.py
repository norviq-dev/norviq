# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The agent-class policy section of /coverage-by-category must distinguish a *failed* DB read
from a genuinely empty namespace. A handler that catches every exception and returns a bare `[]`
with no log makes a statement timeout / serialization failure byte-identical to
"no agent-class policies applied". These tests require the read fault to surface as a `degraded`
signal (and an observable NRVQ-API-7081 log).
"""

from __future__ import annotations

from types import SimpleNamespace

import time

import jwt
import structlog
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.api.routers.coverage import _agent_class_policies
from norviq.config import settings


# --- fake sessions ---------------------------------------------------------------------------------

class _BoomSession:
    """Every query raises — models a statement timeout / serialization failure on the shared pool."""

    def __init__(self, exc: Exception | None = None) -> None:
        self._exc = exc or OperationalError(
            "SELECT ...", {}, Exception("canceling statement due to statement timeout")
        )

    async def execute(self, *_args, **_kwargs):
        raise self._exc

    async def close(self) -> None:
        return None


class _Result:
    """A minimal SQLAlchemy-result stand-in supporting both `.mappings().all()` and `.all()`."""

    def __init__(self, mapping_rows: list[dict] | None = None, tuple_rows: list[tuple] | None = None) -> None:
        self._mapping_rows = mapping_rows or []
        self._tuple_rows = tuple_rows or []

    def mappings(self):
        return SimpleNamespace(all=lambda: self._mapping_rows)

    def all(self):
        return self._tuple_rows


class _HealthySession:
    """1st execute = the policies DISTINCT-ON query (mappings), 2nd = the efficacy GROUP BY (tuples)."""

    def __init__(self, policy_rows: list[dict], efficacy_rows: list[tuple]) -> None:
        self._policy_rows = policy_rows
        self._efficacy_rows = efficacy_rows
        self._calls = 0

    async def execute(self, *_args, **_kwargs):
        self._calls += 1
        if self._calls == 1:
            return _Result(mapping_rows=self._policy_rows)
        return _Result(tuple_rows=self._efficacy_rows)

    async def close(self) -> None:
        return None


class _EfficacyBoomSession:
    """Policies query succeeds; the efficacy overlay query raises (partial degradation)."""

    def __init__(self, policy_rows: list[dict]) -> None:
        self._policy_rows = policy_rows
        self._calls = 0

    async def execute(self, *_args, **_kwargs):
        self._calls += 1
        if self._calls == 1:
            return _Result(mapping_rows=self._policy_rows)
        raise OperationalError("SELECT ...", {}, Exception("efficacy boom"))

    async def close(self) -> None:
        return None


def _policy_row(agent_class: str = "report-gen") -> dict:
    return {
        "namespace": "team-a",
        "agent_class": agent_class,
        "rego_source": "package norviq.intent.report_gen\nallow_names := {\"warehouse_task\"}\n",
        "priority": 100,
        "enforcement_mode": "block",
    }


# --- The direct-function contract ------------------------------------------------------------------

async def test_agent_class_query_failure_marks_section_degraded() -> None:
    """A failing policies read must return a degraded signal, NOT an empty success that reads as
    'no agent-class policies applied'. Pre-fix returned a bare `[]`, so the tuple/degraded contract fails."""
    result = await _agent_class_policies(_BoomSession(), "team-a", "block")

    # Post-fix contract: (policies, degraded). Pre-fix code returned a bare list `[]`.
    assert isinstance(result, tuple), "expected a (policies, degraded) tuple that can signal a failed read"
    policies, degraded = result
    assert policies == []
    assert degraded is True, "a swallowed DB fault must be surfaced as degraded, not an empty success"


async def test_agent_class_query_failure_emits_observable_log() -> None:
    """The swallowed fault must leave a trace — NRVQ-API-7081 — so a DB outage is diagnosable rather
    than silently indistinguishable from an empty namespace (matches the sibling _load_mapping path)."""
    with structlog.testing.capture_logs() as logs:
        await _agent_class_policies(_BoomSession(), "team-a", "block")
    assert any("NRVQ-API-7081" in str(rec.get("code", "")) for rec in logs), (
        "a DB fault in the agent-class query must emit an observable NRVQ-API-7081 log record"
    )


async def test_agent_class_efficacy_failure_marks_degraded_but_keeps_policies() -> None:
    """If only the efficacy overlay fails, the policies still return, but the numbers are incomplete —
    the section is degraded (and logged), not silently presented as real zeroes."""
    with structlog.testing.capture_logs() as logs:
        policies, degraded = await _agent_class_policies(
            _EfficacyBoomSession([_policy_row()]), "team-a", "block"
        )
    assert len(policies) == 1 and policies[0]["cls"] == "report-gen"
    assert degraded is True
    assert any("NRVQ-API-7081" in str(rec.get("code", "")) for rec in logs)


async def test_agent_class_healthy_read_is_not_degraded() -> None:
    """Control: a clean read returns the policies with degraded=False and emits no error log — so the
    degraded flag genuinely discriminates failure from success (not a constant)."""
    session = _HealthySession(
        policy_rows=[_policy_row()],
        # (agent_class, decision, rule_id, framework, count) — framework "" = real traffic (not excluded)
        efficacy_rows=[("report-gen", "block", "deny_x", "", 5)],
    )
    with structlog.testing.capture_logs() as logs:
        policies, degraded = await _agent_class_policies(session, "team-a", "block")
    assert len(policies) == 1
    assert policies[0]["blocked"] == 5 and policies[0]["effective"] is True
    assert degraded is False
    assert not any("NRVQ-API-7081-ERR" in str(rec.get("code", "")) for rec in logs)


async def test_agent_class_efficacy_excludes_redteam_traffic() -> None:
    """The agent-class efficacy overlay attests REAL enforcement — red-team framework rows must NOT
    inflate a class's blocked/observed counts. Regression for the metric-dilution class: the chatbot's
    real langchain blocks were commingled with session-'p' red-team curl-probe blocks on the same class,
    overstating enforcement on the Overview efficacy bars."""
    session = _HealthySession(
        policy_rows=[_policy_row()],
        efficacy_rows=[
            ("report-gen", "block", "deny_x", "", 3),          # real traffic → counts
            ("report-gen", "block", "deny_x", "redteam", 7),   # red-team efficacy run → excluded
        ],
    )
    policies, degraded = await _agent_class_policies(session, "team-a", "block")
    assert degraded is False and len(policies) == 1
    assert policies[0]["blocked"] == 3, "red-team blocks must not inflate real efficacy"
    assert policies[0]["observed"] == 3


async def test_agent_class_empty_namespace_is_not_degraded() -> None:
    """An honestly-empty namespace (query succeeds, zero rows) must NOT be flagged degraded — the whole
    point is to tell 'no policies' apart from 'read failed'."""
    policies, degraded = await _agent_class_policies(
        _HealthySession(policy_rows=[], efficacy_rows=[]), "team-a", "block"
    )
    assert policies == []
    assert degraded is False


# --- The flag is threaded onto the served response -------------------------------------------------

def _client(session) -> TestClient:
    app = create_app()
    app.state.loader = SimpleNamespace(_policies={})

    async def _override():
        yield session

    app.dependency_overrides[get_session] = _override
    return TestClient(app)


def _token() -> str:
    # `exp` is required by the HS256 decode path, so mint a live one.
    return jwt.encode(
        {"sub": "u", "role": "admin", "exp": int(time.time()) + 3600},
        settings.api_secret_key,
        algorithm="HS256",
    )


def test_coverage_response_surfaces_agent_class_degraded_flag() -> None:
    """End-to-end: when the agent-class read fails, the 200 response carries
    `agent_class_policies_degraded: true` so the UI shows 'section unavailable', not 'none applied'."""
    resp = _client(_BoomSession()).get(
        "/api/v1/coverage-by-category?namespace=team-a",
        headers={"Authorization": f"Bearer {_token()}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["agent_class_policies"] == []
    assert body["agent_class_policies_degraded"] is True
