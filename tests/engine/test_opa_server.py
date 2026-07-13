# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""R7: OPA-server evaluator fails CLOSED on OPA unavailability, self-heals, and survives concurrency."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from norviq.config import settings
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.engine.opa_client import sanitize_key
from norviq.engine.trust.models import TrustResult
from norviq.sdk.core.events import AgentIdentity, ToolCallEvent

_REGO = Path("comprehensive.rego").read_text(encoding="utf-8")
_KEY = "default:customer-support"


def _event(tool_name: str = "search_kb", params: dict | None = None) -> ToolCallEvent:
    return ToolCallEvent(
        tool_name=tool_name,
        tool_params=params or {"query": "hi"},
        agent_identity=AgentIdentity(
            spiffe_id="spiffe://norviq/ns/default/sa/customer-support", namespace="default", agent_class="customer-support"
        ),
        session_id="srv",
    )


def _trust() -> TrustResult:
    return TrustResult(score=0.8, category="high", signals={}, weights={}, dominant_signal="", recommendation="")


@pytest.mark.asyncio
async def test_fail_closed_when_opa_unreachable(monkeypatch) -> None:
    """OPA down -> evaluate one candidate -> block with evaluator_error (never fail open)."""
    monkeypatch.setattr(settings, "opa_mode", "server")
    monkeypatch.setattr(settings, "opa_url", "http://127.0.0.1:1")  # refused, no managed server
    evaluator = OPAEvaluator(RedisCache())
    try:
        decision = await evaluator._evaluate_single(_event(), _KEY, _REGO, _trust())
        assert decision.decision == "block"
        assert decision.rule_id == "evaluator_error"
    finally:
        await evaluator.opa.stop()


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary required")
@pytest.mark.asyncio
async def test_self_heal_after_module_lost(monkeypatch) -> None:
    """If OPA loses a module (sidecar restart), the next eval re-pushes and still decides."""
    monkeypatch.setattr(settings, "opa_mode", "server")
    monkeypatch.setattr(settings, "opa_url", "")  # managed
    evaluator = OPAEvaluator(RedisCache())
    try:
        input_doc = evaluator._build_input(_event(), _trust())
        first = await evaluator._evaluate_opa_server(_KEY, _REGO, input_doc)
        assert first["decision"] == "allow"
        # Simulate OPA state loss: delete the module out from under the evaluator.
        await evaluator.opa.delete_policy(sanitize_key(_KEY))
        # _pushed still records the digest, so this only succeeds via re-push-on-undefined.
        healed = await evaluator._evaluate_opa_server(_KEY, _REGO, input_doc)
        assert healed["decision"] == "allow"
    finally:
        await evaluator.opa.stop()


@pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary required")
@pytest.mark.asyncio
async def test_concurrent_server_evaluations(monkeypatch) -> None:
    """50 concurrent candidate evals in server mode all succeed (no serialization timeouts)."""
    monkeypatch.setattr(settings, "opa_mode", "server")
    monkeypatch.setattr(settings, "opa_url", "")
    evaluator = OPAEvaluator(RedisCache())
    try:
        await evaluator.opa.start()
        results = await asyncio.gather(
            *(evaluator._evaluate_single(_event(params={"query": f"q-{i}"}), _KEY, _REGO, _trust()) for i in range(50))
        )
        assert len(results) == 50
        assert all(r.decision == "allow" and r.rule_id == "default_allow" for r in results)
    finally:
        await evaluator.opa.stop()
