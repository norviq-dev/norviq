# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration tests for API -> DB -> evaluate policy lifecycle."""

from __future__ import annotations

import uuid

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


@pytest.fixture
async def db_engine(pg_url: str) -> AsyncEngine:
    engine = create_async_engine(pg_url.replace("postgresql://", "postgresql+asyncpg://"))
    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_post_policy_appears_in_db(api_client: httpx.AsyncClient, db_engine: AsyncEngine) -> None:
    namespace = f"integration-{uuid.uuid4().hex}"
    payload = {
        "namespace": namespace,
        "agent_class": "test-class",
        "rego_source": 'package norviq.strict\ndefault decision = "allow"',
        "enforcement_mode": "block",
        "saved_by": "test",
        "priority": 100,
    }
    response = await api_client.post("/api/v1/policies", json=payload)
    assert response.status_code == 200, response.text

    async with db_engine.begin() as conn:
        row = (
            await conn.execute(
                text("SELECT namespace, agent_class FROM policies WHERE namespace = :namespace"),
                {"namespace": namespace},
            )
        ).mappings().first()
    assert row is not None
    assert row["agent_class"] == "test-class"


@pytest.mark.asyncio
async def test_policy_roundtrip_post_db_evaluate(api_client: httpx.AsyncClient, db_engine: AsyncEngine) -> None:
    namespace = f"integration-{uuid.uuid4().hex}"
    rego = (
        "package norviq.strict\n"
        'default decision = "allow"\n'
        'decision = "block" { input.tool_name == "integration_test_tool" }\n'
        'rule_id = "integration_rule" { input.tool_name == "integration_test_tool" }\n'
    )
    create_response = await api_client.post(
        "/api/v1/policies",
        json={
            "namespace": namespace,
            "agent_class": "test-class",
            "rego_source": rego,
            "enforcement_mode": "block",
            "saved_by": "test",
            "priority": 100,
        },
    )
    assert create_response.status_code == 200, create_response.text

    async with db_engine.begin() as conn:
        persisted = (
            await conn.execute(text("SELECT id FROM policies WHERE namespace = :namespace"), {"namespace": namespace})
        ).first()
    assert persisted is not None

    evaluate_response = await api_client.post(
        "/api/v1/evaluate",
        json={
            "tool_name": "integration_test_tool",
            "tool_params": {},
            "agent_identity": {
                "spiffe_id": f"spiffe://norviq/ns/{namespace}/sa/test",
                "namespace": namespace,
                "agent_class": "test-class",
            },
            "session_id": "integration-test",
            "trust_score": 0.9,
        },
    )
    assert evaluate_response.status_code == 200, evaluate_response.text
    data = evaluate_response.json()
    assert data["decision"] == "block"
    assert data["rule_id"] == "integration_rule"
