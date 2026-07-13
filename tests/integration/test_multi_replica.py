# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Integration tests for multi-replica policy propagation."""

from __future__ import annotations

import asyncio
import os
import uuid

import httpx
import pytest


def _replica_urls() -> list[str]:
    raw = (os.getenv("NRVQ_API_URLS") or "").strip()
    if not raw:
        return []
    return [item.strip().rstrip("/") for item in raw.split(",") if item.strip()]


@pytest.mark.asyncio
async def test_multi_replica_sees_new_policy() -> None:
    urls = _replica_urls()
    if len(urls) < 2:
        pytest.skip("Need NRVQ_API_URLS with at least two replica endpoints")

    namespace = f"replica-{uuid.uuid4().hex}"
    rego = (
        "package norviq.strict\n"
        'default decision = "allow"\n'
        'decision = "block" { input.tool_name == "replica_test_tool" }\n'
        'rule_id = "replica_rule" { input.tool_name == "replica_test_tool" }\n'
    )

    async with httpx.AsyncClient(base_url=urls[0], timeout=15.0) as writer:
        create_response = await writer.post(
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

    await asyncio.sleep(2.0)

    async with httpx.AsyncClient(base_url=urls[1], timeout=15.0) as reader:
        eval_response = await reader.post(
            "/api/v1/evaluate",
            json={
                "tool_name": "replica_test_tool",
                "tool_params": {},
                "agent_identity": {
                    "spiffe_id": f"spiffe://norviq/ns/{namespace}/sa/test",
                    "namespace": namespace,
                    "agent_class": "test-class",
                },
                "session_id": "replica-test",
                "trust_score": 0.9,
            },
        )
    assert eval_response.status_code == 200, eval_response.text
    assert eval_response.json()["decision"] == "block"
