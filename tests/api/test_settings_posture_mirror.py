# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Namespace monitor mode, set from the settings API, must reach the engine that enforces it.

This is one of the three documented ways to stop the enforcing baseline refusing calls (the console's
Target Settings -> Monitor, or `PUT /settings?namespace=<ns>` with `enforcement_mode: audit`). The
softening itself is tested on the resolver (tests/engine/test_posture_trust_wiring.py: a block becomes
`audit` / `monitor_would_block:<rule>`); what was not tested is the hop between them. The row lands in
Postgres, but the engine never reads Postgres for posture: it reads a Redis mirror (`nsconfig:<ns>`)
that only this route writes. A save that skipped the mirror would return 200, show Monitor in the
console, and keep blocking.
"""

from __future__ import annotations

import os
import uuid
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from norviq.api.auth import get_current_user
from norviq.api.db.session import get_session
from norviq.api.main import create_app
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator


class _NoRow:
    """No persisted override yet; writes are no-ops."""

    async def execute(self, stmt):  # noqa: ANN001
        _ = stmt
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    def add(self, obj) -> None:  # noqa: ANN001
        return None

    async def commit(self) -> None:
        return None

    async def close(self) -> None:
        return None


class _RecordingCache:
    def __init__(self) -> None:
        self.mirrored: dict[str, dict] = {}

    async def set_ns_settings(self, namespace: str, fields: dict) -> None:
        self.mirrored[namespace] = fields


def test_saving_monitor_writes_the_mirror_the_engine_reads() -> None:
    app = create_app()
    cache = _RecordingCache()
    app.state.cache = cache

    async def _session():
        yield _NoRow()

    app.dependency_overrides[get_session] = _session
    # The principal is injected rather than minted: a real token for a fixed `sub` shares the session
    # revocation state in Redis with every other test that logs that `sub` out.
    app.dependency_overrides[get_current_user] = lambda: {"role": "admin", "namespace": "agents", "sub": "admin"}
    resp = TestClient(app).put("/api/v1/settings?namespace=agents", json={"enforcement_mode": "audit"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["enforcement_mode"] == "audit"
    assert cache.mirrored.get("agents", {}).get("enforcement_mode") == "audit", (
        f"the settings API saved Monitor but mirrored {cache.mirrored!r}; the engine would keep blocking")


@pytest.mark.asyncio
async def test_the_mirrored_mode_is_what_the_engine_resolves_as_monitor() -> None:
    """Through real Redis: the key the route writes is the key the evaluator reads."""
    url = os.getenv("NRVQ_REDIS_URL")
    if not url:
        pytest.skip("NRVQ_REDIS_URL not set")
    namespace = f"mirror-{uuid.uuid4().hex[:10]}"
    cache = RedisCache(url=url)
    await cache.connect()
    evaluator = OPAEvaluator(cache)
    try:
        assert (await evaluator._resolve_posture(namespace))["monitor"] is False
        evaluator._posture_cache.clear()
        await cache.set_ns_settings(namespace, {"enforcement_mode": "audit", "trust_threshold": None,
                                                "rate_limit": None})
        assert (await evaluator._resolve_posture(namespace))["monitor"] is True
    finally:
        await cache._client().delete(f"nsconfig:{namespace}")
        await evaluator.close()
        await cache.close()
