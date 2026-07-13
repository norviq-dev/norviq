# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

from datetime import datetime, timezone
import json

from norviq.engine.trust.history import AgentHistoryStore


class _ClientStub:
    def __init__(self) -> None:
        now = datetime.now(timezone.utc).timestamp()
        self.rows = [
            json.dumps({"decision": "block", "timestamp_unix": now - 7200}),
            json.dumps({"decision": "allow", "timestamp_unix": now - 10}),
        ]
        self.pipeline_ops: list[tuple] = []

    async def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> None:
        _ = key, min_score, max_score

    async def zrangebyscore(self, key: str, min_score: float, max_score: float) -> list[str]:
        _ = key
        kept = []
        for row in self.rows:
            payload = json.loads(row)
            if min_score <= float(payload.get("timestamp_unix", 0.0)) <= max_score:
                kept.append(row)
        return kept

    async def zadd(self, key: str, data: dict[str, float]) -> None:
        _ = key, data

    async def zremrangebyrank(self, key: str, start: int, stop: int) -> None:
        _ = key, start, stop

    async def expire(self, key: str, ttl: int) -> None:
        _ = key, ttl

    async def delete(self, key: str) -> None:
        _ = key

    def pipeline(self, transaction: bool = True):
        _ = transaction
        return _PipelineStub(self)


class _PipelineStub:
    def __init__(self, client: _ClientStub) -> None:
        self.client = client

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        _ = exc_type, exc, tb
        return False

    async def zadd(self, key: str, data: dict[str, float]) -> None:
        self.client.pipeline_ops.append(("zadd", key))
        await self.client.zadd(key, data)

    async def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> None:
        self.client.pipeline_ops.append(("zremrangebyscore", key, min_score, max_score))
        await self.client.zremrangebyscore(key, min_score, max_score)

    async def zremrangebyrank(self, key: str, start: int, stop: int) -> None:
        self.client.pipeline_ops.append(("zremrangebyrank", key, start, stop))
        await self.client.zremrangebyrank(key, start, stop)

    async def expire(self, key: str, ttl: int) -> None:
        self.client.pipeline_ops.append(("expire", key, ttl))
        await self.client.expire(key, ttl)

    async def execute(self) -> None:
        return None


class _CacheStub:
    def __init__(self) -> None:
        self.client = _ClientStub()

    def _client(self) -> _ClientStub:
        return self.client


async def test_history_store_round_trip_methods() -> None:
    store = AgentHistoryStore(_CacheStub())
    await store.record("spiffe://a", {"timestamp_unix": datetime.now(timezone.utc).timestamp()})
    history = await store.get_history("spiffe://a")
    assert len(history) == 1
    assert history[0]["decision"] == "allow"


async def test_history_record_trims_and_sets_expiry() -> None:
    cache = _CacheStub()
    store = AgentHistoryStore(cache)
    await store.record("spiffe://a", {"timestamp_unix": datetime.now(timezone.utc).timestamp()})
    op_names = [row[0] for row in cache.client.pipeline_ops]
    assert op_names == ["zadd", "zremrangebyscore", "zremrangebyrank", "expire"]
