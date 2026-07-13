# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Redis-backed rolling call history store."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import structlog

from norviq.engine.cache import RedisCache

log = structlog.get_logger()


class AgentHistoryStore:
    """Store one-hour rolling history used by trust signals."""

    WINDOW_SECONDS = 3600
    MAX_ENTRIES = 500

    def __init__(self, cache: RedisCache) -> None:
        """Bind store to shared Redis cache."""
        self._cache = cache

    async def get_history(self, spiffe_id: str) -> list[dict[str, Any]]:
        """Return recent entries for one agent."""
        key = self._key(spiffe_id)
        now = datetime.now(timezone.utc).timestamp()
        cutoff = now - self.WINDOW_SECONDS
        rows = await self._cache._client().zrangebyscore(key, cutoff, now)
        parsed: list[dict[str, Any]] = []
        for row in rows:
            try:
                parsed.append(json.loads(row))
            except (json.JSONDecodeError, TypeError):
                continue
        return parsed

    async def record(self, spiffe_id: str, entry: dict[str, Any]) -> None:
        """Append one entry and enforce rolling limits."""
        key = self._key(spiffe_id)
        score = float(entry.get("timestamp_unix", datetime.now(timezone.utc).timestamp()))
        payload = json.dumps(entry, default=str)
        client = self._cache._client()
        async with client.pipeline(transaction=True) as pipe:
            await pipe.zadd(key, {payload: score})
            await pipe.zremrangebyscore(key, 0, score - self.WINDOW_SECONDS)
            await pipe.zremrangebyrank(key, 0, -(self.MAX_ENTRIES + 1))
            await pipe.expire(key, self.WINDOW_SECONDS)
            await pipe.execute()
        log.debug("nrvq.engine.trust.history.recorded", spiffe_id=spiffe_id, code="NRVQ-ENG-2047")

    async def clear(self, spiffe_id: str) -> None:
        """Clear all history for one agent."""
        await self._cache._client().delete(self._key(spiffe_id))

    def _key(self, spiffe_id: str) -> str:
        """Build redis key for one agent history."""
        return f"agent_history:{spiffe_id}"
