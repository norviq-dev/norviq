# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Async Redis cache for policies, trust scores, and eval results."""

from __future__ import annotations

import json
import random

import redis.asyncio as aioredis
import structlog

from norviq.config import settings
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.trust import TrustScore

log = structlog.get_logger()

TRUST_DECREMENT_LUA = """
local current = redis.call('GET', KEYS[1])
if not current then return nil end
local data = cjson.decode(current)
data['score'] = math.max(0, data['score'] - tonumber(ARGV[1]))
if data['score'] >= tonumber(ARGV[2]) then data['category'] = 'High'
elseif data['score'] >= 0.4 then data['category'] = 'Medium'
else data['category'] = 'Low' end
data['violation_count'] = (data['violation_count'] or 0) + 1
local encoded = cjson.encode(data)
redis.call('SETEX', KEYS[1], tonumber(ARGV[3]), encoded)
return encoded
"""


class RedisCache:
    """Async Redis cache for runtime policy and trust data."""

    def __init__(self, url: str | None = None) -> None:
        """Store Redis connection info."""
        self._url = url or settings.redis_url
        self._redis: aioredis.Redis | None = None
        self._trust_decr_sha: str | None = None

    async def connect(self) -> None:
        """Initialize the Redis client and Lua scripts."""
        self._redis = aioredis.from_url(self._url, max_connections=20, decode_responses=True)
        self._trust_decr_sha = await self._redis.script_load(TRUST_DECREMENT_LUA)
        log.info("nrvq.cache.connected", url=self._url, code="NRVQ-DB-9010")

    async def close(self) -> None:
        """Close all Redis connections."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    def _client(self) -> aioredis.Redis:
        """Return connected Redis client."""
        if self._redis is None:
            raise RuntimeError("RedisCache.connect() must be called before use")
        return self._redis

    def _jitter_ttl(self, base_ttl: int) -> int:
        """Add 0-10 percent jitter to base TTL."""
        return base_ttl + random.randint(0, int(base_ttl * 0.1))

    async def get_policy(self, namespace: str, agent_class: str) -> str | None:
        """Get cached policy source."""
        key = f"policy:{namespace}:{agent_class}"
        value = await self._client().get(key)
        if value is not None:
            log.debug("nrvq.cache.policy.hit", key=key, code="NRVQ-DB-9011")
        return value

    async def set_policy(self, namespace: str, agent_class: str, rego: str) -> None:
        """Cache policy source with TTL jitter."""
        key = f"policy:{namespace}:{agent_class}"
        ttl = self._jitter_ttl(settings.redis_ttl_policy_s)
        await self._client().setex(key, ttl, rego)
        log.debug("nrvq.cache.policy.set", key=key, ttl=ttl, code="NRVQ-DB-9012")

    async def warm_policy(self, namespace: str, agent_class: str, rego: str) -> bool:
        """Warm policy cache using first-writer-wins semantics."""
        key = f"policy:{namespace}:{agent_class}"
        ttl = self._jitter_ttl(settings.redis_ttl_policy_s)
        return bool(await self._client().set(key, rego, ex=ttl, nx=True))

    async def get_trust(self, spiffe_id: str) -> TrustScore | None:
        """Get cached trust score."""
        key = f"trust:{spiffe_id}"
        value = await self._client().get(key)
        if value is None:
            return None
        log.debug("nrvq.cache.trust.hit", key=key, code="NRVQ-DB-9013")
        return TrustScore.model_validate_json(value)

    async def set_trust(self, spiffe_id: str, score: TrustScore) -> None:
        """Cache trust score with TTL jitter."""
        key = f"trust:{spiffe_id}"
        ttl = self._jitter_ttl(settings.redis_ttl_trust_s)
        await self._client().setex(key, ttl, score.model_dump_json())
        log.debug("nrvq.cache.trust.set", key=key, ttl=ttl, code="NRVQ-DB-9014")

    async def decrement_trust(self, spiffe_id: str) -> TrustScore | None:
        """Atomically decrement trust score with Lua."""
        key = f"trust:{spiffe_id}"
        result = await self._client().evalsha(
            self._trust_decr_sha,
            1,
            key,
            str(settings.trust_violation_penalty),
            str(settings.trust_threshold),
            str(self._jitter_ttl(settings.redis_ttl_trust_s)),
        )
        if result is None:
            log.warning("nrvq.cache.trust.not_found", key=key, code="NRVQ-DB-9016")
            return None
        log.info("nrvq.cache.trust.decremented", key=key, code="NRVQ-DB-9015")
        return TrustScore.model_validate_json(result)

    async def get_eval(self, namespace: str, agent_class: str, tool_name: str) -> PolicyDecision | None:
        """Get cached policy decision."""
        key = f"eval:{namespace}:{agent_class}:{tool_name}"
        value = await self._client().get(key)
        if value is None:
            return None
        log.debug("nrvq.cache.eval.hit", key=key, code="NRVQ-DB-9017")
        return PolicyDecision.model_validate_json(value)

    async def set_eval(self, namespace: str, agent_class: str, tool_name: str, decision: PolicyDecision) -> None:
        """Cache policy decision with TTL jitter."""
        key = f"eval:{namespace}:{agent_class}:{tool_name}"
        ttl = self._jitter_ttl(settings.redis_ttl_policy_s)
        await self._client().setex(key, ttl, decision.model_dump_json())
        log.debug("nrvq.cache.eval.set", key=key, ttl=ttl, code="NRVQ-DB-9018")

    async def incr_call_count(self, spiffe_id: str, window_s: int = 60) -> int:
        """Increment call count atomically for rate windows."""
        key = f"callcount:{spiffe_id}"
        count = await self._client().incr(key)
        if count == 1:
            await self._client().expire(key, window_s)
        log.debug("nrvq.cache.callcount.incr", key=key, count=count, code="NRVQ-DB-9019")
        return int(count)

    async def get_session(self, session_id: str) -> dict | None:
        """Get cached session payload."""
        key = f"session:{session_id}"
        value = await self._client().get(key)
        return None if value is None else json.loads(value)

    async def set_session(self, session_id: str, data: dict) -> None:
        """Cache session payload with configured TTL."""
        key = f"session:{session_id}"
        await self._client().setex(key, settings.session_ttl_s, json.dumps(data))
