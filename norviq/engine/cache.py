# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Async Redis cache for policies, trust scores, and eval results."""

from __future__ import annotations

import hashlib
import json
import random

import redis.asyncio as aioredis
import structlog

from norviq.config import settings
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.trust import TrustScore
from norviq.telemetry.metrics import record_cache_hit, record_cache_miss

log = structlog.get_logger()
POLICY_EVENTS_CHANNEL = "norviq:policy_events"


def _hash_seg(segment: str) -> str:
    """Hash ONE attacker-controlled key segment to a fixed-width, colon-free token.

    CRITICAL collision class (live-exploited): Redis keys were built by joining
    attacker-controlled segments with bare colons, e.g. ``f"eval:{namespace}:{agent_class}:{tool_name}"``.
    Because `agent_class`/`tool_name` come straight from POST /evaluate, a caller could pick
    `agent_class="cache-collide-coarse"`, `tool_name="secret_tool:probe"` and collide onto a
    DIFFERENT logical identity `agent_class="cache-collide-coarse:secret_tool"`, `tool_name="probe"` —
    since the cache check runs BEFORE policy lookup, a poisoned "allow" cached under one identity
    was served to the other, bypassing a block policy. `opa_client.sanitize_key` already fixed the
    identical collision class for the OPA package-name identifier (digest-suffixed); this is the
    same fix applied per-segment to Redis keys so segments can never bleed across the `:` delimiter.
    Deterministic: same input -> same output, so get/set/invalidate call sites stay consistent.
    """
    return hashlib.sha256(segment.encode("utf-8")).hexdigest()[:16]

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
        self._redis = aioredis.from_url(
            self._url,
            max_connections=settings.redis_max_connections,
            decode_responses=True,
            # Resilience: proactively validate idle connections and keep TCP alive so a Redis restart
            # is recovered transparently on the next command (paired with the /readyz drain).
            health_check_interval=settings.redis_health_check_interval_s,
            socket_keepalive=True,
            retry_on_timeout=True,
        )
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

    @property
    def _pool(self) -> aioredis.Redis:
        """Compatibility alias for internal Redis client."""
        return self._client()

    def _jitter_ttl(self, base_ttl: int) -> int:
        """Add 0-10 percent jitter to base TTL."""
        return base_ttl + random.randint(0, int(base_ttl * 0.1))

    def _policy_key(self, namespace: str, agent_class: str) -> str:
        """Build the `policy:` Redis key with EACH segment hashed independently (see `_hash_seg`).
        Keeps the colon structure so the key shape/prefix is unchanged; only the segment CONTENTS are
        hashed, so `namespace`/`agent_class` can never bleed across the `:` delimiter."""
        return f"policy:{_hash_seg(namespace)}:{_hash_seg(agent_class)}"

    def _eval_key(self, namespace: str, agent_class: str, tool_name: str) -> str:
        """Build the `eval:` Redis key with EACH segment hashed independently (see `_hash_seg`) — this
        is the collision the finding exploited. Used by get_eval/set_eval so both stay consistent."""
        return f"eval:{_hash_seg(namespace)}:{_hash_seg(agent_class)}:{_hash_seg(tool_name)}"

    def _eval_scope_pattern(self, namespace: str, agent_class: str | None = None) -> str:
        """Build the wildcard SCAN pattern for eval-cache invalidation. `namespace`/`agent_class` are
        hashed to the SAME fixed tokens `_eval_key` produces, and the `tool_name` segment is left as the
        literal `*` wildcard — this is what preserves (ns, class)-scoped wildcard invalidation across the
        hashing fix: `eval:{h(ns)}:{h(class)}:*` still matches every tool_name cached for that scope."""
        if agent_class:
            return f"eval:{_hash_seg(namespace)}:{_hash_seg(agent_class)}:*"
        return f"eval:{_hash_seg(namespace)}:*"

    async def get_policy(self, namespace: str, agent_class: str) -> str | None:
        """Get cached policy source."""
        entry = await self.get_policy_entry(namespace, agent_class)
        if entry is None:
            return None
        return str(entry.get("rego", ""))

    async def get_policy_entry(self, namespace: str, agent_class: str) -> dict | None:
        """Get cached policy entry including metadata."""
        key = self._policy_key(namespace, agent_class)
        value = await self._client().get(key)
        if value is None:
            return None
        log.debug("nrvq.cache.policy.hit", key=key, code="NRVQ-DB-9011")
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            # Backward compatibility for older raw-string cache values.
            return {"rego": value, "priority": 100, "version": 0}
        return {"rego": value, "priority": 100, "version": 0}

    async def set_policy(self, namespace: str, agent_class: str, rego: str, priority: int = 100, version: int = 0) -> None:
        """Cache policy source with TTL jitter."""
        key = self._policy_key(namespace, agent_class)
        ttl = self._jitter_ttl(settings.redis_ttl_policy_s)
        # namespace/agent_class are carried in the VALUE (plaintext) so list_policy_entries() can
        # reverse-map a hashed key back to its real (ns, class) for callers that parse namespace/
        # agent_class out of the returned dict key (see list_policy_entries docstring).
        payload = json.dumps(
            {"rego": rego, "priority": int(priority), "version": int(version),
             "namespace": namespace, "agent_class": agent_class}
        )
        await self._client().setex(key, ttl, payload)
        log.debug("nrvq.cache.policy.set", key=key, ttl=ttl, code="NRVQ-DB-9012")

    async def delete_policy(self, namespace: str, agent_class: str) -> None:
        """Delete cached policy source."""
        key = self._policy_key(namespace, agent_class)
        await self._client().delete(key)
        log.debug("nrvq.cache.policy.deleted", key=key, code="NRVQ-DB-9020")

    async def warm_policy(
        self,
        namespace: str,
        agent_class: str,
        rego: str,
        priority: int = 100,
        version: int = 0,
    ) -> bool:
        """Warm policy cache using first-writer-wins semantics."""
        key = self._policy_key(namespace, agent_class)
        ttl = self._jitter_ttl(settings.redis_ttl_policy_s)
        payload = json.dumps(
            {"rego": rego, "priority": int(priority), "version": int(version),
             "namespace": namespace, "agent_class": agent_class}
        )
        return bool(await self._client().set(key, payload, ex=ttl, nx=True))

    async def list_policy_entries(self) -> dict[str, dict]:
        """List all cached policy entries for runtime hydration.

        The Redis KEY itself is now `policy:{hash(ns)}:{hash(class)}` (collision-fix), which is not
        reverse-parseable. Callers (policy_loader.load_all_from_redis) reverse-parse namespace/
        agent_class OUT of the returned dict key via `key.split(":", 2)`, so we reconstruct a
        plaintext `policy:{namespace}:{agent_class}` DISPLAY key here from the namespace/agent_class
        carried in the cached VALUE (set_policy/warm_policy embed them) instead of the real hashed
        Redis key. Entries cached before this fix (no namespace/agent_class in the value) are skipped
        rather than guessed at — they age out on the short policy TTL and get re-cached correctly.
        """
        entries: dict[str, dict] = {}
        client = self._client()
        async for key in client.scan_iter(match="policy:*"):
            value = await client.get(key)
            if value is None:
                continue
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                parsed = {"rego": value, "priority": 100, "version": 0}
            if not isinstance(parsed, dict):
                continue
            namespace = parsed.get("namespace")
            agent_class = parsed.get("agent_class")
            if not namespace or not agent_class:
                log.warning("nrvq.cache.policy.entry_missing_ns_class", key=str(key), code="NRVQ-DB-9028")
                continue
            entries[f"policy:{namespace}:{agent_class}"] = parsed
        return entries

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
        key = self._eval_key(namespace, agent_class, tool_name)
        value = await self._client().get(key)
        if value is None:
            record_cache_miss("eval")
            return None
        record_cache_hit("eval")
        log.debug("nrvq.cache.eval.hit", key=key, code="NRVQ-DB-9017")
        return PolicyDecision.model_validate_json(value)

    async def set_eval(self, namespace: str, agent_class: str, tool_name: str, decision: PolicyDecision) -> None:
        """Cache policy decision with TTL jitter."""
        key = self._eval_key(namespace, agent_class, tool_name)
        await self._pool.set(key, decision.model_dump_json(), ex=settings.redis_ttl_eval_s)
        log.debug("nrvq.cache.eval.set", key=key, ttl=settings.redis_ttl_eval_s, code="NRVQ-DB-9018")

    async def invalidate_eval_scope(self, namespace: str, agent_class: str | None = None) -> int:
        """Invalidate cached eval decisions for a namespace/class scope."""
        pattern = self._eval_scope_pattern(namespace, agent_class)
        client = self._client()
        keys = []
        async for key in client.scan_iter(match=pattern):
            keys.append(key)
        if not keys:
            return 0
        deleted = int(await client.delete(*keys))
        log.info("nrvq.cache.eval.invalidated", namespace=namespace, agent_class=agent_class, count=deleted, code="NRVQ-DB-9021")
        return deleted

    async def invalidate_all_eval(self) -> int:
        """Invalidate all cached eval decisions across namespaces."""
        client = self._client()
        keys = []
        async for key in client.scan_iter(match="eval:*"):
            keys.append(key)
        if not keys:
            return 0
        deleted = int(await client.delete(*keys))
        log.info("nrvq.cache.eval.invalidated_all", count=deleted, code="NRVQ-DB-9022")
        return deleted

    async def publish_policy_event(self, operation: str, namespace: str, agent_class: str, version: int = 0, origin: str = "") -> None:
        """Publish a policy mutation event for multi-replica synchronization. `origin` = the publishing
        process id so a subscriber can skip its own echo (pub/sub broadcasts to every subscriber incl. self)."""
        payload = json.dumps(
            {
                "operation": operation,
                "namespace": namespace,
                "agent_class": agent_class,
                "version": int(version),
                "origin": origin,
            }
        )
        await self._client().publish(POLICY_EVENTS_CHANNEL, payload)

    async def listen_policy_events(self, callback) -> None:
        """Listen for policy invalidation events from other replicas."""
        pubsub = self._pool.pubsub()
        await pubsub.subscribe("norviq:policy:invalidated")
        log.info("nrvq.cache.pubsub_listening", code="NRVQ-DB-9030")
        async for message in pubsub.listen():
            if message["type"] == "message":
                key = message["data"]
                if isinstance(key, bytes):
                    key = key.decode()
                log.debug("nrvq.cache.pubsub_received", key=key, code="NRVQ-DB-9031")
                await callback(key)

    async def listen_policy_mutations(self, callback) -> None:
        """HA: subscribe to the full policy-mutation stream (POLICY_EVENTS_CHANNEL) and invoke
        `callback(operation, namespace, agent_class, origin)` for EVERY create/apply(upsert)/delete on any
        replica. Unlike listen_policy_events (upsert key only, sidecar), this carries the operation so a
        peer API replica can UNLOAD on delete as well as reload on upsert — the load-bearing HA sync."""
        pubsub = self._pool.pubsub()
        await pubsub.subscribe(POLICY_EVENTS_CHANNEL)
        log.info("nrvq.cache.policy_mutations_listening", channel=POLICY_EVENTS_CHANNEL, code="NRVQ-DB-9032")
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            data = message["data"]
            if isinstance(data, bytes):
                data = data.decode()
            try:
                evt = json.loads(data)
            except (ValueError, TypeError):
                continue
            await callback(str(evt.get("operation", "")), str(evt.get("namespace", "")),
                           str(evt.get("agent_class", "")), str(evt.get("origin", "")))

    async def incr_call_count(self, spiffe_id: str, window_s: int = 60) -> int:
        """Increment call count atomically for rate windows."""
        key = f"callcount:{spiffe_id}"
        count = await self._client().incr(key)
        if count == 1:
            await self._client().expire(key, window_s)
        log.debug("nrvq.cache.callcount.incr", key=key, count=count, code="NRVQ-DB-9019")
        return int(count)

    async def peek_call_count(self, spiffe_id: str) -> int:
        """Read the current windowed call count WITHOUT incrementing (LOGIN-2 lockout pre-check)."""
        raw = await self._client().get(f"callcount:{spiffe_id}")
        return int(raw) if raw is not None else 0

    async def reset_call_count(self, spiffe_id: str) -> None:
        """Clear a windowed call counter (LOGIN-2: a successful login resets its failed-attempt count)."""
        await self._client().delete(f"callcount:{spiffe_id}")

    # F-05: graph ANALYSIS result cache, keyed by (namespace, content-hash version, type, params) so a
    # repeated analysis call is served from cache and invalidated automatically when the graph changes.
    @staticmethod
    def _analysis_key(namespace: str, version: str, analysis_type: str, params: str = "") -> str:
        return f"graph:analysis:{analysis_type}:{namespace}:{version}:{params}"

    async def get_analysis(self, namespace: str, version: str, analysis_type: str, params: str = "") -> object | None:
        """Return a cached graph-analysis result, or None on miss."""
        raw = await self._client().get(self._analysis_key(namespace, version, analysis_type, params))
        if raw is None:
            return None
        log.debug("nrvq.cache.analysis.hit", type=analysis_type, namespace=namespace, code="NRVQ-DB-9023")
        return json.loads(raw)

    async def set_analysis(
        self, namespace: str, version: str, analysis_type: str, result: object, params: str = "", ttl: int = 600
    ) -> None:
        """Cache a graph-analysis result (default 10-minute TTL)."""
        await self._client().set(
            self._analysis_key(namespace, version, analysis_type, params), json.dumps(result), ex=ttl
        )
        log.debug("nrvq.cache.analysis.set", type=analysis_type, namespace=namespace, code="NRVQ-DB-9024")

    async def delete_analysis_scope(self, namespace: str) -> int:
        """Invalidate ALL cached analysis results for a namespace (called when its graph snapshot changes)."""
        deleted = 0
        async for key in self._client().scan_iter(match=f"graph:analysis:*:{namespace}:*"):
            deleted += int(await self._client().delete(key))
        if deleted:
            log.info("nrvq.cache.analysis.invalidated", namespace=namespace, count=deleted, code="NRVQ-DB-9025")
        return deleted

    async def get_session(self, session_id: str) -> dict | None:
        """Get cached session payload."""
        key = f"session:{session_id}"
        value = await self._client().get(key)
        return None if value is None else json.loads(value)

    async def set_session(self, session_id: str, data: dict) -> None:
        """Cache session payload with configured TTL."""
        key = f"session:{session_id}"
        await self._client().setex(key, settings.session_ttl_s, json.dumps(data))

    async def revoke_token(self, token_hash: str, ttl_s: int) -> None:
        """AUTH-01 logout denylist: mark a token hash revoked until the token's own expiry."""
        key = f"revoked:{token_hash}"
        await self._client().setex(key, max(1, int(ttl_s)), "1")
        log.info("nrvq.cache.token.revoked", key=key[:20], ttl=ttl_s, code="NRVQ-DB-9026")

    async def is_token_revoked(self, token_hash: str) -> bool:
        """AUTH-01 logout denylist: True if this token hash was revoked and has not yet expired."""
        return await self._client().get(f"revoked:{token_hash}") is not None

    async def set_ns_settings(self, namespace: str, fields: dict) -> None:
        """CFG-SETTINGS-INERT-01: mirror a namespace's RAW persisted settings override into Redis so the engine
        hot path can resolve per-ns posture without a per-eval DB read (the evaluator holds only this cache, and
        multi-replica correctness needs a shared store). Nulls are preserved — the evaluator does per-field
        fallback to the global config. No TTL; the source of truth stays the DB row (settings_router writes both)."""
        await self._client().set(f"nsconfig:{namespace}", json.dumps(fields))
        log.info("nrvq.cache.ns_settings.set", namespace=namespace, code="NRVQ-DB-9027")

    async def get_ns_settings(self, namespace: str) -> dict | None:
        """CFG-SETTINGS-INERT-01: the mirrored per-ns settings override, or None if the namespace has none."""
        value = await self._client().get(f"nsconfig:{namespace}")
        return None if value is None else json.loads(value)

    async def set_trust_override(self, spiffe_id: str, score: float) -> None:
        """AGT-TRUST-02: durable admin trust CAP for one agent (mirrors the agent_frozen: pattern, no TTL). The
        routine trust:{spiffe} behavioral score is recomputed + clobbered every eval, so a manual pin needs its own
        key. Applied as min(computed, override) — tighten-only, never raises trust above what behavior justifies."""
        await self._client().set(f"agent_trust_override:{spiffe_id}", str(float(score)))

    async def clear_trust_override(self, spiffe_id: str) -> None:
        """AGT-TRUST-02: remove the admin trust cap (score cleared / set to 1.0 / frozen)."""
        await self._client().delete(f"agent_trust_override:{spiffe_id}")
