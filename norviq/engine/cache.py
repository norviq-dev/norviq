# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Async Redis cache for policies, trust scores, and eval results."""

from __future__ import annotations

import hashlib
import json
import random

import redis.asyncio as aioredis
import structlog

from norviq.engine.masking import redact_url_credentials
from norviq.config import settings
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.trust import TrustScore
from norviq.telemetry.metrics import record_cache_hit, record_cache_miss

log = structlog.get_logger()
POLICY_EVENTS_CHANNEL = "norviq:policy_events"
# Live audit fan-out across API workers/replicas — see publish_audit_record.
AUDIT_RECORDS_CHANNEL = "norviq:audit_records"
# Outside the `revoked:` prefix on purpose, so a SCAN of the denylist never mistakes it for an entry and
# a 0.2.5 replica, which reads `revoked:<sha256>` only, can never collide with it.
REVOCATION_SEED_MARKER = "norviq:revocations_seeded"
# Commands per pipelined round trip when the API reads or rewrites the whole denylist.
_REVOKED_BATCH = 1000


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
        # Best-effort listeners fired whenever the Redis eval cache is invalidated (scope or all). The
        # evaluator registers its per-pod in-process eval-decision L1 here so EVERY invalidation path — the
        # loader chokepoint (origin-inline AND peer-via-pubsub) and packs.py's direct calls — clears the
        # in-proc mirror too, with no call site able to miss it. See OPAEvaluator._on_eval_invalidated.
        self._eval_invalidation_hooks: list = []

    def register_eval_invalidation_hook(self, callback) -> None:
        """Register callback(namespace|None, agent_class|None), invoked after any eval-cache invalidation."""
        self._eval_invalidation_hooks.append(callback)

    def _fire_eval_invalidation(self, namespace: str | None, agent_class: str | None) -> None:
        """Notify registered in-proc eval caches. Never let a hook error affect the Redis invalidation."""
        for hook in self._eval_invalidation_hooks:
            try:
                hook(namespace, agent_class)
            except Exception as exc:  # noqa: BLE001 — a hook must never break cache invalidation
                log.warning("nrvq.cache.eval.hook_failed", error=str(exc), code="NRVQ-DB-9023")

    async def connect(self) -> None:
        """Initialize the Redis client and Lua scripts."""
        # A BLOCKING pool, deliberately. redis-py's default `ConnectionPool` raises
        # `ConnectionError("Too many connections")` the moment it is exhausted, and the evaluator fails
        # CLOSED on any exception — so a brief burst did not make an agent's tool call slower, it made
        # it REFUSED. That showed up as 3/200 benign calls blocked with `evaluator_fallback` at
        # concurrency 8, which reads as an enforcement bug and is really a pool ceiling.
        #
        # `BlockingConnectionPool` queues instead, bounded by `timeout`, which is held well under the
        # evaluator's 2.0s OPA budget so a truly stuck Redis still lands on the NAMED `evaluator_timeout`
        # block rather than an anonymous fallback.
        pool = aioredis.BlockingConnectionPool.from_url(
            self._url,
            max_connections=settings.redis_max_connections,
            timeout=settings.redis_pool_wait_s,
            decode_responses=True,
            # Resilience: proactively validate idle connections and keep TCP alive so a Redis restart
            # is recovered transparently on the next command (paired with the /readyz drain).
            health_check_interval=settings.redis_health_check_interval_s,
            socket_keepalive=True,
            retry_on_timeout=True,
        )
        self._redis = aioredis.Redis(connection_pool=pool)
        self._trust_decr_sha = await self._redis.script_load(TRUST_DECREMENT_LUA)
        log.info("nrvq.cache.connected", url=redact_url_credentials(self._url), code="NRVQ-DB-9010")

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

    async def acquire_lock(self, name: str, holder: str, ttl_s: int) -> str | None:
        """Take a cross-replica lock, or report who already holds it.

        Returns None when acquired, and the CURRENT HOLDER's value when it was already taken — callers
        generally need to name the holder in the rejection, not merely refuse.

        `SET key value NX EX ttl` is a single round trip and atomic in Redis, so two API pods racing
        the same lock cannot both win. The TTL is the whole safety story: a pod that dies mid-work
        never releases, and without an expiry the lock would wedge that name permanently.
        """
        acquired = bool(await self._client().set(f"lock:{name}", holder, ex=ttl_s, nx=True))
        if acquired:
            return None
        current = await self._client().get(f"lock:{name}")
        # Lost the race AND the holder vanished between SET and GET — treat as acquired-by-nobody and
        # let the caller proceed rather than refusing on a lock that no longer exists.
        return current if current is not None else None

    async def release_lock(self, name: str, holder: str) -> None:
        """Release a lock this holder owns. A lock held by someone else is left alone.

        The ownership check matters after a TTL expiry: if this worker overran and another already
        took the name, deleting blindly would free a lock that is legitimately held.
        """
        key = f"lock:{name}"
        current = await self._client().get(key)
        if current == holder:
            await self._client().delete(key)

    async def list_policy_entries(self) -> dict[str, dict]:
        """List all cached policy entries for runtime hydration.

        The Redis KEY itself is now `policy:{hash(ns)}:{hash(class)}` (collision-fix), which is not
        reverse-parseable. Callers (policy_loader.load_all_from_redis) reverse-parse namespace/
        agent_class OUT of the returned dict key via `key.split(":", 2)`, so we reconstruct a
        plaintext `policy:{namespace}:{agent_class}` DISPLAY key here from the namespace/agent_class
        carried in the cached VALUE (set_policy/warm_policy embed them) instead of the real hashed
        Redis key. Entries cached without namespace/agent_class in the value are skipped
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

    @staticmethod
    def _parse_override(raw) -> float | None:
        """Parse a trust-cap value; None (no cap) on absent/malformed — matches _safe_override_only's fail-OPEN.
        A malformed value is logged (not silent): it means an admin cap isn't being applied, worth surfacing."""
        if raw is None:
            return None
        try:
            return float(raw)
        except (ValueError, TypeError) as exc:
            log.warning("nrvq.cache.override_parse_failed", value=str(raw)[:64], error=str(exc), code="NRVQ-DB-9026")
            return None

    async def get_agent_flags(self, spiffe_id: str) -> tuple[bool, float | None]:
        """Read the admin freeze + trust cap for one identity in ONE pipelined round trip.

        This is the hot-path kill-switch read: it is NEVER cached — the caller fetches it fresh every eval so a
        freeze/cap propagates cluster-wide on the next call. Fails CLOSED: on any Redis error return
        (frozen=True, cap=None), the same fail-direction as the per-key _safe_frozen_only (closed) +
        _safe_override_only (open) it replaces, so a Redis outage blocks rather than silently unfreezing."""
        try:
            client = self._client()
            async with client.pipeline(transaction=False) as pipe:
                await pipe.get(f"agent_frozen:{spiffe_id}")
                await pipe.get(f"agent_trust_override:{spiffe_id}")
                frozen_raw, override_raw = await pipe.execute()
            return bool(frozen_raw), self._parse_override(override_raw)
        except Exception as exc:  # noqa: BLE001 — fail CLOSED (frozen) so a Redis loss cannot unfreeze an agent
            log.error("nrvq.cache.agent_flags_failed", error=str(exc), code="NRVQ-DB-9024")
            return True, None

    async def get_eval_and_agent_flags(
        self, namespace: str, agent_class: str, tool_name: str, spiffe_id: str
    ) -> tuple[PolicyDecision | None, bool, float | None]:
        """Collapse the warm path's two Redis stages into ONE pipelined round trip: the cached base decision
        + the fresh freeze + the fresh cap. Returns (decision|None, is_frozen, cap). Fails CLOSED: on any Redis
        error return (None, True, None) — is_frozen=True forces a block downstream (via _apply_trust_overrides),
        so a Redis outage never serves a stale allow or an unfrozen agent."""
        try:
            client = self._client()
            eval_key = self._eval_key(namespace, agent_class, tool_name)
            async with client.pipeline(transaction=False) as pipe:
                await pipe.get(eval_key)
                await pipe.get(f"agent_frozen:{spiffe_id}")
                await pipe.get(f"agent_trust_override:{spiffe_id}")
                eval_raw, frozen_raw, override_raw = await pipe.execute()
            if eval_raw is None:
                record_cache_miss("eval")
                decision = None
            else:
                record_cache_hit("eval")
                decision = PolicyDecision.model_validate_json(eval_raw)
            return decision, bool(frozen_raw), self._parse_override(override_raw)
        except Exception as exc:  # noqa: BLE001 — fail CLOSED (frozen) on any error
            log.error("nrvq.cache.eval_and_flags_failed", error=str(exc), code="NRVQ-DB-9025")
            return None, True, None

    async def invalidate_eval_scope(self, namespace: str, agent_class: str | None = None) -> int:
        """Invalidate cached eval decisions for a namespace/class scope."""
        # Fire the in-proc hook UNCONDITIONALLY (before the early return): the per-pod in-proc eval L1 can
        # still hold an entry for this scope even when the Redis scan finds nothing (Redis TTL'd it, or a
        # race), so the local mirror must be cleared regardless of the Redis key count.
        self._fire_eval_invalidation(namespace, agent_class)
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
        self._fire_eval_invalidation(None, None)  # clear every in-proc eval mirror too
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

    async def publish_audit_record(self, record: dict, origin: str = "") -> None:
        """Fan one live audit record to every OTHER API process.

        The /ws/audit hub is in-process (audit_hub.AuditHub), and the API runs `api.workers: 4` by
        default across `api.replicas: 2` — eight independent processes. A browser's websocket is served
        by ONE of them, and a tool call is evaluated by whichever the load balancer picked, so the live
        Audit Log showed roughly one decision in eight and gave no sign the rest existed. On a product
        whose job is to show what enforcement did, a live view that silently drops most of it is worse
        than not having one.

        Reuses the pub/sub the policy path already relies on for exactly this reason. `origin` is the
        publishing process id so a subscriber can skip its own echo — Redis delivers to every
        subscriber including the publisher, and the publisher has already fanned out locally.
        """
        try:
            await self._client().publish(AUDIT_RECORDS_CHANNEL, json.dumps({"origin": origin, "record": record}))
        except Exception as exc:  # never let the live feed break a decision
            log.warning("nrvq.cache.audit_publish_failed", error=str(exc), code="NRVQ-DB-9036")

    async def listen_audit_records(self, callback) -> None:
        """Subscribe to peer audit records and hand each to `callback(record, origin)`."""
        pubsub = self._pool.pubsub()
        await pubsub.subscribe(AUDIT_RECORDS_CHANNEL)
        log.info("nrvq.cache.audit_records_listening", channel=AUDIT_RECORDS_CHANNEL, code="NRVQ-DB-9037")
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            data = message["data"]
            if isinstance(data, bytes):
                data = data.decode()
            try:
                payload = json.loads(data)
            except Exception as exc:
                # Not silent: anything non-JSON on this channel means a peer is publishing a shape this
                # process does not understand — a version skew worth seeing, not a record to drop quietly.
                log.warning("nrvq.cache.audit_record_undecodable", error=str(exc), code="NRVQ-DB-9038")
                continue
            record = payload.get("record")
            if isinstance(record, dict):
                await callback(record, str(payload.get("origin") or ""))

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
        """Read the current windowed call count WITHOUT incrementing (lockout pre-check)."""
        raw = await self._client().get(f"callcount:{spiffe_id}")
        return int(raw) if raw is not None else 0

    async def reset_call_count(self, spiffe_id: str) -> None:
        """Clear a windowed call counter (a successful login resets its failed-attempt count)."""
        await self._client().delete(f"callcount:{spiffe_id}")

    # Graph ANALYSIS result cache, keyed by (namespace, content-hash version, type, params) so a
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
        """Logout denylist: mark a token hash revoked until the token's own expiry."""
        key = f"revoked:{token_hash}"
        await self._client().setex(key, max(1, int(ttl_s)), "1")
        log.info("nrvq.cache.token.revoked", key=key[:20], ttl=ttl_s, code="NRVQ-DB-9026")

    async def is_token_revoked(self, token_hash: str) -> bool:
        """Logout denylist: True if this token hash was revoked and has not yet expired."""
        return await self._client().get(f"revoked:{token_hash}") is not None

    async def revocation_seed_marker_present(self) -> bool:
        """False once Redis has lost its data since the API last rebuilt the denylist from Postgres.

        The marker has no TTL, so it lives exactly as long as the dataset it vouches for: a Redis that
        restarts without its RDB, fails over to an empty replica, or is flushed comes back without it.
        One GET per process per sync pass — never on a request."""
        return bool(await self._client().exists(REVOCATION_SEED_MARKER))

    async def scan_revoked_tokens(self) -> dict[str, int]:
        """Every live denylist entry as {token_hash: remaining_ttl_s}. Read once when an API process
        boots and again after a data loss — never per request — so one SCAN of the keyspace is
        affordable. What the entries are worth is the caller's call: they are imported as revocations.
        The TTLs are read in pipelined batches: one round trip per key took 1.61s at 10.4k keys."""
        client = self._client()
        keys = [key async for key in client.scan_iter(match="revoked:*", count=1000)]
        found: dict[str, int] = {}
        for i in range(0, len(keys), _REVOKED_BATCH):
            batch = keys[i : i + _REVOKED_BATCH]
            async with client.pipeline(transaction=False) as pipe:
                for key in batch:
                    await pipe.ttl(key)
                ttls = await pipe.execute()
            for key, ttl in zip(batch, ttls):
                if ttl and ttl > 0:  # -2: gone since the SCAN; -1: no TTL, which this module never writes
                    found[key.removeprefix("revoked:")] = int(ttl)
        return found

    async def reseed_revoked_tokens(self, entries: dict[str, int]) -> None:
        """Write {token_hash: ttl_s} back into the denylist and set the marker, in one pipelined round
        trip. Redis is not the durable record any more, but the engine's remote-caller path and a
        rolled-back 0.2.5 replica read nothing else, so a wiped Redis has to be put back for them."""
        await self._write_revoked(entries, marker=True)

    async def revoke_tokens(self, entries: dict[str, int]) -> None:
        """Write {token_hash: ttl_s} into the denylist in one pipelined round trip WITHOUT the marker.
        For the logouts one API process holds that Postgres does not have yet: they vouch for nothing
        but themselves, and the marker means the whole denylist is present."""
        await self._write_revoked(entries, marker=False)

    async def _write_revoked(self, entries: dict[str, int], *, marker: bool) -> None:
        """In batches, so a reseed of the whole denylist is not one unbounded pipeline; the marker goes
        last, after every entry has been written, because it vouches for all of them."""
        client = self._client()
        items = list(entries.items())
        for i in range(0, len(items), _REVOKED_BATCH):
            async with client.pipeline(transaction=False) as pipe:
                for token_hash, ttl_s in items[i : i + _REVOKED_BATCH]:
                    await pipe.set(f"revoked:{token_hash}", "1", ex=max(1, int(ttl_s)))
                await pipe.execute()
        if marker:
            await client.set(REVOCATION_SEED_MARKER, "1")

    async def set_ns_settings(self, namespace: str, fields: dict) -> None:
        """Mirror a namespace's RAW persisted settings override into Redis so the engine
        hot path can resolve per-ns posture without a per-eval DB read (the evaluator holds only this cache, and
        multi-replica correctness needs a shared store). Nulls are preserved — the evaluator does per-field
        fallback to the global config. No TTL; the source of truth stays the DB row (settings_router writes both)."""
        await self._client().set(f"nsconfig:{namespace}", json.dumps(fields))
        log.info("nrvq.cache.ns_settings.set", namespace=namespace, code="NRVQ-DB-9027")

    async def get_ns_settings(self, namespace: str) -> dict | None:
        """The mirrored per-ns settings override, or None if the namespace has none."""
        value = await self._client().get(f"nsconfig:{namespace}")
        return None if value is None else json.loads(value)

    async def set_trust_override(self, spiffe_id: str, score: float) -> None:
        """Durable admin trust CAP for one agent (mirrors the agent_frozen: pattern, no TTL). The
        routine trust:{spiffe} behavioral score is recomputed + clobbered every eval, so a manual pin needs its own
        key. Applied as min(computed, override) — tighten-only, never raises trust above what behavior justifies."""
        await self._client().set(f"agent_trust_override:{spiffe_id}", str(float(score)))

    async def clear_trust_override(self, spiffe_id: str) -> None:
        """Remove the admin trust cap (score cleared / set to 1.0 / frozen)."""
        await self._client().delete(f"agent_trust_override:{spiffe_id}")

    # The owner fence on every admin trust store write (norviq/api/routers/agents.py::update_trust and the boot
    # warm). Each writer claims agent_trust_owner:<id> under the agent's lock, then writes through a script that
    # does nothing unless it still owns the agent. A write that outlives its lock — cut off by a timeout while
    # already on the wire, or from a request whose connection dropped — can then never land over a writer that
    # took over. A missing owner key (a flush, an eviction) fences everyone off: the next claim restores it.
    _OWNER_TTL_MS = 30_000
    FENCE_APPLIED, FENCE_LOST, FENCE_MISSING = 1, 0, -1
    # A write that is not a freeze drops a FROZEN trust:<id> snapshot (the freeze's own display row, or one an
    # evaluation wrote while the agent was frozen). It describes a freeze that is no longer in force; left in place
    # it kept the agent reading frozen, then "unscored", until it expired. Reads then fall back to the registry's
    # last computed score. A write that removes or raises the cap likewise drops a snapshot the OLD cap held down
    # (score within 1e-4 of it, the calculator's rounding): that score was min(computed, old cap), not a score
    # the engine will use again, and after Remove Cap it was shown with no cap beside it until the agent's next
    # call. The registry's copy is marked "Unscored" by the same rule (agents.py::_cap_held_snapshot). Any other
    # snapshot is left alone: it is a score the engine computed.
    _FENCED_CONTROL_LUA = """
local owner = redis.call('GET', KEYS[1])
if not owner then return -1 end
if owner ~= ARGV[1] then return 0 end
local old_cap = tonumber(redis.call('GET', KEYS[3]) or '')
local new_cap = tonumber(ARGV[3])
if ARGV[2] == '1' then redis.call('SET', KEYS[2], '1') else redis.call('DEL', KEYS[2]) end
if ARGV[3] ~= '' then redis.call('SET', KEYS[3], ARGV[3]) else redis.call('DEL', KEYS[3]) end
if ARGV[4] ~= '' then
  redis.call('SET', KEYS[4], ARGV[4], 'EX', ARGV[5])
elseif ARGV[2] ~= '1' then
  local shown = redis.call('GET', KEYS[4])
  if shown and string.find(shown, '"category":"[Ff]rozen"') then
    redis.call('DEL', KEYS[4])
  elseif shown and old_cap and (not new_cap or new_cap > old_cap) then
    local score = tonumber(string.match(shown, '"score":%s*([-%d.eE+]+)'))
    if score and score >= old_cap - 0.0001 then redis.call('DEL', KEYS[4]) end
  end
end
return 1
"""
    # The boot warm's write: ADDS what Postgres holds (a freeze, else a cap) and deletes nothing, fenced the same way.
    _FENCED_WARM_LUA = """
local owner = redis.call('GET', KEYS[1])
if not owner then return -1 end
if owner ~= ARGV[1] then return 0 end
if ARGV[2] == '1' then redis.call('SET', KEYS[2], '1') elseif ARGV[3] ~= '' then redis.call('SET', KEYS[3], ARGV[3]) end
return 1
"""

    # The fence token is MONOTONIC: an admin writer takes it from a Postgres sequence while holding the agent's
    # lock (norviq/api/routers/agents.py::_fence_token), so a later lock holder always has a larger token. A
    # claim only ever raises the owner; a writer whose lock died and whose claim lands late carries the smaller
    # token, is refused, and its fenced write is then a no-op (review round 6: a random token let such a late
    # claim win over a freeze committed with 200 in between). A claim without a token (a freeze stealing the
    # fence while it cannot get the lock) keeps the last lock holder's token and adds a steal count (see
    # _CLAIM_LUA). An owner value this release cannot parse (an older release's) counts as token 0; a non-numeric
    # token (no product writer sends one) is not ordered and replaces the owner, as before.
    # The owner value is "<L>" or "<L>:<S>": L is the last lock-holding writer's sequence token, S counts freezes
    # that stole the fence since. A lock-holding claim (a token) wins iff it is newer than L, or it IS L and nothing
    # stole since; it sets "<token>". A steal (no token) keeps L and bumps S, so the writer it took the fence from
    # is fenced off, while every later lock holder (a larger sequence token) still wins: steals never move the
    # owner ahead of the global sequence, so K steals cannot starve the writers after them (review round 7).
    # Parsing is strict (review round 8): L and S are digit strings, anything else is token 0. Tokens are compared
    # as digit strings (length, then text), never as Lua numbers, so no value loses precision or turns into
    # "inf" or an exponent. S is incremented as a number; it counts steals within one owner TTL and stays tiny.
    _CLAIM_LUA = """
local cur = redis.call('GET', KEYS[1])
local function canon(d)
  d = string.gsub(d, '^0+', '')
  if d == '' then return '0' end
  return d
end
local function older(a, b)
  if #a ~= #b then return #a < #b end
  return a < b
end
local token = ARGV[1]
local last, stolen = '0', 0
if cur then
  local l, s = string.match(cur, '^(%d+):(%d+)$')
  if l and #s <= 9 then
    last, stolen = canon(l), tonumber(s)
  elseif string.match(cur, '^%d+$') then
    last = canon(cur)
  end
end
if token == '' then
  token = last .. ':' .. string.format('%d', stolen + 1)
elseif string.match(token, '^%d+$') then
  local t = canon(token)
  if older(t, last) or (t == last and stolen > 0) then return false end
  token = t
end
redis.call('SET', KEYS[1], token, 'PX', ARGV[2])
return token
"""

    async def claim_admin_trust_owner(
        self, spiffe_id: str, token: int | str | None, ttl_ms: int | None = None
    ) -> str | None:
        """Make ``token`` the agent's admin writer if it is not older than the current one, and return it; None when
        a newer writer owns the agent. ``token`` None steals: it keeps the last lock holder's token and adds one
        to the steal count ("<L>:<S+1>", see _CLAIM_LUA). ``ttl_ms`` (default 30 s) must outlast the writer's
        whole operation, or its own write finds the key gone."""
        result = await self._client().eval(
            self._CLAIM_LUA, 1, f"agent_trust_owner:{spiffe_id}", "" if token is None else str(token),
            str(ttl_ms or self._OWNER_TTL_MS),
        )
        if result is None or result is False:
            return None
        return result.decode() if isinstance(result, bytes) else str(result)

    async def apply_admin_trust_control_if_owner(
        self, spiffe_id: str, token: int | str, *, frozen: bool, cap: float | None, display: TrustScore | None = None
    ) -> int:
        """Write one agent's whole admin control state — freeze flag, cap, and optionally the displayed score —
        atomically, and only while ``token`` owns the agent. Returns FENCE_APPLIED, FENCE_LOST (another writer
        owns it) or FENCE_MISSING (the owner key is gone, so the store's state is unknown). One script, so a
        freeze-to-cap change never has an instant with neither, as separate DEL and SET commands did. A write
        that is not a freeze also drops a frozen ``trust:<id>`` snapshot, and one that removes or raises the cap
        drops a snapshot the old cap held down (see _FENCED_CONTROL_LUA)."""
        keys = [f"agent_trust_owner:{spiffe_id}", f"agent_frozen:{spiffe_id}", f"agent_trust_override:{spiffe_id}",
                f"trust:{spiffe_id}"]
        args = [str(token), "1" if frozen else "0", "" if cap is None else str(float(cap)),
                "" if display is None else display.model_dump_json(),
                str(self._jitter_ttl(settings.redis_ttl_trust_s))]
        return int(await self._client().eval(self._FENCED_CONTROL_LUA, len(keys), *keys, *args))

    async def warm_admin_trust_controls(
        self, token: int | str, entries: list[tuple[str, bool, float | None]], rounds: int = 3
    ) -> list[int]:
        """The boot warm's batch: claim every agent for ``token``, then add each agent's freeze or cap through the
        fence, in two pipelines. A cut-off attempt's late writes are no-ops once an admin write re-claims.

        The caller holds the batch's Postgres locks, so no LIVE admin writer can own these agents: a lost or
        missing fence here is a dead writer's late claim (a SET cut off on the wire that landed after the warm's
        claim). Those agents are re-claimed and re-added, up to ``rounds`` times (a freeze steal since the warm's
        claim keeps the warm fenced off: the agent reports lost and the caller retries it with a newer token); the outcomes returned are the last ones, so the caller can see any
        agent that still did not take its control."""
        client = self._client()
        outcomes = [self.FENCE_LOST] * len(entries)
        for _ in range(rounds):
            pending = [i for i, outcome in enumerate(outcomes) if outcome != self.FENCE_APPLIED]
            if not pending:
                break
            async with client.pipeline(transaction=False) as pipe:
                for i in pending:
                    await pipe.eval(self._CLAIM_LUA, 1, f"agent_trust_owner:{entries[i][0]}", str(token),
                                    str(self._OWNER_TTL_MS))
                await pipe.execute()
            async with client.pipeline(transaction=False) as pipe:
                for i in pending:
                    spiffe_id, frozen, cap = entries[i]
                    keys = [f"agent_trust_owner:{spiffe_id}", f"agent_frozen:{spiffe_id}",
                            f"agent_trust_override:{spiffe_id}"]
                    await pipe.eval(self._FENCED_WARM_LUA, 3, *keys, str(token), "1" if frozen else "0",
                                    "" if cap is None else str(float(cap)))
                for i, result in zip(pending, await pipe.execute()):
                    outcomes[i] = int(result)
        return outcomes
