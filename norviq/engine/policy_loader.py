# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policy loader with in-memory and Redis-backed lifecycle management."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import uuid
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from norviq.config import settings
from norviq.engine.cache import RedisCache
from norviq.engine.evaluator import OPAEvaluator
from norviq.exceptions import NorviqError

log = structlog.get_logger()

_MAX_VERSIONS = int(getattr(settings, "policy_max_versions", 10))


@dataclass(slots=True)
class PolicyVersion:
    """Policy snapshot at a specific version."""

    version: int
    rego_source: str
    priority: int = 100
    saved_by: str = ""
    saved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyLoader:
    """Load and mutate policy versions with copy-on-write maps."""
    # pubsub invalidation_listener is consumed by sidecar policy watcher.

    def __init__(self, cache: RedisCache, evaluator: OPAEvaluator) -> None:
        """Store dependencies and initialize local state."""
        self._cache = cache
        self._evaluator = evaluator
        self._policies: dict[str, dict] = {}
        self._versions: dict[str, list[PolicyVersion]] = {}
        self._db: AsyncEngine | None = None
        # F-04: True once the startup warm load completes. Lets the evaluator distinguish a genuine
        # "no policy for this namespace" (deny) from "policies not yet loaded" (distinctly-alarmed deny).
        self._warmed: bool = False
        if hasattr(self._evaluator, "bind_loader"):
            self._evaluator.bind_loader(self)

    def _key(self, namespace: str, agent_class: str) -> str:
        """Build namespace and class compound key."""
        return f"{namespace}:{agent_class}"

    def _db_url(self) -> str:
        """Return SQLAlchemy-compatible asyncpg URL."""
        raw = settings.pg_url.strip().strip("\"'").replace("postgresql://", "postgresql+asyncpg://")
        split = urlsplit(raw)
        filtered = [(k, v) for k, v in parse_qsl(split.query, keep_blank_values=True) if k.lower() not in {"ssl", "sslmode"}]
        return urlunsplit((split.scheme, split.netloc, split.path, urlencode(filtered), split.fragment))

    def _build_connect_args(self) -> dict:
        """Build asyncpg connect args from settings."""
        pg_query = dict(parse_qsl(urlsplit(settings.pg_url).query, keep_blank_values=True))
        ssl_mode = str(
            pg_query.get("sslmode")
            or pg_query.get("ssl")
            or getattr(settings, "db_ssl_mode", "prefer")
        ).lower()
        if ssl_mode in {"disable", "false", "0"}:
            ssl = False
        elif ssl_mode in {"require", "verify-ca", "verify-full"}:
            ssl = ssl_mode
        else:
            ssl = "prefer"
        return {"command_timeout": settings.db_command_timeout, "ssl": ssl}

    def _db_engine(self) -> AsyncEngine:
        """Lazily initialize DB engine for policy hydration."""
        if self._db is None:
            self._db = create_async_engine(
                self._db_url(),
                pool_size=settings.pg_pool_size,
                max_overflow=settings.db_pool_max_overflow,
                pool_timeout=settings.db_pool_timeout,
                connect_args=self._build_connect_args(),
            )
        return self._db

    async def load(self, namespace: str, agent_class: str) -> str | None:
        """Load policy from memory first, then Redis."""
        key = self._key(namespace, agent_class)
        entry = self._policies.get(key)
        if entry is not None:
            log.debug("nrvq.policy.memory_hit", key=key, code="NRVQ-REG-5001")
            return str(entry["rego"])
        cached = await self._cache.get_policy_entry(namespace, agent_class)
        if cached is not None:
            self._update_memory(key, str(cached.get("rego", "")), int(cached.get("priority", 100)))
            log.debug("nrvq.policy.cache_hit", key=key, code="NRVQ-REG-5002")
            return str(cached.get("rego", ""))
        log.warning("nrvq.policy.not_found", key=key, code="NRVQ-REG-5000")
        return None

    async def create(
        self,
        namespace: str,
        agent_class: str,
        rego_source: str,
        saved_by: str = "",
        priority: int = 100,
        enforcement_mode: str = "block",
        policy_name: str | None = None,
    ) -> int:
        """Create or update a policy and return new version."""
        key = self._key(namespace, agent_class)
        policy_id = str(uuid.uuid4())
        version_row_id = str(uuid.uuid4())
        upsert_policy = text(
            """
            INSERT INTO policies (
                id, name, namespace, agent_class, rego_source, version, enforcement_mode, priority, created_at
            )
            VALUES (
                :id, :name, :namespace, :agent_class, :rego_source, 1, :enforcement_mode, :priority, NOW()
            )
            ON CONFLICT (namespace, agent_class) DO UPDATE SET
                rego_source = EXCLUDED.rego_source,
                version = policies.version + 1,
                priority = EXCLUDED.priority,
                enforcement_mode = EXCLUDED.enforcement_mode,
                created_at = NOW()
            RETURNING id, version
            """
        )
        insert_version = text(
            """
            INSERT INTO policy_versions (id, policy_id, version, rego_source, saved_at, saved_by)
            VALUES (:id, :policy_id, :version, :rego_source, NOW(), :saved_by)
            """
        )
        async with self._db_engine().begin() as conn:
            row = (
                await conn.execute(
                    upsert_policy,
                    {
                        "id": policy_id,
                        "name": policy_name or agent_class,
                        "namespace": namespace,
                        "agent_class": agent_class,
                        "rego_source": rego_source,
                        "enforcement_mode": enforcement_mode,
                        "priority": int(priority),
                    },
                )
            ).mappings().one()
            new_version = int(row["version"])
            await conn.execute(
                insert_version,
                {
                    "id": version_row_id,
                    "policy_id": row["id"],
                    "version": new_version,
                    "rego_source": rego_source,
                    "saved_by": saved_by,
                },
            )

        history = self._versions.get(key, [])
        snapshot = PolicyVersion(version=new_version, rego_source=rego_source, priority=priority, saved_by=saved_by)
        self._versions = {**self._versions, key: [*history, snapshot][-_MAX_VERSIONS:]}
        self._update_memory(key, rego_source, priority)
        # delete policy: clear prior policy cache value so updates are atomic for readers.
        await self._cache.delete_policy(namespace, agent_class)
        await self._cache.set_policy(namespace, agent_class, rego_source, priority=priority, version=new_version)
        # NEW: Invalidate Redis caches for this policy scope.
        pool = getattr(self._cache, "_pool", None)
        if pool is not None:
            await pool.delete(f"policy:{key}")
        await self._invalidate_eval_for_policy_scope(namespace, agent_class)
        if pool is not None:
            await pool.publish("norviq:policy:invalidated", key)
        log.info("nrvq.policy.cache_invalidated", key=key, code="NRVQ-REG-5010")
        await self._cache.publish_policy_event("upsert", namespace, agent_class, version=new_version)
        self._evaluator.load_policy(namespace, agent_class, rego_source, priority=priority)
        log.info("nrvq.policy.created", key=key, version=new_version, priority=priority, code="NRVQ-REG-5003")
        return new_version

    async def rollback(self, namespace: str, agent_class: str, target_version: int) -> str:
        """Rollback to a previous version and return its source."""
        key = self._key(namespace, agent_class)
        target = next((item for item in self._versions.get(key, []) if item.version == target_version), None)
        if target is None:
            log.error("nrvq.policy.rollback_not_found", key=key, version=target_version, code="NRVQ-REG-5004")
            raise NorviqError(f"Version {target_version} not found for {key}", code="NRVQ-REG-5004")
        new_version = await self.create(
            namespace,
            agent_class,
            target.rego_source,
            saved_by=f"rollback_to_v{target_version}",
            priority=target.priority,
        )
        log.info(
            "nrvq.policy.rolled_back",
            key=key,
            from_version=target_version,
            to_version=new_version,
            code="NRVQ-REG-5005",
        )
        return target.rego_source

    def get_versions(self, namespace: str, agent_class: str) -> list[PolicyVersion]:
        """Return version history copy for one policy key."""
        return list(self._versions.get(self._key(namespace, agent_class), []))

    def get_current(self, namespace: str, agent_class: str) -> str | None:
        """Return current policy source from memory."""
        entry = self._policies.get(self._key(namespace, agent_class))
        if entry is None:
            return None
        return str(entry["rego"])

    def get_entry(self, namespace: str, agent_class: str) -> dict | None:
        """Return current in-memory policy entry including priority."""
        return self._policies.get(self._key(namespace, agent_class))

    async def delete(self, namespace: str, agent_class: str) -> bool:
        """Delete a policy from EVERY layer so it cannot be resurrected. F-52: previously this only cleared the
        in-memory loader dict + the Redis policy cache, leaving the Postgres row (rehydrated on restart) AND the
        evaluator's in-memory copy (kept enforcing) AND a possibly-stale eval-result cache. Now it removes all
        four: Postgres rows, evaluator index, loader dict, Redis policy + eval caches."""
        key = self._key(namespace, agent_class)
        # Absent from the in-memory index -> nothing to delete (warm_cache rehydrates every stored policy into
        # _policies on startup, so a key the spoke actually holds is present here; this also keeps a delete of a
        # non-existent policy a clean 404 without a DB round-trip).
        if key not in self._policies:
            return False
        self._policies = {k: v for k, v in self._policies.items() if k != key}
        self._versions = {k: v for k, v in self._versions.items() if k != key}
        # Postgres: drop the policy + its version history (so warm_cache on restart can't bring it back).
        async with self._db_engine().begin() as conn:
            await conn.execute(
                text("DELETE FROM policy_versions WHERE policy_id IN "
                     "(SELECT id FROM policies WHERE namespace = :ns AND agent_class = :ac)"),
                {"ns": namespace, "ac": agent_class},
            )
            await conn.execute(
                text("DELETE FROM policies WHERE namespace = :ns AND agent_class = :ac"),
                {"ns": namespace, "ac": agent_class},
            )
        # Evaluator in-memory index (the counterpart to load_policy on create).
        if hasattr(self._evaluator, "unload_policy"):
            self._evaluator.unload_policy(namespace, agent_class)
        await self._cache.delete_policy(namespace, agent_class)
        await self._invalidate_eval_for_policy_scope(namespace, agent_class)  # clear stale eval-result cache
        await self._cache.publish_policy_event("delete", namespace, agent_class, version=0)
        log.info("nrvq.policy.deleted", key=key, code="NRVQ-REG-5007")
        return True

    async def reload_all(self) -> int:
        """Reload current in-memory policies into evaluator."""
        count = 0
        for key, entry in self._policies.items():
            namespace, agent_class = key.split(":", 1)
            self._evaluator.load_policy(namespace, agent_class, str(entry["rego"]), priority=int(entry.get("priority", 100)))
            count += 1
        log.info("nrvq.policy.reload_all", count=count, code="NRVQ-REG-5006")
        return count

    async def load_all_from_redis(self) -> int:
        """Hydrate in-memory/evaluator state from cached policy keys."""
        entries = await self._cache.list_policy_entries()
        count = 0
        for key, entry in entries.items():
            if not key.startswith("policy:"):
                continue
            parts = key.split(":", 2)
            if len(parts) != 3:
                continue
            namespace, agent_class = parts[1], parts[2]
            rego = str(entry.get("rego", ""))
            priority = int(entry.get("priority", 100))
            self._update_memory(self._key(namespace, agent_class), rego, priority)
            self._evaluator.load_policy(namespace, agent_class, rego, priority=priority)
            count += 1
        log.info("nrvq.policy.hydrated", count=count, code="NRVQ-REG-5008")
        return count

    async def load_from_db(self, namespace: str, agent_class: str) -> dict | None:
        """Load a policy from PostgreSQL into in-memory cache."""
        key = self._key(namespace, agent_class)
        query = text(
            """
            SELECT rego_source, priority
            FROM policies
            WHERE namespace = :namespace AND agent_class = :agent_class
            ORDER BY version DESC
            LIMIT 1
            """
        )
        async with self._db_engine().begin() as conn:
            row = (await conn.execute(query, {"namespace": namespace, "agent_class": agent_class})).mappings().first()
        if not row:
            return None
        entry = {"rego": str(row["rego_source"]), "priority": int(row["priority"] or 100)}
        self._policies = {**self._policies, key: entry}
        if hasattr(self._evaluator, "reload_policy"):
            self._evaluator.reload_policy(namespace, agent_class, entry["rego"])
        log.info("nrvq.policy.lazy_loaded", key=key, code="NRVQ-REG-5014")
        return entry

    async def warm_cache(self) -> None:
        """Load latest policies from DB into memory on startup."""
        query = text(
            """
            SELECT namespace, agent_class, rego_source, priority
            FROM policies
            ORDER BY namespace, agent_class, version DESC
            """
        )
        async with self._db_engine().begin() as conn:
            rows = (await conn.execute(query)).mappings().all()
        policies: dict[str, dict] = {}
        for row in rows:
            key = self._key(str(row["namespace"]), str(row["agent_class"]))
            if key in policies:
                continue
            entry = {"rego": str(row["rego_source"]), "priority": int(row["priority"] or 100)}
            policies[key] = entry
            if hasattr(self._evaluator, "reload_policy"):
                self._evaluator.reload_policy(str(row["namespace"]), str(row["agent_class"]), entry["rego"])
        self._policies = {**self._policies, **policies}
        self._warmed = True  # F-04: warm load done -> the no-policy path is now "genuine", not "not-ready".
        log.info("nrvq.policy.cache_warmed", count=len(policies), code="NRVQ-REG-5015")

    def _update_memory(self, key: str, rego_source: str, priority: int) -> None:
        """Update memory map via copy-on-write swap."""
        self._policies = {**self._policies, key: {"rego": rego_source, "priority": int(priority)}}

    async def _invalidate_eval_for_policy_scope(self, namespace: str, agent_class: str) -> None:
        """Delete all cached evaluation results for a policy scope."""
        pattern = f"eval:{namespace}:{agent_class}:*"
        pool = getattr(self._cache, "_pool", None)
        if pool is None:
            await self._cache.invalidate_eval_scope(namespace, agent_class)
            log.debug("nrvq.policy.eval_cache_cleared", namespace=namespace, agent_class=agent_class, code="NRVQ-REG-5011")
            return
        cursor = 0
        while True:
            cursor, keys = await pool.scan(cursor, match=pattern, count=100)
            if keys:
                await pool.delete(*keys)
            if cursor == 0:
                break
        log.debug("nrvq.policy.eval_cache_cleared", namespace=namespace, agent_class=agent_class, code="NRVQ-REG-5011")

    async def _reload_policy(self, namespace: str, agent_class: str) -> None:
        """Reload a single policy from cache or DB into memory."""
        key = f"{namespace}:{agent_class}"

        cached = await self._cache.get_policy_entry(namespace, agent_class)
        if cached:
            rego = cached if isinstance(cached, str) else cached.get("rego", "")
            priority = cached.get("priority", 100) if isinstance(cached, dict) else 100
        else:
            log.debug("nrvq.policy.reload_cache_miss", key=key, code="NRVQ-REG-5012")
            return

        new_policies = dict(self._policies)
        new_policies[key] = {"rego": rego, "priority": priority}
        self._policies = new_policies

        if hasattr(self, "_evaluator") and self._evaluator:
            self._evaluator.reload_policy(namespace, agent_class, rego)

        log.info("nrvq.policy.reloaded", key=key, code="NRVQ-REG-5013")

    @property
    def policy_count(self) -> int:
        """Return count of in-memory policies."""
        return len(self._policies)

    async def close(self) -> None:
        """Dispose database resources."""
        if self._db is not None:
            await self._db.dispose()
            self._db = None
