# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policy loader with in-memory and Redis-backed lifecycle management."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

import structlog

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
        if hasattr(self._evaluator, "bind_loader"):
            self._evaluator.bind_loader(self)

    def _key(self, namespace: str, agent_class: str) -> str:
        """Build namespace and class compound key."""
        return f"{namespace}:{agent_class}"

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
    ) -> int:
        """Create or update a policy and return new version."""
        key = self._key(namespace, agent_class)
        history = self._versions.get(key, [])
        new_version = (history[-1].version + 1) if history else 1
        snapshot = PolicyVersion(version=new_version, rego_source=rego_source, priority=priority, saved_by=saved_by)
        self._versions = {**self._versions, key: [*history, snapshot][-_MAX_VERSIONS:]}
        self._update_memory(key, rego_source, priority)
        # delete policy: clear prior policy cache value so updates are atomic for readers.
        await self._cache.delete_policy(namespace, agent_class)
        await self._cache.set_policy(namespace, agent_class, rego_source, priority=priority, version=new_version)
        # eval: invalidate stale decisions for this policy scope.
        await self._invalidate_eval_for_policy_scope(namespace, agent_class)
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
        """Delete policy from memory, versions, and cache."""
        key = self._key(namespace, agent_class)
        if key not in self._policies:
            return False
        self._policies = {k: v for k, v in self._policies.items() if k != key}
        self._versions = {k: v for k, v in self._versions.items() if k != key}
        await self._cache.delete_policy(namespace, agent_class)
        await self._invalidate_eval_for_policy_scope(namespace, agent_class)
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

    def _update_memory(self, key: str, rego_source: str, priority: int) -> None:
        """Update memory map via copy-on-write swap."""
        self._policies = {**self._policies, key: {"rego": rego_source, "priority": int(priority)}}

    async def _invalidate_eval_for_policy_scope(self, namespace: str, agent_class: str) -> None:
        """Invalidate cached decisions for the effective policy scope."""
        if namespace == "__cluster__" and agent_class == "__baseline__":
            await self._cache.invalidate_all_eval()
            return
        if agent_class == "__baseline__":
            await self._cache.invalidate_eval_scope(namespace)
            return
        await self._cache.invalidate_eval_scope(namespace, agent_class)

    @property
    def policy_count(self) -> int:
        """Return count of in-memory policies."""
        return len(self._policies)
