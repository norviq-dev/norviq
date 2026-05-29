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
    saved_by: str = ""
    saved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyLoader:
    """Load and mutate policy versions with copy-on-write maps."""

    def __init__(self, cache: RedisCache, evaluator: OPAEvaluator) -> None:
        """Store dependencies and initialize local state."""
        self._cache = cache
        self._evaluator = evaluator
        self._policies: dict[str, str] = {}
        self._versions: dict[str, list[PolicyVersion]] = {}

    def _key(self, namespace: str, agent_class: str) -> str:
        """Build namespace and class compound key."""
        return f"{namespace}:{agent_class}"

    async def load(self, namespace: str, agent_class: str) -> str | None:
        """Load policy from memory first, then Redis."""
        key = self._key(namespace, agent_class)
        policy = self._policies.get(key)
        if policy is not None:
            log.debug("nrvq.policy.memory_hit", key=key, code="NRVQ-REG-5001")
            return policy
        cached = await self._cache.get_policy(namespace, agent_class)
        if cached is not None:
            self._update_memory(key, cached)
            log.debug("nrvq.policy.cache_hit", key=key, code="NRVQ-REG-5002")
            return cached
        log.warning("nrvq.policy.not_found", key=key, code="NRVQ-REG-5000")
        return None

    async def create(self, namespace: str, agent_class: str, rego_source: str, saved_by: str = "") -> int:
        """Create or update a policy and return new version."""
        key = self._key(namespace, agent_class)
        history = self._versions.get(key, [])
        new_version = (history[-1].version + 1) if history else 1
        snapshot = PolicyVersion(version=new_version, rego_source=rego_source, saved_by=saved_by)
        self._versions = {**self._versions, key: [*history, snapshot][-_MAX_VERSIONS:]}
        self._update_memory(key, rego_source)
        await self._cache.set_policy(namespace, agent_class, rego_source)
        self._evaluator.load_policy(namespace, agent_class, rego_source)
        log.info("nrvq.policy.created", key=key, version=new_version, code="NRVQ-REG-5003")
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
        return self._policies.get(self._key(namespace, agent_class))

    async def reload_all(self) -> int:
        """Reload current in-memory policies into evaluator."""
        count = 0
        for key, rego in self._policies.items():
            namespace, agent_class = key.split(":", 1)
            self._evaluator.load_policy(namespace, agent_class, rego)
            count += 1
        log.info("nrvq.policy.reload_all", count=count, code="NRVQ-REG-5006")
        return count

    def _update_memory(self, key: str, rego_source: str) -> None:
        """Update memory map via copy-on-write swap."""
        self._policies = {**self._policies, key: rego_source}

    @property
    def policy_count(self) -> int:
        """Return count of in-memory policies."""
        return len(self._policies)
