# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policy loader with in-memory and Redis-backed lifecycle management."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
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
# COMP-GEN-02: the per-class compliance-remediation overlay key suffix; its eval results cache under the base class.
_REMEDIATION_SUFFIX = "__remediation__"


@dataclass(slots=True)
class PolicyVersion:
    """Policy snapshot at a specific version."""

    version: int
    rego_source: str
    priority: int = 100
    enforcement_mode: str = "block"
    saved_by: str = ""
    saved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyLoader:
    """Load and mutate policy versions with copy-on-write maps."""
    # pubsub invalidation_listener is consumed by sidecar policy watcher.

    def __init__(self, cache: RedisCache, evaluator: OPAEvaluator) -> None:
        """Store dependencies and initialize local state."""
        self._cache = cache
        self._evaluator = evaluator
        # HA: a per-PROCESS id stamped on every policy event this replica publishes, so the cross-replica
        # sync listener can skip its OWN echoes (Redis pub/sub broadcasts to all subscribers incl. self).
        self._origin = uuid.uuid4().hex
        self._policies: dict[str, dict] = {}
        self._versions: dict[str, list[PolicyVersion]] = {}
        # C1: when a (ns, class) policy was last APPLIED to the cluster (distinct from when it was last SAVED).
        # An apply re-stamps this even when the rego is unchanged, so the Catalog card always reflects the action.
        self._applied_at: dict[str, datetime] = {}
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

    async def scope_exists(self, namespace: str, agent_class: str) -> bool:
        """M2: whether (namespace, agent_class) already has a persisted policy row — DB-authoritative (same
        source of truth `delete()`'s H2 fix uses), so this holds across HA replicas even when a scope was
        created by a peer this replica has not warmed into memory. Lets a caller distinguish a NEW scope
        (counts against the per-namespace scope cap, see `count_namespace_scopes`) from an UPDATE to an
        existing scope (exempt — it does not grow the count)."""
        async with self._db_engine().begin() as conn:
            row = (await conn.execute(
                text("SELECT 1 FROM policies WHERE namespace = :ns AND agent_class = :ac LIMIT 1"),
                {"ns": namespace, "ac": agent_class},
            )).first()
        return row is not None

    async def count_namespace_scopes(self, namespace: str) -> int:
        """M2: count of DISTINCT (namespace, agent_class) policy scopes currently persisted for `namespace`.
        DB-authoritative for the same HA reason as `scope_exists`. Backs the per-namespace hard cap on the
        number of distinct scopes a namespace may hold — mirrors the existing `draft_cap_per_namespace`
        retention pattern (`norviq/api/retention.py`), but for the policy catalog rather than drafts: the
        version history is already pruned (`prune_versions`) and drafts are capped, yet nothing previously
        bounded the COUNT of distinct scopes a write-capable credential could create, each held forever in
        memory + OPA + the DB."""
        async with self._db_engine().begin() as conn:
            row = (await conn.execute(
                text("SELECT COUNT(*) AS n FROM policies WHERE namespace = :ns"),
                {"ns": namespace},
            )).mappings().one()
        return int(row["n"])

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
        # C1/HA: `applied_at` is stamped here with the DB's own NOW() (never a Python-side `datetime.now()`,
        # which would differ per replica) and RETURNED so this replica's in-memory `_applied_at` is hydrated
        # from the SAME value every other replica will read back on their own upsert/warm reload — a create()
        # always loads the rego into the evaluator (genuinely (re)applies it), so it always re-stamps.
        upsert_policy = text(
            """
            INSERT INTO policies (
                id, name, namespace, agent_class, rego_source, version, enforcement_mode, priority, created_at, applied_at
            )
            VALUES (
                :id, :name, :namespace, :agent_class, :rego_source, 1, :enforcement_mode, :priority, NOW(), NOW()
            )
            ON CONFLICT (namespace, agent_class) DO UPDATE SET
                rego_source = EXCLUDED.rego_source,
                version = policies.version + 1,
                priority = EXCLUDED.priority,
                enforcement_mode = EXCLUDED.enforcement_mode,
                created_at = NOW(),
                applied_at = NOW()
            RETURNING id, version, applied_at
            """
        )
        insert_version = text(
            """
            INSERT INTO policy_versions (id, policy_id, version, rego_source, saved_at, saved_by, priority, enforcement_mode)
            VALUES (:id, :policy_id, :version, :rego_source, NOW(), :saved_by, :priority, :enforcement_mode)
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
            applied_at_db = row["applied_at"]
            await conn.execute(
                insert_version,
                {
                    "id": version_row_id,
                    "policy_id": row["id"],
                    "version": new_version,
                    "rego_source": rego_source,
                    "saved_by": saved_by,
                    "priority": int(priority),
                    "enforcement_mode": enforcement_mode,
                },
            )

        history = self._versions.get(key, [])
        snapshot = PolicyVersion(version=new_version, rego_source=rego_source, priority=priority,
                                 enforcement_mode=enforcement_mode, saved_by=saved_by)
        self._versions = {**self._versions, key: [*history, snapshot][-_MAX_VERSIONS:]}
        self._update_memory(key, rego_source, priority, enforcement_mode)
        # C1/HA: hydrate THIS replica's in-memory applied_at from the value Postgres just returned — the
        # single authoritative timestamp every replica (via load_from_db/warm_cache/apply_remote_event) and a
        # restart will converge on, rather than a locally-computed datetime.now() that could drift per replica.
        self.mark_applied(namespace, agent_class, when=applied_at_db)
        # delete policy: clear prior policy cache value so updates are atomic for readers.
        await self._cache.delete_policy(namespace, agent_class)
        await self._cache.set_policy(namespace, agent_class, rego_source, priority=priority, version=new_version)
        # Invalidate Redis caches for this policy scope. The authoritative policy-mirror delete already
        # happened via delete_policy() above (line ~216), which uses the cache's hashed key — a direct
        # unhashed `pool.delete(f"policy:{key}")` here would target a key that no longer exists (cache.py
        # now hashes policy-key segments) and, pre-hashing, would have wrongly deleted the value set_policy
        # just wrote. Only the eval-cache scope invalidation + the peer-invalidation publish remain.
        pool = getattr(self._cache, "_pool", None)
        await self._invalidate_eval_for_policy_scope(namespace, agent_class)
        if pool is not None:
            await pool.publish("norviq:policy:invalidated", key)
        log.info("nrvq.policy.cache_invalidated", key=key, code="NRVQ-REG-5010")
        await self._cache.publish_policy_event("upsert", namespace, agent_class, version=new_version, origin=self._origin)
        self._evaluator.load_policy(namespace, agent_class, rego_source, priority=priority)
        log.info("nrvq.policy.created", key=key, version=new_version, priority=priority, code="NRVQ-REG-5003")
        await self.prune_versions(namespace, agent_class)  # Part B (B5): bound version history (never the current)
        return new_version

    async def prune_versions(self, namespace: str, agent_class: str) -> int:
        """Part B (B5): keep the version history bounded — a version is KEPT if it is the current-enforcing
        version, OR within the last ``policy_version_keep_count``, OR saved within ``policy_version_keep_days``;
        everything else is pruned from ``policy_versions``.

        SAFETY INVARIANT (gated + tested): the current-enforcing version (``policies.version``) is NEVER pruned —
        the ``version <> current`` guard makes it impossible to drop the version backing the enforcing state.
        Best-effort: a prune failure never affects the save/enforcement."""
        keep_count = int(settings.policy_version_keep_count)
        keep_days = int(settings.policy_version_keep_days)
        cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
        try:
            async with self._db_engine().begin() as conn:
                row = (await conn.execute(
                    text("SELECT id, version FROM policies WHERE namespace = :ns AND agent_class = :cls"),
                    {"ns": namespace, "cls": agent_class},
                )).mappings().first()
                if row is None:
                    return 0
                pid, current_version = row["id"], int(row["version"])
                result = await conn.execute(
                    text(
                        "DELETE FROM policy_versions WHERE policy_id = :pid "
                        "AND version <> :current "                       # NEVER the current-enforcing version
                        "AND saved_at < :cutoff "                        # keep anything within the day-window
                        "AND version NOT IN ("                           # keep the last N by version
                        "  SELECT version FROM policy_versions WHERE policy_id = :pid ORDER BY version DESC LIMIT :keep"
                        ")"
                    ),
                    {"pid": pid, "current": current_version, "cutoff": cutoff, "keep": keep_count},
                )
            pruned = int(result.rowcount or 0)
            if pruned:
                log.info("nrvq.policy.versions_pruned", key=self._key(namespace, agent_class), pruned=pruned,
                         kept_current=current_version, code="NRVQ-REG-5013")
            return pruned
        except Exception as exc:  # noqa: BLE001 — pruning is best-effort; never fail a save
            log.warning("nrvq.policy.version_prune_failed", error=str(exc), code="NRVQ-REG-5014")
            return 0

    async def apply_to_target(
        self,
        source_namespace: str,
        source_agent_class: str,
        target_namespace: str,
        target_agent_class: str,
        *,
        saved_by: str = "",
        enforcement_mode: str = "block",
    ) -> tuple[int, bool] | None:
        """Part C: apply a SAVED policy to a target scope so it ACTUALLY enforces on this cluster.

        The old apply path called ``self._evaluator.load_policy(...)`` — but the evaluator resolves policy
        CONTENT from ``self._policies`` (the loader's map, read by ``_collect_candidates``), NOT the evaluator's
        own ``_policies`` dict. So apply wrote a dict nobody reads and never persisted/loaded the target: a 200
        that did not enforce (``/evaluate`` at the target stayed ``no_policy_loaded``). This routes apply through
        the SAME read-path + persistence + cache-invalidation that ``create()`` uses, so apply-from-portal
        deterministically enforces at the target.

        Returns ``(version_now_enforcing_at_target, created_new_version)`` or ``None`` if the source has no
        current policy (caller raises 404). Idempotent: if the target already enforces byte-identical rego it
        re-affirms the read path + invalidates the eval cache WITHOUT a version bump (preserves the
        no-version-inflation-on-re-apply invariant that the same-namespace UI flow relies on).
        """
        src = self.get_entry(source_namespace, source_agent_class)
        if src is None:
            return None
        rego = str(src["rego"])
        priority = int(src.get("priority", 100))
        target_key = self._key(target_namespace, target_agent_class)

        if self.get_current(target_namespace, target_agent_class) == rego:
            # Already the enforcing content at the target — make sure it is in the read path + the eval cache is
            # fresh (defensive: clears any stale cached decision), but do NOT create a new version. If the CALLER
            # asked for a different enforcement_mode than what's persisted (the editor "Enforcement -> audit"
            # case, rego byte-identical), PERSIST the new mode — without a version bump, the rego is unchanged —
            # instead of silently discarding it and re-deriving the OLD mode. A true reaffirm (mode unchanged)
            # stays a no-op.
            existing_target = self.get_entry(target_namespace, target_agent_class)
            existing_mode = str((existing_target or {}).get("enforcement_mode", enforcement_mode))
            mode_changed = enforcement_mode != existing_mode
            effective_mode = enforcement_mode if mode_changed else existing_mode
            # M1 (apply_to_target variant): current_version must be the LATEST version's real number, not
            # the count of retained versions — pruned history (cap 10 / 90d) means len() != the real version,
            # which understated it once a class passed 10 lifetime versions. That wrong number flowed into
            # apply_policy's response -> UI expectedVersion, which the verify-poll compares against
            # list_policies' CORRECT versions[-1].version, so it could never converge -> permanent false
            # "STALLED". Compute once from the real version history and reuse for the mode-change publish too.
            versions = self.get_versions(target_namespace, target_agent_class)
            current_version = versions[-1].version if versions else 1
            applied_at_db: datetime | None = None
            if mode_changed:
                async with self._db_engine().begin() as conn:
                    # C1/HA: a mode-only reapply is a genuine (re)apply of this scope even though the rego
                    # is byte-identical — stamp applied_at with the DB's own NOW() (RETURNING it) so this
                    # replica and every peer (via load_from_db/warm_cache/apply_remote_event) converge on the
                    # same value, same as create()'s stamp.
                    row = (await conn.execute(
                        text(
                            "UPDATE policies SET enforcement_mode = :mode, applied_at = NOW() "
                            "WHERE namespace = :ns AND agent_class = :ac "
                            "RETURNING applied_at"
                        ),
                        {"mode": enforcement_mode, "ns": target_namespace, "ac": target_agent_class},
                    )).mappings().one()
                    applied_at_db = row["applied_at"]
                    # FIX-5 (prerequisite): also patch the CURRENT version's row in `policy_versions` — the
                    # in-memory patch below only fixes THIS replica's `_versions`. Without this DB write, a
                    # peer replica's `_rehydrate_versions_for_key` (apply_remote_event's upsert branch) would
                    # re-read the STALE mode from Postgres and there would be no durable source of truth to
                    # recover from at all (a peer restart would resurrect the stale mode too).
                    await conn.execute(
                        text(
                            "UPDATE policy_versions SET enforcement_mode = :mode "
                            "WHERE version = :version AND policy_id = ("
                            "  SELECT id FROM policies WHERE namespace = :ns AND agent_class = :ac"
                            ")"
                        ),
                        {"mode": enforcement_mode, "version": current_version,
                         "ns": target_namespace, "ac": target_agent_class},
                    )
                # Patch the most-recent version snapshot too, so a later rollback-to-current doesn't
                # resurrect the stale mode (rollback restores the target version's own stored mode).
                history = self._versions.get(target_key)
                if history:
                    history[-1].enforcement_mode = enforcement_mode
                log.info("nrvq.policy.mode_updated", key=target_key, mode=enforcement_mode, code="NRVQ-REG-5019")
            # C1/HA: re-stamp applied_at on every reaffirm so the Catalog card visibly updates even when
            # nothing enforcement-relevant changed. When the mode WAS persisted above, hydrate from that exact
            # DB value so this replica and every peer converge; a true no-op (rego AND mode unchanged) has
            # nothing new to persist, so this stays the pre-existing in-memory-only fast path (unconverged,
            # same as before this fix — there is no new authoritative value for a peer to read back).
            self.mark_applied(target_namespace, target_agent_class, when=applied_at_db)
            self._update_memory(target_key, rego, priority, effective_mode)
            await self._invalidate_eval_for_policy_scope(target_namespace, target_agent_class)
            pool = getattr(self._cache, "_pool", None)
            if pool is not None:
                await pool.publish("norviq:policy:invalidated", target_key)
            self._evaluator.load_policy(target_namespace, target_agent_class, rego, priority=priority)
            if mode_changed:
                # Same-version mode flip still needs to reach HA peers so their read-path reflects it too.
                await self._cache.publish_policy_event(
                    "upsert", target_namespace, target_agent_class, version=current_version, origin=self._origin
                )
            log.info("nrvq.policy.reapplied", key=target_key, code="NRVQ-REG-5011")
            return (current_version, False)

        # Different / new target scope → persist + load the policy there (full propagation + a new version).
        version = await self.create(
            target_namespace,
            target_agent_class,
            rego,
            saved_by=saved_by,
            priority=priority,
            enforcement_mode=enforcement_mode,
        )
        log.info("nrvq.policy.applied_to_target", source=self._key(source_namespace, source_agent_class),
                 target=target_key, version=version, code="NRVQ-REG-5012")
        return (version, True)

    async def rollback(self, namespace: str, agent_class: str, target_version: int) -> str:
        """Rollback to a previous version and return its source."""
        key = self._key(namespace, agent_class)
        target = next((item for item in self._versions.get(key, []) if item.version == target_version), None)
        if target is None:
            log.error("nrvq.policy.rollback_not_found", key=key, version=target_version, code="NRVQ-REG-5004")
            raise NorviqError(f"Version {target_version} not found for {key}", code="NRVQ-REG-5004")
        # Rollback restores the TARGET version's exact posture — its own stored priority + enforcement_mode
        # (persisted per-version now, and rehydrated across a restart), not the current policy's. This is
        # the true "roll back to how it was at vN", and survives a restart.
        new_version = await self.create(
            namespace,
            agent_class,
            target.rego_source,
            saved_by=f"rollback_to_v{target_version}",
            priority=target.priority,
            enforcement_mode=target.enforcement_mode,
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

    def mark_applied(self, namespace: str, agent_class: str, when: datetime | None = None) -> None:
        """C1/HA: record that a policy was APPLIED to the cluster now (re-stamps even for unchanged content).
        In-memory fast path only — callers that persisted a DB-side ``applied_at`` (``create()``, the
        mode-change branch of ``apply_to_target()``) MUST pass that exact value as ``when`` so this replica's
        view matches the row every peer will read back via ``load_from_db``/``warm_cache``/
        ``apply_remote_event``. Falls back to a local ``datetime.now()`` only for the true-no-op reaffirm
        case, where nothing new was persisted (unconverged, matching this method's pre-HA-fix behavior)."""
        self._applied_at = {**self._applied_at, self._key(namespace, agent_class): when or datetime.now(timezone.utc)}

    def get_applied_at(self, namespace: str, agent_class: str) -> datetime | None:
        """C1/HA: the last time this (ns, class) was applied. Hydrated from the DB-authoritative
        ``policies.applied_at`` column on warm start, on a peer's remote-event upsert, and on any lazy
        ``load_from_db`` — so this converges cross-replica for a real apply, not just within this process
        lifetime (the one exception: a true no-op reaffirm — rego AND mode both unchanged — only re-stamps
        this replica's in-memory view, since there's nothing new to persist)."""
        return self._applied_at.get(self._key(namespace, agent_class))

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
        in_memory = key in self._policies
        self._policies = {k: v for k, v in self._policies.items() if k != key}
        self._versions = {k: v for k, v in self._versions.items() if k != key}
        # H2: DB-AUTHORITATIVE — always run the (idempotent) Postgres DELETE, even when the key isn't in
        # THIS replica's memory. In HA a policy created on replica A before B started may not be in B's
        # `_policies`; the old early-return-False left the row alive (404 while it survives + re-warms on
        # restart). rowcount tells us whether a row actually existed so a true no-op still returns False.
        async with self._db_engine().begin() as conn:
            await conn.execute(
                text("DELETE FROM policy_versions WHERE policy_id IN "
                     "(SELECT id FROM policies WHERE namespace = :ns AND agent_class = :ac)"),
                {"ns": namespace, "ac": agent_class},
            )
            res = await conn.execute(
                text("DELETE FROM policies WHERE namespace = :ns AND agent_class = :ac"),
                {"ns": namespace, "ac": agent_class},
            )
        db_deleted = int(getattr(res, "rowcount", 0) or 0) > 0
        if not in_memory and not db_deleted:
            return False  # genuinely absent everywhere — a clean 404
        # Evaluator in-memory index (the counterpart to load_policy on create).
        if hasattr(self._evaluator, "unload_policy"):
            self._evaluator.unload_policy(namespace, agent_class)
        await self._cache.delete_policy(namespace, agent_class)
        await self._invalidate_eval_for_policy_scope(namespace, agent_class)  # clear stale eval-result cache
        await self._cache.publish_policy_event("delete", namespace, agent_class, version=0, origin=self._origin)
        log.info("nrvq.policy.deleted", key=key, code="NRVQ-REG-5007")
        return True

    async def apply_remote_event(self, operation: str, namespace: str, agent_class: str) -> None:
        """HA: apply a policy mutation another replica published, into THIS replica's in-memory state. The
        cross-replica sync listener (api/main.py) calls this for every non-self policy event so every replica
        enforces the same policy set within pub/sub latency (~ms) instead of until a restart. DB-read for an
        upsert (the peer already wrote the authoritative row); local unload for a delete. Best-effort — a
        failure here must never crash the listener (the next event, or a restart's warm_cache, self-heals)."""
        try:
            if operation == "delete":
                key = self._key(namespace, agent_class)
                self._policies = {k: v for k, v in self._policies.items() if k != key}
                self._versions = {k: v for k, v in self._versions.items() if k != key}
                if hasattr(self._evaluator, "unload_policy"):
                    self._evaluator.unload_policy(namespace, agent_class)
                await self._invalidate_eval_for_policy_scope(namespace, agent_class)
                log.info("nrvq.policy.remote_unloaded", key=key, code="NRVQ-REG-5016")
            else:  # upsert (create / apply)
                await self.load_from_db(namespace, agent_class)  # reads the peer's authoritative DB row
                # FIX-5: load_from_db only refreshes self._policies (current row) — it never touches
                # self._versions. Without this, a peer's version-snapshot mode-patch (apply_to_target's
                # history[-1].enforcement_mode = ...) only ever lands on the ORIGINATING replica, so a
                # rollback-to-current request landing on THIS replica would read a stale
                # _versions[key][-1].enforcement_mode. Re-read this key's version history from Postgres
                # (DB-authoritative — the peer already wrote it) so cross-replica rollback fidelity holds.
                await self._rehydrate_versions_for_key(namespace, agent_class)
                await self._invalidate_eval_for_policy_scope(namespace, agent_class)
                log.info("nrvq.policy.remote_reloaded", key=self._key(namespace, agent_class), code="NRVQ-REG-5017")
        except Exception as exc:  # noqa: BLE001 — sync is best-effort; never sink the listener
            log.error("nrvq.policy.remote_event_failed", operation=operation, ns=namespace, cls=agent_class,
                      error=str(exc), code="NRVQ-REG-5018")

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
            SELECT rego_source, priority, enforcement_mode, applied_at
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
        entry = {"rego": str(row["rego_source"]), "priority": int(row["priority"] or 100),
                 "enforcement_mode": str(row["enforcement_mode"] or "block")}
        self._policies = {**self._policies, key: entry}
        # C1/HA: this is the read path a PEER replica takes on an upsert event (apply_remote_event ->
        # load_from_db) — hydrate _applied_at from the SAME DB row so the peer converges on the originator's
        # persisted timestamp instead of keeping whatever (possibly null/stale) value it had before.
        if row["applied_at"] is not None:
            self._applied_at = {**self._applied_at, key: row["applied_at"]}
        if hasattr(self._evaluator, "reload_policy"):
            self._evaluator.reload_policy(namespace, agent_class, entry["rego"], priority=entry["priority"])
        log.info("nrvq.policy.lazy_loaded", key=key, code="NRVQ-REG-5014")
        return entry

    async def namespaces_for_class(self, agent_class: str) -> list[str]:
        """FIX-1 (namespace=all): every REAL namespace that currently holds a policy for ``agent_class``.

        The console's global picker sends ``namespace="all"``, which is not a real caller namespace (a real
        agent always carries a concrete one). This resolves that sentinel to the actual loaded layers — a union
        across the namespaces that own a policy for the class — the same way the asset/attack graphs already
        resolve ``all``. Reads DISTINCT from the DB (authoritative) and unions any in-memory-only keys (e.g. a
        spoke-pushed policy not re-scanned from DB). Never returns the sentinel namespaces. Fail-closed: on a DB
        error it degrades to the in-memory set rather than widening scope.

        FIX-3 (console under-report): also match ``<agent_class>__remediation__`` — a namespace can hold ONLY a
        per-class compliance-remediation overlay (COMP-GEN-01) with no base ``<agent_class>`` row yet. Bare
        ``agent_class = :agent_class`` alone would silently drop that namespace from this union, so the
        console's namespace="all" aggregate view would under-report it. Real per-namespace enforcement is
        unaffected — it looks up the remediation key unconditionally; this only widens the AGGREGATE listing."""
        found: set[str] = set()
        remediation_class = f"{agent_class}__remediation__"
        for key in self._policies:
            ns, _, ac = key.partition(":")
            if ac in (agent_class, remediation_class) and ns not in ("all", "__cluster__"):
                found.add(ns)
        query = text(
            "SELECT DISTINCT namespace FROM policies "
            "WHERE (agent_class = :agent_class OR agent_class = :remediation_class) AND namespace <> 'all'"
        )
        try:
            async with self._db_engine().begin() as conn:
                rows = (await conn.execute(
                    query, {"agent_class": agent_class, "remediation_class": remediation_class}
                )).mappings().all()
            for row in rows:
                found.add(str(row["namespace"]))
        except Exception as exc:  # noqa: BLE001 — DB unreachable → in-memory only, never widen scope
            log.warning("nrvq.policy.namespaces_for_class_failed", error=str(exc), code="NRVQ-REG-5015")
        return sorted(found)

    async def warm_cache(self) -> None:
        """Load latest policies from DB into memory on startup."""
        query = text(
            """
            SELECT namespace, agent_class, rego_source, priority, enforcement_mode, applied_at
            FROM policies
            ORDER BY namespace, agent_class, version DESC
            """
        )
        async with self._db_engine().begin() as conn:
            rows = (await conn.execute(query)).mappings().all()
        policies: dict[str, dict] = {}
        applied_at: dict[str, datetime] = {}
        for row in rows:
            key = self._key(str(row["namespace"]), str(row["agent_class"]))
            if key in policies:
                continue
            entry = {"rego": str(row["rego_source"]), "priority": int(row["priority"] or 100),
                     "enforcement_mode": str(row["enforcement_mode"] or "block")}
            policies[key] = entry
            # C1/HA: hydrate applied_at from the same DB rows on startup, so a restarted replica shows the
            # cluster's real last-applied time rather than None (process-local _applied_at is always empty
            # right after a restart).
            if row["applied_at"] is not None:
                applied_at[key] = row["applied_at"]
            if hasattr(self._evaluator, "reload_policy"):
                self._evaluator.reload_policy(str(row["namespace"]), str(row["agent_class"]), entry["rego"], priority=entry["priority"])
        self._policies = {**self._policies, **policies}
        self._applied_at = {**applied_at, **self._applied_at}  # in-process values (this lifetime) win on conflict
        await self._rehydrate_versions()  # B3: restore version history so the Versions tab + rollback survive a restart
        self._warmed = True  # F-04: warm load done -> the no-policy path is now "genuine", not "not-ready".
        log.info("nrvq.policy.cache_warmed", count=len(policies), code="NRVQ-REG-5015")

    async def _rehydrate_versions(self) -> None:
        """B3: rebuild the in-memory ``_versions`` map from the durable ``policy_versions`` table on startup.

        Previously ``_versions`` was only ever populated by an in-process ``create()``, so after a pod restart a
        warm-loaded policy showed "No version history available" and rollback had nothing to target — even though
        every version is persisted. This joins policy_versions → policies to key history by (namespace, class),
        ordered oldest→newest so the latest snapshot stays last (matching create()'s append order). Best-effort:
        a failure leaves in-memory history as-is (still fail-safe — the current policy is unaffected)."""
        query = text(
            """
            SELECT p.namespace AS namespace, p.agent_class AS agent_class,
                   pv.version AS version, pv.rego_source AS rego_source,
                   pv.saved_at AS saved_at, pv.saved_by AS saved_by,
                   pv.priority AS priority, pv.enforcement_mode AS enforcement_mode
            FROM policy_versions pv JOIN policies p ON pv.policy_id = p.id
            ORDER BY p.namespace, p.agent_class, pv.version ASC
            """
        )
        rehydrated: dict[str, list[PolicyVersion]] = {}
        try:
            async with self._db_engine().begin() as conn:
                rows = (await conn.execute(query)).mappings().all()
            for row in rows:
                key = self._key(str(row["namespace"]), str(row["agent_class"]))
                snapshot = PolicyVersion(
                    version=int(row["version"]),
                    rego_source=str(row["rego_source"]),
                    priority=int(row["priority"] or 100),          # rollback fidelity across a restart
                    enforcement_mode=str(row["enforcement_mode"] or "block"),
                    saved_by=str(row["saved_by"] or ""),
                    saved_at=row["saved_at"],
                )
                rehydrated.setdefault(key, []).append(snapshot)
            # RETENTION consistency: cap each rehydrated list to the same in-memory bound the append path
            # enforces (_MAX_VERSIONS) — the DB may retain more (policy_version_keep_count/keep_days), but
            # post-restart memory must not hold an unbounded history the live path would never accumulate.
            rehydrated = {k: v[-_MAX_VERSIONS:] for k, v in rehydrated.items()}
            # In-process history (written this lifetime) wins over rehydrated for a key already tracked.
            self._versions = {**rehydrated, **self._versions}
            log.info("nrvq.policy.versions_rehydrated", keys=len(rehydrated), code="NRVQ-REG-5016")
        except Exception as exc:  # noqa: BLE001 — history is derived; a failure never blocks warm-up
            log.warning("nrvq.policy.version_rehydrate_failed", error=str(exc), code="NRVQ-REG-5017")

    async def _rehydrate_versions_for_key(self, namespace: str, agent_class: str) -> None:
        """Single-key counterpart to `_rehydrate_versions`, used by `apply_remote_event`'s upsert branch.

        FIX-5: that branch previously called only `load_from_db` (refreshes `_policies`, so GET /policies is
        correct cluster-wide) but never touched `_versions` — so the FIX-A version-snapshot mode-patch
        (`apply_to_target`'s `history[-1].enforcement_mode = ...`) only ever landed on the ORIGINATING
        replica. A peer serving a rollback-to-current request would read its own stale
        `_versions[key][-1].enforcement_mode`. This re-reads just this key's version history from the
        durable `policy_versions` table (DB-authoritative — the peer already wrote the row) and REPLACES
        `self._versions[key]` outright, so a remote replica's history matches the originator's after an
        upsert event lands. Best-effort: a failure leaves this replica's existing history as-is."""
        query = text(
            """
            SELECT pv.version AS version, pv.rego_source AS rego_source,
                   pv.saved_at AS saved_at, pv.saved_by AS saved_by,
                   pv.priority AS priority, pv.enforcement_mode AS enforcement_mode
            FROM policy_versions pv JOIN policies p ON pv.policy_id = p.id
            WHERE p.namespace = :ns AND p.agent_class = :cls
            ORDER BY pv.version ASC
            """
        )
        key = self._key(namespace, agent_class)
        try:
            async with self._db_engine().begin() as conn:
                rows = (await conn.execute(query, {"ns": namespace, "cls": agent_class})).mappings().all()
            if not rows:
                return
            snapshots = [
                PolicyVersion(
                    version=int(row["version"]),
                    rego_source=str(row["rego_source"]),
                    priority=int(row["priority"] or 100),
                    enforcement_mode=str(row["enforcement_mode"] or "block"),
                    saved_by=str(row["saved_by"] or ""),
                    saved_at=row["saved_at"],
                )
                for row in rows
            ]
            self._versions = {**self._versions, key: snapshots}
            log.info("nrvq.policy.versions_rehydrated_key", key=key, count=len(snapshots), code="NRVQ-REG-5020")
        except Exception as exc:  # noqa: BLE001 — history is derived; a failure never blocks the sync listener
            log.warning("nrvq.policy.version_rehydrate_key_failed", key=key, error=str(exc), code="NRVQ-REG-5021")

    def _update_memory(self, key: str, rego_source: str, priority: int, enforcement_mode: str = "block") -> None:
        """Update memory map via copy-on-write swap. M4: the in-memory entry now carries enforcement_mode so
        list_policies can report it (was absent → the editor rewrote every saved policy to 'audit')."""
        self._policies = {**self._policies, key: {"rego": rego_source, "priority": int(priority), "enforcement_mode": enforcement_mode}}

    async def _invalidate_eval_for_policy_scope(self, namespace: str, agent_class: str) -> None:
        """Delete cached evaluation results affected by a policy change.

        CAND-A2: a namespace-wide OVERLAY scope (`__baseline__`, `__guardrail__`, and the `__pack__*` scopes)
        changes the effective decision for EVERY agent class in the namespace — not just its own eval key. So
        creating/reverting one must invalidate the WHOLE namespace's eval cache, or sibling classes keep serving
        a stale cached decision until the short eval TTL expires (the packs path already invalidates ns-wide;
        the generic create/delete path did not, so a `__baseline__` that newly blocks a tool was still served as
        the cached `allow` for ~TTL seconds). A concrete class scope stays narrowly scoped as before.
        """
        ns_wide = agent_class.startswith("__")  # __baseline__/__guardrail__/__pack__* affect every class in the ns
        # COMP-GEN-02 (cache-key-scope, DEF-003): a per-class compliance-remediation overlay is stored under the
        # compound key "<class>__remediation__", which does NOT start with "__" — but its rego is a tighten-only
        # overlay the evaluator BLENDS INTO the BASE class's decision, and eval results are cached under the BASE
        # class, never under the compound key. Invalidating the literal "<class>__remediation__" scope therefore
        # hit a phantom scope nobody caches under, leaving the base class serving a stale (possibly `allow`)
        # decision for ~eval TTL after a compliance control was applied/reverted. Resolve the overlay to its base
        # class so the scope that actually holds the affected decisions is cleared.
        target: str | None = None if ns_wide else agent_class
        if target is not None and target.endswith(_REMEDIATION_SUFFIX) and len(target) > len(_REMEDIATION_SUFFIX):
            target = target[: -len(_REMEDIATION_SUFFIX)]
        # ALWAYS delegate to the cache's own scope invalidation so the key SEGMENTS are hashed exactly the
        # way set_eval writes them. cache.py sha256-hashes each eval-key segment to defeat colon-stuffing
        # collisions; a direct, unhashed `eval:{namespace}:*` scan here would silently match NOTHING against the
        # hashed keys. `invalidate_eval_scope(ns, None)` builds the `eval:{h(ns)}:*` wildcard for the ns-wide case.
        await self._cache.invalidate_eval_scope(namespace, target)
        log.debug("nrvq.policy.eval_cache_cleared", namespace=namespace, agent_class=agent_class,
                  invalidated_scope=target, ns_wide=ns_wide, code="NRVQ-REG-5011")

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
            self._evaluator.reload_policy(namespace, agent_class, rego, priority=int(priority))

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
