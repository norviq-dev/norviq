# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""OPA-style policy evaluation engine for tool calls."""

from __future__ import annotations

import asyncio
from collections import OrderedDict
import contextlib
import hashlib
import json
import os
import re
import tempfile
import time
import traceback
from datetime import datetime, timezone
from typing import Awaitable

import structlog

from norviq.config import settings
from norviq.engine.cache import RedisCache
from norviq.engine.confusables import skeleton
from norviq.engine.inproc_cache import _MISS, TTLCache
from norviq.engine.masking import mask_params
from norviq.engine.graph.asset_graph import AssetGraphBuilder
from norviq.engine.graph.store import GraphStore
from norviq.engine.opa_client import OpaClient, managed_package, rewrite_package, sanitize_key
from norviq.telemetry.metrics import record_tool_call
from norviq.telemetry.spans import create_tool_call_span, enrich_span
from norviq.engine.trust import AgentHistoryStore, AgentProfileStore, TrustCalculator, TrustInput, TrustResult
from norviq.engine.trust.signals.param_entropy import ParamEntropySignal
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent
from norviq.sdk.core.trust import TrustScore

log = structlog.get_logger()

# Cap on concurrently-held ephemeral dry-run OPA modules (LRU-evicted past this) — bounds server
# memory + the _pushed digest map against a user dry-running arbitrary ns/class strings.
_MAX_DRYRUN_MODULES = 256

# Rule_ids that namespace monitor (audit) mode must NOT soften — they stay hard even when a
# namespace is set to visibility-only. An admin trust freeze is an incident-response kill switch that must outrank
# namespace posture; a not-ready / engine-error / invalid-payload block is an engine-health signal, not a policy
# decision to monitor away; and the rate-limit throttle is a resource control. This matches the GLOBAL audit mode,
# which likewise never weakens these.
_POSTURE_EXEMPT_RULES = frozenset(
    {"trust_frozen", "policy_load_pending", "evaluator_error", "evaluator_invalid_payload", "rate_limit_exceeded"}
)


class InvalidSpiffeIdentity(ValueError):
    """Raised when an agent's SPIFFE id fails format validation (named fallback attribution)."""


class OPAEvaluator:
    """Core evaluator for policy decisions with cache-first execution."""

    _PACKAGE_RE = re.compile(r"(?m)^\s*package\s+([A-Za-z0-9_\.]+)\s*$")

    def __init__(self, cache: RedisCache) -> None:
        """Store shared cache and initialize concurrency controls."""
        self._cache = cache
        self._history = AgentHistoryStore(cache)
        self._profile = AgentProfileStore(cache)
        self._trust_calculator = TrustCalculator(cache, self._history, self._profile)
        # Per-pod L1 for the hot path's slowly-changing input reads: namespace posture (keyed by ns)
        # and the stored trust score (keyed by spiffe). Both are safe to serve slightly stale (bounded
        # by the TTL); the admin freeze/cap kill-switch is read fresh inside the trust calculator and is
        # never cached here. TTL <= 0 makes these pass-throughs (see inproc_cache.TTLCache).
        _ttl = settings.evaluator_inproc_cache_ttl_s
        self._posture_cache = TTLCache(_ttl, settings.evaluator_inproc_cache_max)
        self._trust_score_cache = TTLCache(_ttl, settings.evaluator_inproc_cache_max)
        # Per-pod L1 for the base POLICY DECISION (pre-override), so a warm hit skips the get_eval Redis GET
        # and the whole warm path collapses to one pipelined round trip (the fresh freeze+cap). TTL is CLAMPED
        # to redis_ttl_eval_s: a dropped policy-invalidation pub/sub event must never leave a stale decision
        # cached LONGER than the Redis eval cache's own 5s self-heal bound. Invalidated eagerly on every policy
        # event via the cache's invalidation hook (below) — freeze/cap are NOT cached here, always read fresh.
        _eval_ttl = min(_ttl, settings.redis_ttl_eval_s) if _ttl > 0 else 0
        self._inproc_eval_cache = TTLCache(_eval_ttl, settings.evaluator_inproc_cache_max)
        if hasattr(cache, "register_eval_invalidation_hook"):
            cache.register_eval_invalidation_hook(self._on_eval_invalidated)
        self._semaphore = asyncio.Semaphore(settings.evaluator_max_concurrency)
        # OPA-server client + per-key pushed-rego digests (server mode); unused in subprocess mode.
        self.opa = OpaClient()
        self._pushed: dict[str, str] = {}
        # Dry-run pushes an ephemeral `dryrun:<ns>:<cls>` OPA module per scope. Any authenticated user can
        # dry-run with arbitrary ns/class strings, so track dry-run keys in insertion order and LRU-evict past
        # a cap (delete the OPA module + drop the digest) — bounds server memory + _pushed against abuse.
        self._dryrun_keys: OrderedDict[str, None] = OrderedDict()
        self._audit_tasks: set[asyncio.Task[None]] = set()
        self._policies: dict[str, dict] = {}
        # Count PERSISTENT engine (OPA-eval) errors so evaluator_error is observable, not silent. This is
        # an engine-health signal (a transient error self-heals on retry and is NOT counted here), distinct from
        # any policy decision. Surfaced alongside the DB-derived count on /audit/stats.
        self._engine_error_count = 0
        self._loader = None
        self._graph_store: GraphStore | None = None
        self._graphs: dict[str, AssetGraphBuilder] = {}

    @property
    def graph_builder(self) -> AssetGraphBuilder:
        """Expose shared runtime asset graph builder."""
        return self.get_graph("default")

    def get_graph(self, namespace: str) -> AssetGraphBuilder:
        """Return graph builder scoped by namespace."""
        if namespace not in self._graphs:
            self._graphs[namespace] = AssetGraphBuilder(max_nodes=settings.graph_max_nodes)
        return self._graphs[namespace]

    def bind_graph_store(self, graph_store: GraphStore) -> None:
        """Bind graph store for async persistence."""
        self._graph_store = graph_store

    async def evaluate(self, event: ToolCallEvent) -> PolicyDecision:
        """Evaluate tool call against all matching policies."""
        start = time.monotonic()
        cache_hit = False
        log.info(
            "nrvq.eval.start",
            tool_name=event.tool_name,
            namespace=event.agent_identity.namespace,
            agent_class=event.agent_identity.agent_class,
            code="NRVQ-ENG-DEBUG-1",
        )
        span = create_tool_call_span(
            event.tool_name,
            event.agent_identity.namespace,
            event.agent_identity.agent_class,
        )
        try:
            self._validate_spiffe(event.agent_identity.spiffe_id)
            # Resolve the caller namespace's posture (enforcement_mode / trust_threshold /
            # rate_limit) ONCE per eval, per-field fallback to the global config. A namespace with no override
            # yields the global posture and byte-identical behavior. Threaded into trust (threshold), the cache-hit
            # controls (rate_limit) and the post-resolution softening (monitor mode).
            posture = await self._resolve_posture(event.agent_identity.namespace)
            trust = await self._trust(event.agent_identity.spiffe_id)
            cache_tool = self._cache_tool_key(event)
            ns = event.agent_identity.namespace
            agent_class = event.agent_identity.agent_class
            spiffe = event.agent_identity.spiffe_id
            if self._inproc_eval_cache.enabled:
                # L1+L2 warm path: check the per-pod eval L1 first, then issue exactly ONE pipelined Redis
                # round trip for the rest. On an in-proc HIT that is just the fresh freeze+cap; on a miss it is
                # the eval GET bundled with the fresh freeze+cap. The freeze/cap are read fresh every call and
                # threaded into trust as prefetched_flags — never cached — so a freeze still flips a stale
                # in-proc allow to a block via _apply_trust_overrides on the very next call.
                inproc = self._inproc_eval_cache.get((ns, agent_class, cache_tool))
                if inproc is not _MISS:
                    is_frozen, cap = await self._cache.get_agent_flags(spiffe)
                    cached = inproc
                else:
                    cached, is_frozen, cap = await self._cache.get_eval_and_agent_flags(
                        ns, agent_class, cache_tool, spiffe
                    )
                    if cached is not None:
                        # Populate the L1 from the shared Redis decision (both hold the PRE-override base decision).
                        self._inproc_eval_cache.set((ns, agent_class, cache_tool), cached)
                trust_result = await self._compute_trust(
                    event, trust, posture["trust_threshold"], prefetched_flags=(is_frozen, cap)
                )
            else:
                trust_result = await self._compute_trust(event, trust, posture["trust_threshold"])
                cached = await self._cache.get_eval(ns, agent_class, cache_tool)
            if cached is not None:
                cache_hit = True
                decision = await self._handle_cache_hit(event, cached, start, trust_result, posture)
                # Stamp the real measured end-to-end latency so the audit record reflects it (not 0.0).
                decision = decision.model_copy(update={"latency_ms": round((time.monotonic() - start) * 1000, 2)})
                await self._persist_behavior(event, decision, trust_result)
                self._record_telemetry(event, decision, start, cache_hit, span)
                return decision
            candidates = await self._collect_candidates(event)
            log.info(
                "nrvq.eval.candidates",
                count=len(candidates),
                keys=[str(c["key"]) for c in candidates],
                code="NRVQ-ENG-DEBUG-2",
            )
            if not candidates:
                ns = event.agent_identity.namespace
                agent_class = event.agent_identity.agent_class
                async with self._eval_slot():
                    result = await asyncio.wait_for(
                        self._evaluate_opa(
                            f"{ns}:{agent_class}", ns, agent_class, self._build_input(event, trust_result)
                        ),
                        timeout=2.0,
                    )
                base_decision = self._build_decision(result, event, trust_result, (time.monotonic() - start) * 1000)
            else:
                results = []
                for candidate in candidates:
                    log.info(
                        "nrvq.eval.opa_call",
                        key=str(candidate["key"]),
                        rego_len=len(str(candidate["rego"])),
                        code="NRVQ-ENG-DEBUG-3",
                    )
                    async with self._eval_slot():
                        result = await asyncio.wait_for(
                            self._evaluate_single(event, str(candidate["key"]), str(candidate["rego"]), trust_result),
                            timeout=2.0,
                        )
                    log.info(
                        "nrvq.eval.opa_result",
                        key=str(candidate["key"]),
                        result=str(result)[:200],
                        code="NRVQ-ENG-DEBUG-4",
                    )
                    results.append(
                        {
                            "decision": result,
                            "priority": int(candidate["priority"]),
                            "key": str(candidate["key"]),
                            # Propagate the provenance flag set at candidate construction — the resolver
                            # must never re-derive overlay-ness from the key string.
                            "overlay": bool(candidate.get("overlay", False)),
                        }
                    )
                winner = self._resolve_with_packs(results)
                log.info("nrvq.eval.winner", winner=str(winner)[:200], code="NRVQ-ENG-DEBUG-5")
                base_decision = winner["decision"]
            if base_decision.rule_id not in settings.evaluator_non_cacheable_rules:
                await self._cache.set_eval(event.agent_identity.namespace, event.agent_identity.agent_class, cache_tool, base_decision)
                # Mirror the shared decision into the per-pod L1 under the SAME non-cacheable guard, so warm
                # replays skip the get_eval round trip. Caches only the PRE-override base decision — the fresh
                # freeze/cap + posture overrides are re-applied per call in _handle_cache_hit.
                if self._inproc_eval_cache.enabled:
                    self._inproc_eval_cache.set(
                        (event.agent_identity.namespace, event.agent_identity.agent_class, cache_tool), base_decision
                    )
            # Run the per-ns rate-limit throttle on the FRESH path too — otherwise call #1 (a cache
            # MISS) and non-cacheable allows never count against the window, and the ns-wide backstop only
            # ever engages on cache-hit replays. Same allow-only footing as the cache-hit path.
            throttled = await self._maybe_rate_limit(event, base_decision, start, posture)
            if throttled is not None:
                decision = throttled
            else:
                decision = self._apply_trust_overrides(base_decision, trust_result, event.event_id)
                decision = self._apply_posture(decision, posture, event.event_id)  # monitor mode
                decision = self._ensure_block_attribution(decision, event.event_id)
            # The multi-candidate path builds per-candidate decisions with latency_ms=0.0; stamp the real
            # measured end-to-end latency on the winning decision so every audit record carries it (AU-12/SLA).
            decision = decision.model_copy(update={"latency_ms": round((time.monotonic() - start) * 1000, 2)})
            await self._persist_behavior(event, decision, trust_result)
            self._record_telemetry(event, decision, start, cache_hit, span)
            return decision
        except asyncio.TimeoutError:
            elapsed_ms = (time.monotonic() - start) * 1000
            log.error("nrvq.engine.timeout", event_id=event.event_id, elapsed_ms=elapsed_ms, code="NRVQ-ENG-2020")
            decision = self._timeout_decision(event, elapsed_ms)
            self._record_telemetry(event, decision, start, cache_hit, span)
            return decision
        except InvalidSpiffeIdentity:
            elapsed_ms = (time.monotonic() - start) * 1000
            log.warning("nrvq.engine.invalid_identity", event_id=event.event_id, code="NRVQ-ENG-2006")
            decision = self._invalid_identity_decision(event, elapsed_ms)
            self._record_telemetry(event, decision, start, cache_hit, span)
            return decision
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            log.error("nrvq.engine.error", event_id=event.event_id, error=str(exc), code="NRVQ-ENG-2000")
            decision = self._ensure_block_attribution(self._fallback_decision(event, elapsed_ms), event.event_id)
            self._record_telemetry(event, decision, start, cache_hit, span)
            return decision
        finally:
            span.end()

    def _record_telemetry(
        self,
        event: ToolCallEvent,
        decision: PolicyDecision,
        start: float,
        cache_hit: bool,
        span,
    ) -> None:
        """Record metrics and enrich traces for one evaluated tool call."""
        latency_ms = (time.monotonic() - start) * 1000
        labels = {
            "namespace": event.agent_identity.namespace,
            "agent_class": event.agent_identity.agent_class,
            "tool_name": event.tool_name,
            "decision": decision.decision,
        }
        record_tool_call(labels, latency_ms, decision.trust_score, cache_hit)
        enrich_span(
            span,
            decision.decision,
            decision.trust_score,
            decision.rule_id,
            latency_ms,
            cache_hit,
            getattr(decision, "trust_signals", None),
        )

    async def _handle_cache_hit(
        self,
        event: ToolCallEvent,
        cached: PolicyDecision,
        start: float,
        trust_result: TrustResult,
        posture: dict,
    ) -> PolicyDecision:
        """Apply cache-hit controls before returning a cached decision."""
        # Throttle on the ALLOW footing (not just the no-policy `default_allow` rule) so the per-ns
        # rate_limit backstop applies to every explicitly-governed allow class too. rate_limit_exceeded is
        # exempt from monitor softening (a throttle is a resource control, not a policy decision) — the posture
        # pass inside _maybe_rate_limit leaves it untouched via _POSTURE_EXEMPT_RULES.
        throttled = await self._maybe_rate_limit(event, cached, start, posture)
        if throttled is not None:
            return throttled
        decision = self._apply_trust_overrides(cached, trust_result, event.event_id)
        decision = self._apply_posture(decision, posture, event.event_id)  # monitor mode
        log.debug("nrvq.engine.cache_hit", event_id=event.event_id, code="NRVQ-ENG-2004")
        return self._ensure_block_attribution(decision, event.event_id)

    async def _maybe_rate_limit(
        self, event: ToolCallEvent, base_decision: PolicyDecision, start: float, posture: dict
    ) -> PolicyDecision | None:
        """The per-namespace rate_limit is a namespace-wide DoS backstop, so it must throttle EVERY
        allowed call in the namespace — not only the no-policy `default_allow` class. Gate on the ALLOW decision
        (never block/escalate/audit — those are not resource grants and must not be flipped to a throttle),
        keeping the read-tool carve-out. Returns a posture-applied `rate_limit_exceeded` block when the
        window is exceeded, else None. Invoked from BOTH the cache-hit and fresh-eval paths so call #1 and
        non-cacheable allows are counted too; a single evaluate() traverses exactly one path, so the window
        counter increments exactly once per allowed non-exempt call."""
        if (base_decision.decision == "allow"
                and not self._is_rate_limit_exempt(event.tool_name)
                and await self._is_rate_limited(event.agent_identity.spiffe_id, posture["rate_limit"])):
            return self._apply_posture(
                await self._rate_limit_decision(event, start, posture["rate_limit"]), posture, event.event_id
            )
        return None

    async def _resolve_posture(self, namespace: str) -> dict:
        """Resolve a namespace's effective posture from the Redis mirror, per-field fallback
        to the global config. `monitor` is True ONLY when the namespace explicitly overrides enforcement_mode to
        'audit' — a null/global mode does NO softening (parity with today's weak global audit semantics, which only
        affect the no-policy default, never a real policy block). `trust_threshold` is None when unset so the trust
        calculator keeps its bit-identical literal 0.7/0.4 tiers. `rate_limit` never falls back to 0.

        Served from the per-pod posture L1 when warm: a posture change updates the Redis mirror and
        converges on every pod within the L1 TTL (the same bounded window as the eval cache)."""
        cached = self._posture_cache.get(namespace)
        if cached is not _MISS:
            return cached
        raw = None
        try:
            raw = await self._cache.get_ns_settings(namespace)
        except Exception as exc:  # noqa: BLE001 — a mirror read failure must never fail-closed; use global posture
            log.warning("nrvq.engine.posture.mirror_unavailable", namespace=namespace, error=str(exc),
                        code="NRVQ-ENG-2058")
        mode = raw.get("enforcement_mode") if raw else None
        thr = raw.get("trust_threshold") if raw else None
        rl = raw.get("rate_limit") if raw else None
        posture = {
            "monitor": mode == "audit",
            "trust_threshold": float(thr) if thr is not None else None,
            "rate_limit": int(rl) if rl is not None else settings.evaluator_rate_limit_per_window,
        }
        self._posture_cache.set(namespace, posture)
        return posture

    def _apply_posture(self, decision: PolicyDecision, posture: dict, event_id: str) -> PolicyDecision:
        """Namespace monitor mode softens a would-block/escalate to an allow-but-log `audit`
        decision (visibility only). Fires ONLY on an explicit per-ns enforcement_mode='audit'. Never tightens.
        Exempt rule_ids stay hard (parity with the global audit mode, which does not weaken these): an admin trust
        freeze is an incident-response kill switch that must outrank namespace posture; engine-health/not-ready
        blocks and the rate-limit throttle are not policy decisions to be monitored away."""
        if not posture.get("monitor"):
            return decision
        if decision.decision not in ("block", "escalate"):
            return decision
        if decision.rule_id in _POSTURE_EXEMPT_RULES:
            return decision
        log.info("nrvq.engine.posture.monitor_softened", event_id=event_id, orig_decision=decision.decision,
                 orig_rule=decision.rule_id, code="NRVQ-ENG-2059")
        return decision.model_copy(update={
            "decision": "audit",
            "rule_id": f"monitor_would_block:{decision.rule_id}",
            "reason": f"Monitor mode (namespace audit): would {decision.decision} — {decision.reason}",
        })

    @staticmethod
    def _is_rate_limit_exempt(tool_name: str) -> bool:
        """Read-like tools are exempt from the per-identity rate limiter (benign read spike not denied)."""
        if not settings.evaluator_rate_limit_read_exempt:
            return False
        name = (tool_name or "").lower()
        if name.endswith("_status") or name.endswith("_read"):
            return True
        return any(name.startswith(p) for p in settings.evaluator_rate_limit_read_prefixes)

    @staticmethod
    def _ensure_block_attribution(decision: PolicyDecision, event_id: str) -> PolicyDecision:
        """A block must NEVER carry an empty or allow-rule rule_id (the audit/UI mislabels). The OTel span
        path is already correct; this clamps the persisted/audited decision and alarms if an unattributed block
        ever reaches here."""
        if decision.decision == "block" and decision.rule_id in ("", "default_allow"):
            log.warning("nrvq.engine.unattributed_block", event_id=event_id, prior_rule=decision.rule_id,
                        code="NRVQ-ENG-2057")
            return decision.model_copy(update={"rule_id": "unattributed_block",
                                               "reason": decision.reason or "Blocked (attribution unavailable)"})
        return decision

    async def _trust(self, spiffe_id: str) -> TrustScore:
        """Return trust score from cache, initializing when absent.

        Fronted by the per-pod trust-score L1 to skip the Redis GET on warm calls. This is the STORED
        score only (a status/display value that the per-call `TrustCalculator.calculate` recomputes
        fresh); serving it slightly stale never relaxes enforcement, and the freeze/cap kill-switch is
        read fresh inside the calculator regardless."""
        cached = self._trust_score_cache.get(spiffe_id)
        if cached is not _MISS:
            return cached
        trust = await self._cache.get_trust(spiffe_id)
        if trust is None:
            trust = TrustScore()
            await self._cache.set_trust(spiffe_id, trust)
        self._trust_score_cache.set(spiffe_id, trust)
        return trust

    def _on_eval_invalidated(self, namespace: str | None = None, agent_class: str | None = None) -> None:
        """Clear the WHOLE per-pod in-proc eval L1 on any eval-cache invalidation.

        Registered on the RedisCache, so it fires for every invalidation path — the loader chokepoint
        (origin-inline mutations AND peer pub/sub events) and packs.py's direct calls — with no call site able
        to miss it. Clearing the whole (small, per-pod) cache rather than a scoped subset is deliberate: it
        structurally cannot leak a stale decision across an overlay/base/pack scope mismatch, and policy events
        are rare enough that the re-warm cost is negligible."""
        _ = namespace, agent_class
        self._inproc_eval_cache.clear()

    def clear_inproc_eval(self) -> None:
        """Public hook to drop the in-proc eval L1 (used by tests + the embedded sidecar's invalidation)."""
        self._inproc_eval_cache.clear()

    async def _compute_trust(
        self,
        event: ToolCallEvent,
        trust: TrustScore,
        trust_threshold: float | None = None,
        prefetched_flags: tuple[bool, float | None] | None = None,
    ) -> TrustResult:
        """Compute trust from seven behavioral signals.

        `trust_threshold` (per-ns override, else None) moves the category tiers. The calculator also reads
        the durable admin trust CAP for this identity and applies it tighten-only. Both are
        threaded into the single categorize inside `calculate()` so there is exactly one recategorization site.
        `prefetched_flags = (is_frozen, cap)` forwards a freeze/cap the evaluator already read FRESH in the
        collapsed hot-path pipeline, so the calculator does not re-read them (still fresh, never cached)."""
        trust_input = TrustInput(
            spiffe_id=event.agent_identity.spiffe_id,
            namespace=event.agent_identity.namespace,
            agent_class=event.agent_identity.agent_class,
            tool_name=event.tool_name,
            tool_params=event.tool_params,
            session_id=event.session_id,
            chain_depth=event.call_depth,
            timestamp=datetime.now(timezone.utc),
        )
        return await self._trust_calculator.calculate(
            trust_input, trust_threshold=trust_threshold, prefetched_flags=prefetched_flags
        )

    def _apply_trust_overrides(self, decision: PolicyDecision, trust_result: TrustResult, event_id: str) -> PolicyDecision:
        """Apply low/frozen trust overrides to policy decision."""
        decision = decision.model_copy(
            update={
                "trust_score": trust_result.score,
                "trust_category": trust_result.category,
                "trust_signals": trust_result.signals,
                "trust_dominant_signal": trust_result.dominant_signal,
                "trust_recommendation": trust_result.recommendation,
                "decided_at": datetime.now(timezone.utc),
            }
        )
        if trust_result.category == "frozen":
            log.warning("nrvq.engine.trust.override_block", event_id=event_id, code="NRVQ-ENG-2046")
            # Name the rule_id so the audit attributes the block rather than the prior allow rule.
            return decision.model_copy(update={"decision": "block", "rule_id": "trust_frozen",
                                               "reason": "Agent trust frozen — all tool calls blocked"})
        if trust_result.category == "low" and decision.decision == "allow":
            reason = f"Low trust ({trust_result.score:.2f}): {trust_result.dominant_signal}"
            log.warning("nrvq.engine.trust.override_escalate", event_id=event_id, code="NRVQ-ENG-2045")
            # rule_id carries the override provenance (escalate_low_trust is non-cacheable).
            return decision.model_copy(
                update={"decision": "escalate", "rule_id": "escalate_low_trust", "reason": reason}
            )
        return decision

    @staticmethod
    def _normalize_for_match(params: dict) -> dict:
        """Confusable-skeleton string values for injection MATCHING only (original preserved for audit)."""
        def _norm(value):
            if isinstance(value, str):
                return skeleton(value)
            if isinstance(value, list):
                return [_norm(v) for v in value]
            if isinstance(value, dict):
                return {k: _norm(v) for k, v in value.items()}
            return value

        return _norm(params)

    @staticmethod
    def _redacted_input(input_doc: dict) -> dict:
        """Mask tool_params before any log so raw PII/PAN/PHI can never reach a logger (PCI 3.4 / HIPAA)."""
        safe = dict(input_doc)
        if "tool_params" in safe:
            safe["tool_params"] = mask_params(safe.get("tool_params"))
        if "tool_params_normalized" in safe:
            safe["tool_params_normalized"] = mask_params(safe.get("tool_params_normalized"))
        return safe

    def _build_input(self, event: ToolCallEvent, trust_result: TrustResult) -> dict:
        """Build OPA input payload from tool event and trust state."""
        return {
            "tool_name": event.tool_name,
            # Confusable-skeleton of the tool NAME (homoglyph/zero-width evasion on the name itself,
            # e.g. Cyrillic "open_bгeaker"); rego matches control verbs/surface against this for parity.
            "tool_name_normalized": skeleton(event.tool_name),
            "tool_params": event.tool_params,
            # Matching-only confusable skeleton (homoglyph/zero-width evasion); rego scans this for injection.
            "tool_params_normalized": self._normalize_for_match(event.tool_params),
            "agent": {
                "spiffe_id": event.agent_identity.spiffe_id,
                "namespace": event.agent_identity.namespace,
                "agent_class": event.agent_identity.agent_class,
            },
            "trust_score": trust_result.score,
            "trust_category": trust_result.category,
            "session_id": event.session_id,
            "call_depth": event.call_depth,
        }

    async def _persist_behavior(self, event: ToolCallEvent, decision: PolicyDecision, trust_result: TrustResult) -> None:
        """Persist trust state, enforced outcome history, and profile evolution."""
        self._queue_background(self._safe_set_trust(event.agent_identity.spiffe_id, trust_result))
        self._queue_background(self._safe_register_agent(event, trust_result))
        await self._post_decision(event, decision)
        self._queue_background(self._safe_record_graph(event, decision))
        self._queue_background(self._safe_record_history(event, decision))
        self._queue_background(self._safe_update_profile(event, decision))
        self._queue_audit(decision)

    async def _restore_graph(self, namespace: str) -> None:
        """GRAPH-RESTORE: on the FIRST record for a namespace after a process start, restore the persisted
        snapshot into the live builder. Without this, a pod restart begins from an EMPTY graph and the next
        save clobbers the accumulated snapshot with just the new call — the asset/attack graphs silently
        lose every node built before the restart (graph amnesia on every deploy)."""
        if namespace in self._graphs or self._graph_store is None:
            return
        try:
            restored = await self._graph_store.load(namespace)
        except Exception as exc:  # pragma: no cover - cache/DB outage must not block the decision path
            log.error("nrvq.engine.graph.restore_failed", namespace=namespace, error=str(exc),
                      code="NRVQ-GRP-11016")
            return
        if restored is not None:
            self._graphs[namespace] = restored
            log.info("nrvq.engine.graph.restored", namespace=namespace,
                     nodes=restored.graph.number_of_nodes(), code="NRVQ-GRP-11017")

    async def _safe_record_graph(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Record graph updates and persist snapshots without blocking decisions."""
        try:
            namespace = event.agent_identity.namespace or "default"
            await self._restore_graph(namespace)
            graph = self.get_graph(namespace)
            graph.record_tool_call(
                spiffe_id=event.agent_identity.spiffe_id,
                tool_name=event.tool_name,
                decision=decision.decision,
                namespace=namespace,
                agent_class=event.agent_identity.agent_class,
            )
            if self._graph_store is not None:
                await self._graph_store.save(namespace, graph)
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.graph.record_failed", error=str(exc), code="NRVQ-GRP-11001")

    async def _safe_set_trust(self, spiffe_id: str, trust_result: TrustResult) -> None:
        """Persist trust score/factors while tolerating Redis failures."""
        try:
            await self._cache.set_trust(
                spiffe_id,
                TrustScore(
                    score=trust_result.score,
                    category=trust_result.category.title(),
                    factors={
                        "signals": trust_result.signals,
                        "weights": trust_result.weights,
                        "dominant_signal": trust_result.dominant_signal,
                        "recommendation": trust_result.recommendation,
                    },
                ),
            )
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.cache_set_failed", error=str(exc), code="NRVQ-ENG-2049")

    async def _safe_register_agent(self, event: ToolCallEvent, trust_result: TrustResult) -> None:
        """Write-through the agent's latest trust to the persistent registry (best-effort).

        Keeps the Agents view populated after the short-lived ``trust:*`` cache TTL expires.
        Fire-and-forget: a missing/unreachable DB (tests, cold start) must never fail a decision.
        """
        try:
            from norviq.api.db.session import get_session, upsert_agent_registry

            provider = get_session()
            session = await provider.__anext__()
            try:
                await upsert_agent_registry(
                    session,
                    spiffe_id=event.agent_identity.spiffe_id,
                    namespace=event.agent_identity.namespace or "default",
                    agent_class=event.agent_identity.agent_class,
                    trust_score=trust_result.score,
                    trust_category=trust_result.category.title(),
                )
                await session.commit()
            finally:
                await provider.aclose()
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.agent_registry.write_failed", error=str(exc), code="NRVQ-ENG-2051")

    async def _safe_record_history(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Persist enforced decision for rolling trust-history features."""
        try:
            cache_tool = self._cache_tool_key(event)
            await self._history.record(
                event.agent_identity.spiffe_id,
                {
                    "tool_name": event.tool_name,
                    "decision": decision.decision,
                    "param_hash": cache_tool.split(":")[-1],
                    "chain_depth": event.call_depth,
                    "timestamp": decision.decided_at.isoformat(),
                    "timestamp_unix": decision.decided_at.timestamp(),
                },
            )
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.history_failed", error=str(exc), code="NRVQ-ENG-2043")

    async def _safe_update_profile(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Update profile only for trusted outcomes using raw entropy baseline."""
        if decision.decision not in {"allow", "audit"}:
            return
        try:
            entropy = ParamEntropySignal.entropy_of_params(event.tool_params)
            rpm = await self._observed_rpm(event)
            await self._profile.update_profile(event.agent_identity.spiffe_id, event.tool_name, entropy, rpm, decision.decision)
        except Exception as exc:  # pragma: no cover
            log.error("nrvq.engine.trust.profile_failed", error=str(exc), code="NRVQ-ENG-2044")

    async def _observed_rpm(self, event: ToolCallEvent) -> float:
        """Estimate current calls-per-minute from recent history window."""
        history = await self._history.get_history(event.agent_identity.spiffe_id)
        now = datetime.now(timezone.utc).timestamp()
        recent = sum(1 for row in history if float(row.get("timestamp_unix", 0.0)) >= now - 60)
        return float(recent + 1)

    def _queue_background(self, work: Awaitable[None]) -> None:
        """Run non-critical persistence without blocking decision path."""
        task = asyncio.create_task(work)
        self._audit_tasks.add(task)
        task.add_done_callback(self._audit_tasks.discard)

    def _cache_tool_key(self, event: "ToolCallEvent") -> str:
        """Build the eval-cache key suffix from EVERY decision-relevant input dimension, not just tool +
        params. SECURITY (cache-key-scope, fail-open): the 5s eval cache keys on (namespace, agent_class,
        <this suffix>); any decision input NOT in the suffix lets one call's cached decision shadow a
        different call's within the TTL — an enforcement bypass. Two such inputs were omitted and are added
        here: `call_depth` (drives the chain_depth_limit / OWASP-LLM08 anti-recursion block — a shallow-depth
        allow must NOT shadow a deep-depth block) and `workload` (workload-tier `deployment:` policies — one
        workload's decision must NOT bleed to another sharing tool+params). Include them so the cached
        decision is only ever served for an identical decision input."""
        payload = json.dumps(event.tool_params, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        workload = getattr(event.agent_identity, "workload", "") or ""
        depth = int(getattr(event, "call_depth", 0) or 0)
        return f"{event.tool_name}:{digest}:d{depth}:w{workload}"

    def _extract_package_name(self, rego_source: str) -> str | None:
        """Extract package name from Rego source header."""
        if not rego_source:
            return None
        match = self._PACKAGE_RE.search(rego_source)
        if not match:
            return None
        return match.group(1).strip()

    def _opa_query_for_package(self, package_name: str | None) -> str:
        """Build OPA query path for a package root object."""
        if package_name:
            return f"data.{package_name}"
        return "data.norviq.strict"

    def _no_policy_decision(self, key: str, namespace: str) -> dict:
        """Decide when NO policy is loaded for `key`. Deny-by-default for a PEP (enforcement_mode=block),
        with three distinct, loudly-logged cases so a startup/load anomaly is never mistaken for genuine no-policy.

        - load FAILURE never reaches here: load_from_db raises -> evaluate() fail-closes (NRVQ-ENG-2000).
        - not-yet-warmed (loader bound but warm load incomplete) -> deny `policy_load_pending` (distinct alarm).
        - genuine no-policy for an enforcing namespace -> deny `no_policy_loaded` (block mode) or allow (audit mode).
        """
        loader = getattr(self, "_loader", None)
        warmed = getattr(loader, "_warmed", True) if loader is not None else True
        if not warmed:
            log.warning("nrvq.engine.policy_load_pending", key=key, namespace=namespace, code="NRVQ-ENG-2056")
            return {"decision": "block", "rule_id": "policy_load_pending", "reason": "Policy subsystem not ready"}
        if settings.enforcement_mode == "block" and str(settings.no_policy_decision).lower() == "deny":
            log.warning("nrvq.engine.no_policy_loaded", key=key, namespace=namespace, code="NRVQ-ENG-2055")
            return {"decision": "block", "rule_id": "no_policy_loaded",
                    "reason": "No policy loaded for namespace (default-deny)"}
        return {"decision": "allow", "rule_id": "default_allow", "reason": "No policy matched"}

    async def _evaluate_opa(
        self, key: str, namespace: str, agent_class: str, opa_input: dict, rego_source: str = ""
    ) -> dict:
        """Resolve the policy source for `key` and evaluate it (server HTTP or subprocess fork)."""
        rego = rego_source
        package_name: str | None = None
        if not rego.strip():
            entry = self._policies.get(key)
            if isinstance(entry, dict):
                rego = str(entry.get("rego", ""))
                package_name = str(entry.get("package_name", "")).strip() or None
        if not rego.strip():
            return self._no_policy_decision(key, namespace)
        if settings.opa_mode == "server":
            return await self._evaluate_opa_server(key, rego, opa_input)
        return await self._evaluate_opa_subprocess(namespace, agent_class, opa_input, rego, package_name)

    async def _track_dryrun_module(self, key: str) -> None:
        """LRU-bound the ephemeral dry-run OPA modules so an authenticated user can't grow the OPA server
        + _pushed map without limit by dry-running arbitrary ns/class strings. Past the cap, evict the oldest
        dry-run module (delete it from OPA + drop its digest); a re-used key simply re-pushes on next dry-run."""
        self._dryrun_keys[key] = None
        self._dryrun_keys.move_to_end(key)
        while len(self._dryrun_keys) > _MAX_DRYRUN_MODULES:
            old_key, _ = self._dryrun_keys.popitem(last=False)
            self._pushed.pop(old_key, None)
            try:
                await self.opa.delete_policy(sanitize_key(old_key))
            except Exception:  # noqa: BLE001 — best-effort cleanup; OPA over-writes by module_id anyway
                pass

    async def _evaluate_opa_server(self, key: str, rego: str, opa_input: dict) -> dict:
        """Evaluate against the long-lived OPA server; push (or re-push) the module as needed."""
        package = managed_package(key)
        module_id = sanitize_key(key)
        digest = hashlib.sha256(rego.encode("utf-8")).hexdigest()
        if self._pushed.get(key) != digest:
            await self.opa.push_policy(module_id, rewrite_package(rego, package))
            self._pushed[key] = digest
            if key.startswith("dryrun:"):
                await self._track_dryrun_module(key)
        result = await self.opa.query(package, opa_input)
        if result is None:
            # OPA lost in-memory state (sidecar restart) — re-push this module once and retry.
            log.warning("nrvq.opa.module_missing", key=key, code="NRVQ-ENG-2057")
            await self.opa.push_policy(module_id, rewrite_package(rego, package))
            self._pushed[key] = digest
            result = await self.opa.query(package, opa_input)
        if not isinstance(result, dict):
            return {"decision": "block", "rule_id": "evaluator_invalid_payload", "reason": "No policy decision produced"}
        if self._fired_without_decision(result):
            return {"decision": "block", "rule_id": "evaluator_invalid_payload",
                    "reason": "policy produced no decision (partial-set rule fired without a resolver)"}
        return {
            "decision": str(result.get("decision", "allow")),
            "rule_id": str(result.get("rule_id", "")),
            "reason": str(result.get("reason", "")),
        }

    async def _evaluate_opa_subprocess(
        self, namespace: str, agent_class: str, opa_input: dict, rego: str, package_name: str | None
    ) -> dict:
        """Evaluate Rego source via a per-call `opa eval` fork (rollback path)."""
        if package_name is None:
            package_name = self._extract_package_name(rego)
        query = self._opa_query_for_package(package_name)
        log.info(
            "nrvq.opa.query.resolved",
            package_name=package_name or "(none)",
            query=query,
            namespace=namespace,
            agent_class=agent_class,
            code="NRVQ-ENG-DEBUG-QUERY",
        )

        with tempfile.TemporaryDirectory(prefix="norviq-opa-") as tmpdir:
            policy_path = os.path.join(tmpdir, "policy.rego")
            input_path = os.path.join(tmpdir, "input.json")
            with open(policy_path, "w", encoding="utf-8") as policy_file:
                policy_file.write(rego)
            with open(input_path, "w", encoding="utf-8") as input_file:
                json.dump(opa_input, input_file)

            if settings.debug_opa_logging:
                log.info(
                    "nrvq.opa.input",
                    rego_preview=rego[:200],
                    input_doc=str(self._redacted_input(opa_input))[:500],  # masked even when debug on
                    package_name=package_name or "",
                    query=query,
                    code="NRVQ-ENG-DEBUG-OPA-IN",
                )

            proc = await asyncio.create_subprocess_exec(
                "opa",
                "eval",
                "--format=json",
                "--v0-compatible",
                "--data",
                policy_path,
                "--input",
                input_path,
                query,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if settings.debug_opa_logging:
                log.info(
                    "nrvq.opa.subprocess_done",
                    returncode=proc.returncode,
                    stdout_len=len(stdout),
                    stdout_preview=stdout.decode("utf-8", errors="replace")[:500],
                    stderr_preview=stderr.decode("utf-8", errors="replace")[:500],
                    code="NRVQ-ENG-DEBUG-OPA",
                )

        if proc.returncode != 0:
            raise RuntimeError(f"opa eval failed: {stderr.decode('utf-8', errors='replace').strip()}")

        parsed = json.loads(stdout.decode("utf-8"))
        value = self._extract_opa_value(parsed)
        if value is None:
            return {"decision": "block", "rule_id": "evaluator_invalid_payload", "reason": "No policy decision produced"}
        if isinstance(value, dict):
            if self._fired_without_decision(value):
                return {"decision": "block", "rule_id": "evaluator_invalid_payload",
                        "reason": "policy produced no decision (partial-set rule fired without a resolver)"}
            return {
                "decision": str(value.get("decision", "allow")),
                "rule_id": str(value.get("rule_id", "")),
                "reason": str(value.get("reason", "")),
            }
        return {"decision": "block", "rule_id": "evaluator_invalid_payload", "reason": "Invalid policy decision payload"}

    @staticmethod
    def _fired_without_decision(value: dict) -> bool:
        """True when a partial-set rule FIRED (blocks/escalates/audits non-empty) but the module
        produced no top-level `decision` — i.e. a decision-producing rule matched but there is no resolver
        to turn it into a decision. Defaulting such a result to "allow" would silently ALLOW a fired block.
        Fail closed only in this exact case, so a legitimate complete-rule policy whose condition simply did
        not match (no partial sets, decision undefined -> allow) is unaffected."""
        if "decision" in value:
            return False
        return bool(value.get("blocks") or value.get("escalates") or value.get("audits"))

    def _extract_opa_value(self, payload: object) -> object | None:
        """Extract first expression value from OPA eval JSON response."""
        if not isinstance(payload, dict):
            return None
        try:
            return payload["result"][0]["expressions"][0]["value"]
        except (KeyError, IndexError, TypeError):
            return None

    def _eval_slot(self):
        """Concurrency gate: serialize subprocess `opa eval` forks; no gate in server mode (OPA + the
        httpx pool absorb concurrency, which is what flattens the tail under load)."""
        if settings.opa_mode == "server":
            return contextlib.nullcontext()
        return self._semaphore

    async def _evaluate_single(
        self, event: ToolCallEvent, key: str, rego_source: str, trust_result: TrustResult
    ) -> PolicyDecision:
        """Evaluate one candidate policy source and return typed decision.

        A TRANSIENT OPA failure (e.g. the server-mode module lazy-load/push race right after a policy
        apply) must not fall straight through to a fail-closed `evaluator_error` block — a CLEAN, well-formed
        input would then be recorded as `evaluator_error` and mistaken for a real policy decision. So this retries
        ONCE (server mode re-pushes the module on the second attempt), so a transient error self-heals and a clean
        input never yields `evaluator_error`. Only a PERSISTENT engine error stays fail-closed, and it is counted
        + logged distinctly so it is visible as an engine-health signal, never confused with a policy rule. The
        retry runs ONLY on the error path, so the happy path keeps its latency."""
        last_exc: Exception | None = None
        for attempt in (1, 2):
            try:
                input_doc = self._build_input(event, trust_result)
                # Gated AND masked — raw tool_params never logged, so SSN/PAN/PHI cannot leak to an INFO line.
                if settings.debug_opa_logging and attempt == 1:
                    log.info("nrvq.eval.opa_input", input_doc=str(self._redacted_input(input_doc))[:500],
                             code="NRVQ-ENG-DEBUG-INPUT")
                result = await self._evaluate_opa(
                    key, event.agent_identity.namespace, event.agent_identity.agent_class, input_doc, rego_source
                )
                if attempt > 1:
                    log.info("nrvq.eval.opa_recovered", key=key, attempt=attempt, code="NRVQ-ENG-2056")
                return self._build_decision(result, event, trust_result, 0.0)
            except Exception as exc:  # noqa: BLE001 — fail-closed engine-error path
                last_exc = exc
                log.warning("nrvq.eval.opa_retry" if attempt == 1 else "nrvq.eval.opa_failed",
                            key=key, attempt=attempt, error=str(exc), code="NRVQ-ENG-DEBUG-ERR")
        # Persistent engine error → fail closed with a DISTINCT reason + a counted, observable engine-health
        # signal so it is never mistaken for a policy decision (a real policy block carries a policy rule_id).
        self._engine_error_count += 1
        log.error("nrvq.eval.opa_failed_persistent", key=key, error=str(last_exc),
                  traceback=traceback.format_exc(), engine_error_count=self._engine_error_count,
                  code="NRVQ-ENG-2057")
        result = {
            "decision": "block",
            "rule_id": "evaluator_error",
            "reason": "OPA evaluation failed (engine error, fail-closed) — not a policy decision",
        }
        return self._build_decision(result, event, trust_result, 0.0)

    def _build_decision(
        self, result: dict, event: ToolCallEvent, trust_result: TrustResult, elapsed_ms: float
    ) -> PolicyDecision:
        """Build policy decision model from rule evaluation output."""
        return PolicyDecision(
            decision=result.get("decision", settings.enforcement_mode),
            rule_id=result.get("rule_id", ""),
            reason=result.get("reason", ""),
            trust_score=trust_result.score,
            trust_category=trust_result.category,
            trust_signals=trust_result.signals,
            trust_dominant_signal=trust_result.dominant_signal,
            trust_recommendation=trust_result.recommendation,
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    async def _collect_candidates(self, event: ToolCallEvent) -> list[dict]:
        """Collect candidate policies from loader state by specificity."""
        if self._loader is None:
            return []
        namespace = event.agent_identity.namespace
        agent_class = event.agent_identity.agent_class or ""
        # The console's global picker sends namespace="all", which is NOT a real caller namespace (a
        # real agent always carries a concrete one). Resolve it to the UNION of every namespace that actually
        # holds a policy for this class — the same union the asset/attack graphs use — so /evaluate and
        # /policies/effective report the real winning layer (e.g. deny_shell_execution) instead of a misleading
        # no_policy_loaded. The concrete-namespace collection below is left byte-identical (decision parity).
        if namespace == "all":
            return await self._collect_candidates_union(agent_class)
        candidates = []

        async def _append_policy(target_namespace: str, target_agent_class: str) -> None:
            # This helper is used ONLY for base/floor lookups (the caller's own class, __baseline__,
            # namespace/workload tiers) — it NEVER tags "overlay": True. Overlay-ness must come from provenance
            # (where a candidate was constructed), never from a string-suffix match on the key, so a real
            # agent_class that happens to end in a reserved suffix (e.g. "...__remediation__") can never be
            # misclassified as an overlay and lose its priority-based precedence.
            key = f"{target_namespace}:{target_agent_class}"
            if key in self._loader._policies:
                entry = self._loader._policies[key]
                candidates.append({"key": key, "rego": entry["rego"], "priority": entry["priority"]})
                return
            loaded = await self._loader.load_from_db(target_namespace, target_agent_class)
            if loaded:
                candidates.append({"key": key, "rego": loaded["rego"], "priority": loaded["priority"]})

        await _append_policy(namespace, agent_class)
        await _append_policy(namespace, "__baseline__")
        await _append_policy("__cluster__", "__baseline__")
        # The catalog advertises WORKLOAD and NAMESPACE tiers (resolve_policy_key mints
        # `deployment:<name>` / `namespace:<ns>` keys); collect them here so they are enforced, not just
        # advertised (in-memory-only, additive: zero hot-path cost when absent, and priority resolution
        # still picks the winner):
        #   - namespace tier applies to EVERY call in the namespace (like a ns-scoped baseline);
        #   - workload tier applies only when the caller identifies its workload (never guessed).
        ns_tier_key = f"{namespace}:namespace:{namespace}"
        if ns_tier_key in self._loader._policies:
            entry = self._loader._policies[ns_tier_key]
            candidates.append({"key": ns_tier_key, "rego": entry["rego"], "priority": entry["priority"]})
        workload = getattr(event.agent_identity, "workload", "") or ""
        if workload:
            wl_key = f"{namespace}:deployment:{workload}"
            if wl_key in self._loader._policies:
                entry = self._loader._policies[wl_key]
                candidates.append({"key": wl_key, "rego": entry["rego"], "priority": entry["priority"]})
        # Additive sector-pack candidate. In-memory ONLY (no load_from_db) so it costs nothing
        # on the hot path for namespaces with no pack enabled — and is simply absent by default, so the
        # single-cluster path / attack namespaces are unchanged unless a pack is materialized here.
        # Every overlay appended below is tagged "overlay": True AT CONSTRUCTION — this is the sole
        # source of overlay-ness the resolver relies on (see _resolve_with_packs). Never derive it later from
        # the key string, which is ambiguous whenever a real agent_class collides with a reserved suffix.
        pack_key = f"{namespace}:__pack__"
        if pack_key in self._loader._policies:
            entry = self._loader._policies[pack_key]
            candidates.append({"key": pack_key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True})
        # Opt-in per-namespace tool allowlist guardrail. Same additive/in-memory-only discipline as
        # __pack__: absent by default (zero hot-path cost, single-cluster/attacks unchanged) and tighten-only.
        guardrail_key = f"{namespace}:__guardrail__"
        if guardrail_key in self._loader._policies:
            entry = self._loader._policies[guardrail_key]
            candidates.append({"key": guardrail_key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True})
        # Per-namespace sector-pack OVERRIDE — an operator-authored tighten-only overlay that customizes
        # the pack (e.g. add a stricter block). Same additive discipline: absent by default, tighten-only, never
        # weakens a pack's block. Revertable by deleting the (ns,__pack_override__) policy.
        override_key = f"{namespace}:__pack_override__"
        if override_key in self._loader._policies:
            entry = self._loader._policies[override_key]
            candidates.append({"key": override_key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True})
        # fleet-mgmt: per-namespace pack WEAKEN overlay — an explicit, admin-authored, audited customization that may
        # RELAX a pack's added restriction (unlike __pack_override__ which is tighten-only). Same additive/in-memory
        # discipline: absent by default (zero hot-path cost, single-cluster/attacks unchanged). The base comprehensive
        # policy is still a hard floor (_resolve_with_packs), so a weaken can never drop below the org baseline.
        # The weaken exception is scoped to the PACK family ONLY (see _resolve_overlay) — it can never relax
        # a __guardrail__ or a *__remediation__ overlay, which are hard tighten-only.
        weaken_key = f"{namespace}:__pack_weaken__"
        if weaken_key in self._loader._policies:
            entry = self._loader._policies[weaken_key]
            candidates.append({"key": weaken_key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True})
        # Per-CLASS compliance remediation overlay — a "Generate enforcing policy" draft for
        # a compliance gap technique is control-specific and additive (it must only ADD a block for this one
        # class, never REPLACE the class's existing comprehensive policy). It is reviewed+applied to the
        # dedicated key `(ns, "<agent_class>__remediation__")` — never to the base `(ns, agent_class)` key —
        # so the base policy stays byte-identical. Same additive/in-memory-only discipline as __pack__/
        # __guardrail__: absent by default, zero hot-path cost, tighten-only via _resolve_with_packs — and
        # HARD tighten-only: a __pack_weaken__ overlay can never relax this one.
        if agent_class:
            remediation_key = f"{namespace}:{agent_class}__remediation__"
            if remediation_key in self._loader._policies:
                entry = self._loader._policies[remediation_key]
                candidates.append(
                    {"key": remediation_key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True}
                )
        return candidates

    async def _collect_candidates_union(self, agent_class: str) -> list[dict]:
        """Union resolver for the console's namespace=all picker. Collects the class policy + baseline +
        the additive overlays for EVERY namespace that actually holds a policy for this class, plus the single
        cluster baseline. Mirrors the concrete-namespace collection above so `_resolve_with_packs` yields the
        real winning rule (e.g. deny_shell_execution), never no_policy_loaded when a policy IS loaded. Overlays
        stay tighten-only, so the union can never weaken a decision. Fail-closed: empty when nothing is loaded
        anywhere (then the caller still denies, now with the correct no_policy_loaded reason)."""
        candidates: list[dict] = []
        seen: set[str] = set()

        async def _append_policy(target_namespace: str, target_agent_class: str) -> None:
            # Base/floor lookup only — never tags "overlay": True (mirrors _collect_candidates).
            key = f"{target_namespace}:{target_agent_class}"
            if key in seen:
                return
            if key in self._loader._policies:
                entry = self._loader._policies[key]
                candidates.append({"key": key, "rego": entry["rego"], "priority": entry["priority"]})
                seen.add(key)
                return
            loaded = await self._loader.load_from_db(target_namespace, target_agent_class)
            if loaded:
                candidates.append({"key": key, "rego": loaded["rego"], "priority": loaded["priority"]})
                seen.add(key)

        def _append_overlay(key: str) -> None:
            # additive/in-memory-only overlays (pack/guardrail/override/weaken/remediation) — absent by default,
            # tighten-only. Tagged "overlay": True at construction — the resolver's sole source of truth.
            if key in seen or key not in self._loader._policies:
                return
            entry = self._loader._policies[key]
            candidates.append({"key": key, "rego": entry["rego"], "priority": entry["priority"], "overlay": True})
            seen.add(key)

        for ns in await self._loader.namespaces_for_class(agent_class):
            await _append_policy(ns, agent_class)
            await _append_policy(ns, "__baseline__")
            for overlay in ("__pack__", "__guardrail__", "__pack_override__", "__pack_weaken__"):
                _append_overlay(f"{ns}:{overlay}")
            # Mirror the per-class remediation overlay lookup from _collect_candidates for
            # the union resolver (console's namespace="all" picker) — same additive/in-memory-only, tighten-only.
            if agent_class:
                _append_overlay(f"{ns}:{agent_class}__remediation__")
        await _append_policy("__cluster__", "__baseline__")
        return candidates

    def _resolve_with_packs(self, results: list[dict]) -> dict:
        """Sector packs (:__pack__) and the opt-in tool-allowlist guardrail (:__guardrail__) are
        ADDITIVE-ONLY overlays — they can only TIGHTEN the decision (block < escalate < audit < allow), never
        loosen it, regardless of priority. We resolve the non-overlay candidates normally, then let the most
        restrictive overlay win only if it is stricter than the base. This makes an overlay's block/escalate
        enforce over a permissive baseline AND prevents an overlay escalate/allow from ever weakening a
        stricter policy.

        Overlay-ness is read from the "overlay" PROVENANCE FLAG each candidate was tagged with at
        construction (_collect_candidates/_collect_candidates_union), never re-derived from the key string. A
        real agent_class whose own base policy happens to end in a reserved suffix (e.g. "...__remediation__")
        is therefore never misclassified as an overlay and always keeps its priority-based precedence."""
        rank = {"block": 0, "escalate": 1, "audit": 2, "allow": 3}
        overlay = [r for r in results if r.get("overlay")]
        base = [r for r in results if not r.get("overlay")]
        base_winner = self._resolve_precedence(base) if base else None
        overlay_winner = self._resolve_overlay(overlay) if overlay else None
        if base_winner is None:
            return overlay_winner
        if overlay_winner is None:
            return base_winner
        overlay_rank = rank.get(overlay_winner["decision"].decision, 3)
        base_rank = rank.get(base_winner["decision"].decision, 3)
        return overlay_winner if overlay_rank < base_rank else base_winner

    @staticmethod
    def _is_overlay(key: str) -> bool:
        """Key-suffix heuristic retained for callers that only have a key string (e.g. the console's
        /policies/effective display labeling) and cannot carry the "overlay" provenance flag. Overlay candidates:
        sector packs, the allowlist guardrail, the tighten-only override, the fleet-mgmt admin pack
        WEAKEN overlay, and a per-class compliance remediation overlay (any class segment
        ending `__remediation__`, e.g. "ns:report-gen__remediation__"). The remediation suffix is dynamic (one
        overlay key per real class, unlike the fixed namespace-wide overlay names), so it's matched by suffix
        rather than an exact `:__remediation__` literal — the `__remediation__` double-underscore suffix is a
        reserved naming convention (mirrors `__pack__`/`__guardrail__`) that a real agent class is not expected
        to collide with, but CAN in principle. The evaluator's own resolution path
        (_resolve_with_packs) does NOT use this method — it uses the "overlay" flag tagged at construction, which
        can never misclassify a real class's own base policy. Prefer the flag over this heuristic wherever the
        candidate dict is available."""
        return (key.endswith(":__pack__") or key.endswith(":__guardrail__")
                or key.endswith(":__pack_override__") or key.endswith(":__pack_weaken__")
                or key.endswith("__remediation__"))

    def _resolve_overlay(self, results: list[dict]) -> dict:
        """Partition overlays into (a) the PACK family (:__pack__, :__pack_override__, :__pack_weaken__),
        where an explicit :__pack_weaken__ MAY relax the pack's own added block, and (b) HARD tighten-only
        overlays (:__guardrail__, *__remediation__), which a weaken must NEVER be able to relax — a
        __pack_weaken__ overlay exists ONLY to dial back a sector pack's own restriction, not to neutralize an
        operator guardrail or a compliance-remediation control. Each partition is resolved independently, then
        combined by plain most-restrictive-wins, so a hard block/escalate always survives a pack weaken's allow."""
        rank = {"block": 0, "escalate": 1, "audit": 2, "allow": 3}
        pack_family = [
            r for r in results
            if str(r["key"]).endswith((":__pack__", ":__pack_override__", ":__pack_weaken__"))
        ]
        pack_keys = {str(r["key"]) for r in pack_family}
        hard = [r for r in results if str(r["key"]) not in pack_keys]
        pack_winner = self._resolve_pack_family(pack_family) if pack_family else None
        hard_winner = self._resolve_hard_overlay(hard) if hard else None
        if pack_winner is None:
            return hard_winner
        if hard_winner is None:
            return pack_winner
        pack_rank = rank.get(pack_winner["decision"].decision, 3)
        hard_rank = rank.get(hard_winner["decision"].decision, 3)
        # a tie keeps the hard overlay's winner (guardrail/remediation reason takes attribution priority).
        return pack_winner if pack_rank < hard_rank else hard_winner

    @staticmethod
    def _resolve_pack_family(results: list[dict]) -> dict:
        """Resolve the PACK family (:__pack__, :__pack_override__, :__pack_weaken__) with the weaken exception:
        an explicit admin :__pack_weaken__ overlay supersedes the rest of the family so it can RELAX the pack's
        own added block — but only within this family; it never reaches outside it (see _resolve_overlay). Ties
        broken by highest priority; several weaken overlays -> the most permissive (deliberate relaxation) wins."""
        rank = {"block": 0, "escalate": 1, "audit": 2, "allow": 3}
        weaken = [r for r in results if str(r["key"]).endswith(":__pack_weaken__")]
        if weaken:
            weaken.sort(key=lambda item: (-rank.get(item["decision"].decision, 3), -int(item["priority"])))
            return weaken[0]
        results.sort(key=lambda item: (rank.get(item["decision"].decision, 3), -int(item["priority"])))
        return results[0]

    @staticmethod
    def _resolve_hard_overlay(results: list[dict]) -> dict:
        """Plain most-restrictive-wins for HARD tighten-only overlays (:__guardrail__, *__remediation__) — NO
        weaken exception. Ties broken by highest priority."""
        rank = {"block": 0, "escalate": 1, "audit": 2, "allow": 3}
        results.sort(key=lambda item: (rank.get(item["decision"].decision, 3), -int(item["priority"])))
        return results[0]

    def _resolve_precedence(self, results: list[dict]) -> dict:
        """Highest priority wins; most restrictive wins on ties."""
        decision_rank = {"block": 0, "escalate": 1, "audit": 2, "allow": 3}
        results.sort(
            key=lambda item: (
                -int(item["priority"]),
                decision_rank.get(item["decision"].decision, 3),
            )
        )
        return results[0]

    def _fallback_decision(self, event: ToolCallEvent, elapsed_ms: float) -> PolicyDecision:
        """Return fail-closed fallback decision when evaluation fails."""
        mode = "block"
        log.warning("nrvq.engine.fallback", event_id=event.event_id, mode=mode, code="NRVQ-ENG-2003")
        return PolicyDecision(
            decision=mode,
            rule_id="evaluator_fallback",  # name the fail-closed block so it is never left empty
            reason=f"Evaluation failed, fallback={mode}",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def _invalid_identity_decision(self, event: ToolCallEvent, elapsed_ms: float) -> PolicyDecision:
        """Named fail-closed decision for an invalid SPIFFE identity (SIEM can alert on the spoof class)."""
        return PolicyDecision(
            decision="block",
            rule_id="invalid_spiffe_identity",
            reason="Agent SPIFFE identity failed validation — fail-closed block",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def _timeout_decision(self, event: ToolCallEvent, elapsed_ms: float) -> PolicyDecision:
        """Return fail-closed decision specifically for evaluation timeout paths."""
        mode = "block"
        log.warning("nrvq.engine.timeout_fallback", event_id=event.event_id, mode=mode, code="NRVQ-ENG-2021")
        return PolicyDecision(
            decision=mode,
            rule_id="evaluator_timeout",
            reason="Evaluation timed out, fallback=block",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def load_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int = 100) -> None:
        """Load or replace policy with copy-on-write atomic assignment."""
        key = f"{namespace}:{agent_class}"
        package_name = self._extract_package_name(rego_source)
        self._policies = {
            **self._policies,
            key: {"rego": rego_source, "priority": int(priority), "package_name": package_name},
        }
        log.info("nrvq.engine.policy_loaded", key=key, code="NRVQ-ENG-2005")

    def unload_policy(self, namespace: str, agent_class: str) -> None:
        """Remove a policy from the in-memory index (copy-on-write) so a deleted/retracted policy stops
        being evaluated — the counterpart to load_policy."""
        key = f"{namespace}:{agent_class}"
        if key in self._policies:
            self._policies = {k: v for k, v in self._policies.items() if k != key}
            log.info("nrvq.engine.policy_unloaded", key=key, code="NRVQ-ENG-2031")

    def reload_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int | None = None) -> None:
        """Hot-reload a single policy without restarting.

        Use COPY-ON-WRITE (atomic dict swap) like load_policy — an in-place mutation of
        self._policies[key] would risk a torn read for a concurrent candidate iteration. PRESERVE the
        existing priority so the layer stack is not silently re-ordered; an explicit `priority` overrides
        when the caller has it.
        """
        key = f"{namespace}:{agent_class}"
        package_name = self._extract_package_name(rego_source)
        existing = self._policies.get(key)
        resolved_priority = priority if priority is not None else (int(existing["priority"]) if existing else 100)
        self._policies = {
            **self._policies,
            key: {"rego": rego_source, "priority": resolved_priority, "package_name": package_name},
        }
        log.info("nrvq.engine.policy_hot_reloaded", key=key, code="NRVQ-ENG-2030")

    def bind_loader(self, loader: object) -> None:
        """Bind loader reference for multi-policy priority resolution."""
        self._loader = loader

    async def _post_decision(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Log and mutate trust state after decision finalization."""
        if decision.decision == "block":
            log.warning("nrvq.engine.blocked", event_id=event.event_id, rule=decision.rule_id, code="NRVQ-ENG-2010")
            return
        if decision.decision == "escalate":
            log.warning("nrvq.engine.escalated", event_id=event.event_id, code="NRVQ-ENG-2015")
            return
        log.info("nrvq.engine.allowed", event_id=event.event_id, code="NRVQ-ENG-2001")

    async def _emit_audit(self, decision: PolicyDecision) -> None:
        """Emit asynchronous audit event without blocking caller path."""
        # Minimal non-blocking emission until dedicated pipeline integration.
        log.info(
            "nrvq.engine.audit_decision",
            event_id=decision.event_id,
            decision=decision.decision,
            rule_id=decision.rule_id,
            trust_score=decision.trust_score,
            trust_category=decision.trust_category,
            trust_signals=decision.trust_signals,
            latency_ms=decision.latency_ms,
            code="NRVQ-AUD-6000",
        )

    def _queue_audit(self, decision: PolicyDecision) -> None:
        """Queue audit task and track it for safe lifecycle management."""
        task = asyncio.create_task(self._emit_audit(decision))
        self._audit_tasks.add(task)
        task.add_done_callback(self._audit_tasks.discard)

    async def close(self) -> None:
        """Flush outstanding audit tasks during shutdown."""
        if self._audit_tasks:
            await asyncio.gather(*self._audit_tasks, return_exceptions=True)

    async def _is_rate_limited(self, spiffe_id: str, limit: int | None = None) -> bool:
        """Check whether rate limit is exceeded for the current window. `limit` is the caller
        namespace's per-ns ceiling (already global-defaulted by _resolve_posture); None keeps the global default."""
        ceiling = int(limit) if limit is not None else settings.evaluator_rate_limit_per_window
        count = await self._cache.incr_call_count(spiffe_id, settings.evaluator_rate_limit_window_s)
        return count > ceiling

    async def _rate_limit_decision(self, event: ToolCallEvent, start: float, limit: int | None = None) -> PolicyDecision:
        """Build and apply block decision when cached allow exceeds rate limit. The reason
        names the ACTUAL enforced ceiling (per-ns when overridden) so the audit record is not misleading."""
        elapsed_ms = (time.monotonic() - start) * 1000
        ceiling = int(limit) if limit is not None else settings.evaluator_rate_limit_per_window
        return PolicyDecision(
            decision="block",
            rule_id="rate_limit_exceeded",
            reason=f"Rate limit exceeded: >{ceiling} per {settings.evaluator_rate_limit_window_s}s",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def _validate_spiffe(self, spiffe_id: str) -> None:
        """Validate SPIFFE identifier format before trust operations."""
        if not spiffe_id.startswith("spiffe://"):
            raise InvalidSpiffeIdentity("invalid spiffe_id")
