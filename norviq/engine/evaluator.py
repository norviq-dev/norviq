# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""OPA-style policy evaluation engine for tool calls."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from datetime import datetime, timezone
from typing import Awaitable

import structlog

from norviq.config import settings
from norviq.engine.cache import RedisCache
from norviq.engine.graph.asset_graph import AssetGraphBuilder
from norviq.engine.graph.store import GraphStore
from norviq.engine.trust import AgentHistoryStore, AgentProfileStore, TrustCalculator, TrustInput, TrustResult
from norviq.engine.trust.signals.param_entropy import ParamEntropySignal
from norviq.sdk.core.decisions import PolicyDecision
from norviq.sdk.core.events import ToolCallEvent
from norviq.sdk.core.trust import TrustScore

log = structlog.get_logger()


class OPAEvaluator:
    """Core evaluator for policy decisions with cache-first execution."""

    def __init__(self, cache: RedisCache) -> None:
        """Store shared cache and initialize concurrency controls."""
        self._cache = cache
        self._history = AgentHistoryStore(cache)
        self._profile = AgentProfileStore(cache)
        self._trust_calculator = TrustCalculator(cache, self._history, self._profile)
        self._semaphore = asyncio.Semaphore(settings.evaluator_max_concurrency)
        self._audit_tasks: set[asyncio.Task[None]] = set()
        self._policies: dict[str, dict] = {}
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
        try:
            self._validate_spiffe(event.agent_identity.spiffe_id)
            trust = await self._trust(event.agent_identity.spiffe_id)
            trust_result = await self._compute_trust(event, trust)
            cache_tool = self._cache_tool_key(event.tool_name, event.tool_params)
            cached = await self._cache.get_eval(event.agent_identity.namespace, event.agent_identity.agent_class, cache_tool)
            if cached is not None:
                decision = await self._handle_cache_hit(event, cached, start, trust_result)
                await self._persist_behavior(event, decision, trust_result)
                return decision
            candidates = self._collect_candidates(event)
            if not candidates:
                async with self._semaphore:
                    result = await asyncio.wait_for(
                        self._evaluate_opa(
                            event.agent_identity.namespace,
                            event.agent_identity.agent_class,
                            self._build_input(event, trust_result),
                        ),
                        timeout=0.1,
                    )
                base_decision = self._build_decision(result, event, trust_result, (time.monotonic() - start) * 1000)
            else:
                results = []
                for candidate in candidates:
                    async with self._semaphore:
                        result = await asyncio.wait_for(
                            self._evaluate_single(event, str(candidate["rego"]), trust_result),
                            timeout=0.1,
                        )
                    results.append(
                        {
                            "decision": result,
                            "priority": int(candidate["priority"]),
                            "key": str(candidate["key"]),
                        }
                    )
                winner = self._resolve_precedence(results)
                base_decision = winner["decision"]
            if base_decision.rule_id not in settings.evaluator_non_cacheable_rules:
                await self._cache.set_eval(event.agent_identity.namespace, event.agent_identity.agent_class, cache_tool, base_decision)
            decision = self._apply_trust_overrides(base_decision, trust_result, event.event_id)
            await self._persist_behavior(event, decision, trust_result)
            return decision
        except asyncio.TimeoutError:
            elapsed_ms = (time.monotonic() - start) * 1000
            log.error("nrvq.engine.timeout", event_id=event.event_id, elapsed_ms=elapsed_ms, code="NRVQ-ENG-2020")
            return self._timeout_decision(event, elapsed_ms)
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            log.error("nrvq.engine.error", event_id=event.event_id, error=str(exc), code="NRVQ-ENG-2000")
            return self._fallback_decision(event, elapsed_ms)

    async def _handle_cache_hit(
        self,
        event: ToolCallEvent,
        cached: PolicyDecision,
        start: float,
        trust_result: TrustResult,
    ) -> PolicyDecision:
        """Apply cache-hit controls before returning a cached decision."""
        if cached.rule_id == "default_allow" and await self._is_rate_limited(event.agent_identity.spiffe_id):
            return await self._rate_limit_decision(event, start)
        decision = self._apply_trust_overrides(cached, trust_result, event.event_id)
        log.debug("nrvq.engine.cache_hit", event_id=event.event_id, code="NRVQ-ENG-2004")
        return decision

    async def _trust(self, spiffe_id: str) -> TrustScore:
        """Return trust score from cache, initializing when absent."""
        trust = await self._cache.get_trust(spiffe_id)
        if trust is not None:
            return trust
        trust = TrustScore()
        await self._cache.set_trust(spiffe_id, trust)
        return trust

    async def _compute_trust(self, event: ToolCallEvent, trust: TrustScore) -> TrustResult:
        """Compute trust from seven behavioral signals."""
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
        return await self._trust_calculator.calculate(trust_input)

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
            return decision.model_copy(update={"decision": "block", "reason": "Agent trust frozen — all tool calls blocked"})
        if trust_result.category == "low" and decision.decision == "allow":
            reason = f"Low trust ({trust_result.score:.2f}): {trust_result.dominant_signal}"
            log.warning("nrvq.engine.trust.override_escalate", event_id=event_id, code="NRVQ-ENG-2045")
            return decision.model_copy(update={"decision": "escalate", "reason": reason})
        return decision

    def _build_input(self, event: ToolCallEvent, trust_result: TrustResult) -> dict:
        """Build OPA input payload from tool event and trust state."""
        return {
            "tool_name": event.tool_name,
            "tool_params": event.tool_params,
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
        await self._post_decision(event, decision)
        self._queue_background(self._safe_record_graph(event, decision))
        self._queue_background(self._safe_record_history(event, decision))
        self._queue_background(self._safe_update_profile(event, decision))
        self._queue_audit(decision)

    async def _safe_record_graph(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Record graph updates and persist snapshots without blocking decisions."""
        try:
            namespace = event.agent_identity.namespace or "default"
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

    async def _safe_record_history(self, event: ToolCallEvent, decision: PolicyDecision) -> None:
        """Persist enforced decision for rolling trust-history features."""
        try:
            cache_tool = self._cache_tool_key(event.tool_name, event.tool_params)
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

    def _cache_tool_key(self, tool_name: str, tool_params: dict) -> str:
        """Build cache key suffix from tool name plus stable params hash."""
        payload = json.dumps(tool_params, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
        return f"{tool_name}:{digest}"

    async def _evaluate_opa(self, namespace: str, agent_class: str, opa_input: dict) -> dict:
        """Evaluate inline MVP policy rules and return first-match result."""
        # MVP placeholder: substring checks are intentionally simple until OPA/Rego integration.
        _ = self._policies.get(f"{namespace}:{agent_class}", "")
        params = str(opa_input.get("tool_params", {})).lower()
        for keyword in settings.evaluator_sql_deny_keywords:
            if keyword in params:
                return {"decision": "block", "rule_id": "deny_sql_injection", "reason": "SQL injection pattern detected"}
        tenant = str(opa_input.get("tool_params", {}).get("tenant_id", ""))
        agent_ns = opa_input["agent"]["namespace"]
        if tenant and tenant != agent_ns:
            return {"decision": "block", "rule_id": "deny_cross_tenant", "reason": f"Cross-tenant access: {tenant} != {agent_ns}"}
        if opa_input.get("tool_name", "").startswith(settings.evaluator_delete_prefix):
            if opa_input.get("tool_params", {}).get("record_id") == settings.evaluator_wildcard_value:
                return {"decision": "block", "rule_id": "deny_wildcard_delete", "reason": "Wildcard delete not allowed"}
        count = await self._cache.incr_call_count(opa_input["agent"]["spiffe_id"], settings.evaluator_rate_limit_window_s)
        if count > settings.evaluator_rate_limit_per_window:
            return {
                "decision": "block",
                "rule_id": "rate_limit_exceeded",
                "reason": f"Rate limit exceeded: {count}/{settings.evaluator_rate_limit_per_window} per {settings.evaluator_rate_limit_window_s}s",
            }
        if opa_input["trust_score"] < settings.trust_threshold:
            score = opa_input["trust_score"]
            return {"decision": "escalate", "rule_id": "escalate_low_trust", "reason": f"Trust score {score} below threshold"}
        return {"decision": "allow", "rule_id": "default_allow", "reason": "All checks passed"}

    async def _evaluate_single(self, event: ToolCallEvent, _rego_source: str, trust_result: TrustResult) -> PolicyDecision:
        """Evaluate one candidate policy source and return typed decision."""
        default_match = re.search(r'default\s+decision\s*=\s*"(allow|audit|escalate|block)"', _rego_source)
        if default_match:
            mode = default_match.group(1)
            rule_match = re.search(r'rule_id\s*=\s*"([^"]+)"', _rego_source)
            reason_match = re.search(r'reason\s*=\s*"([^"]+)"', _rego_source)
            return PolicyDecision(
                decision=mode,
                rule_id=rule_match.group(1) if rule_match else "",
                reason=reason_match.group(1) if reason_match else f"decision={mode}",
                trust_score=trust_result.score,
                trust_category=trust_result.category,
                trust_signals=trust_result.signals,
                trust_dominant_signal=trust_result.dominant_signal,
                trust_recommendation=trust_result.recommendation,
                latency_ms=0.0,
                event_id=event.event_id,
            )
        result = await self._evaluate_opa(
            event.agent_identity.namespace, event.agent_identity.agent_class, self._build_input(event, trust_result)
        )
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

    def _collect_candidates(self, event: ToolCallEvent) -> list[dict]:
        """Collect candidate policies from loader state by specificity."""
        if self._loader is None:
            return []
        namespace = event.agent_identity.namespace
        agent_class = event.agent_identity.agent_class or ""
        candidates = []
        class_key = f"{namespace}:{agent_class}"
        if class_key in self._loader._policies:
            entry = self._loader._policies[class_key]
            candidates.append({"key": class_key, "rego": entry["rego"], "priority": entry["priority"]})
        ns_key = f"{namespace}:__baseline__"
        if ns_key in self._loader._policies:
            entry = self._loader._policies[ns_key]
            candidates.append({"key": ns_key, "rego": entry["rego"], "priority": entry["priority"]})
        cluster_key = "__cluster__:__baseline__"
        if cluster_key in self._loader._policies:
            entry = self._loader._policies[cluster_key]
            candidates.append({"key": cluster_key, "rego": entry["rego"], "priority": entry["priority"]})
        return candidates

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
            reason=f"Evaluation failed, fallback={mode}",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def _timeout_decision(self, event: ToolCallEvent, elapsed_ms: float) -> PolicyDecision:
        """Return fail-closed decision specifically for evaluation timeout paths."""
        mode = "block"
        log.warning("nrvq.engine.timeout_fallback", event_id=event.event_id, mode=mode, code="NRVQ-ENG-2021")
        return PolicyDecision(
            decision=mode,
            reason="Evaluation timed out, fallback=block",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def load_policy(self, namespace: str, agent_class: str, rego_source: str, priority: int = 100) -> None:
        """Load or replace policy with copy-on-write atomic assignment."""
        key = f"{namespace}:{agent_class}"
        self._policies = {**self._policies, key: {"rego": rego_source, "priority": int(priority)}}
        log.info("nrvq.engine.policy_loaded", key=key, code="NRVQ-ENG-2005")

    def reload_policy(self, namespace: str, agent_class: str, rego_source: str) -> None:
        """Hot-reload a single policy without restarting."""
        key = f"{namespace}:{agent_class}"
        if key in self._policies:
            self._policies[key]["rego"] = rego_source
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
        # Minimal non-blocking emission until dedicated pipeline integration (F014).
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

    async def _is_rate_limited(self, spiffe_id: str) -> bool:
        """Check whether rate limit is exceeded for the current window."""
        count = await self._cache.incr_call_count(spiffe_id, settings.evaluator_rate_limit_window_s)
        return count > settings.evaluator_rate_limit_per_window

    async def _rate_limit_decision(self, event: ToolCallEvent, start: float) -> PolicyDecision:
        """Build and apply block decision when cached allow exceeds rate limit."""
        elapsed_ms = (time.monotonic() - start) * 1000
        return PolicyDecision(
            decision="block",
            rule_id="rate_limit_exceeded",
            reason=f"Rate limit exceeded: >{settings.evaluator_rate_limit_per_window} per {settings.evaluator_rate_limit_window_s}s",
            latency_ms=round(elapsed_ms, 2),
            event_id=event.event_id,
        )

    def _validate_spiffe(self, spiffe_id: str) -> None:
        """Validate SPIFFE identifier format before trust operations."""
        if not spiffe_id.startswith("spiffe://"):
            raise ValueError("invalid spiffe_id")
