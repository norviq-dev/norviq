# Norviq Error Codes

Every structured log line carries a stable `code="NRVQ-<COMPONENT>-<n>"` field. Grep for the code, not
the message text — messages get reworded, codes don't.

Codes come from log/error literals in `norviq/**/*.py` (control plane, engine, sidecar, SDK, CLI),
`webhook/*.go` (the Go admission webhook + CRD controller), and `ui/src/**` (one console-side guard).

A code is a **stable identifier for a situation, not a 1:1 alias for one message**. 95 of them are
reused across two or more related events (noted inline below) — `NRVQ-DB-9002`, `NRVQ-DB-9003`,
`NRVQ-API-7099` and `NRVQ-SDC-3032` are the ones most likely to surprise you.

What a code will **never** do is cover both a security signal and ordinary traffic: if a code fires
on something you would alert on, it does not also fire on a routine read. That is enforced by
`tests/test_log_code_uniqueness.py`, which also freezes the 95 so the count can only fall. It used
to be untrue — `NRVQ-API-7080` once covered `rate_limit.fail_open` alongside `cluster_info.served`,
so alerting on the throttle failing open also fired on every dashboard view.

`*-DEBUG-*` codes are development traces, not operator signals; they are listed in the index but not
individually described.

## Registry Summary

| Component | Unique Codes | Primary Sources |
|---|---:|---|
| API | 87 | `norviq/api/main.py`, `norviq/api/routers/*` |
| WHK | 55 | `webhook/main.go`, `webhook/handler.go`, `webhook/controller.go`, `webhook/injector.go` |
| ENG | 46 | `norviq/engine/evaluator.py`, `norviq/engine/trust/*`, `norviq/engine/opa_client.py` |
| DB | 42 | `norviq/api/db/session.py`, `norviq/engine/cache.py`, `norviq/api/main.py` |
| FLT | 36 | `norviq/fleet/*`, `norviq/fleet_relay.py`, `norviq/fleet_puller.py` |
| SDK | 29 | `norviq/sdk/*` |
| REG | 23 | `norviq/engine/policy_loader.py` |
| SDC | 20 | `norviq/sidecar/*` |
| AUTH | 17 | `norviq/api/auth.py`, `norviq/api/jwks.py`, `norviq/api/routers/auth_login.py` |
| AUD | 13 | `norviq/engine/audit_emitter.py`, `norviq/api/audit_retention.py` |
| GRP | 10 | `norviq/engine/graph/*` |
| RED | 10 | `norviq/redteam/*`, `norviq/api/routers/redteam.py` |
| TEL | 8 | `norviq/telemetry/*` |
| IDT | 7 | `norviq/engine/identity.py` |
| CLI | 5 | `norviq/cli/main.py`, `norviq/cli/api_client.py` |
| SIEM | 3 | `norviq/api/siem.py` |
| UI | 1 | `ui/src/api/clusterGuard.ts` |

Total unique codes: **410** (including `*-DEBUG-*` traces).

## API

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-API-7000 | `nrvq.api.started` | `norviq/api/main.py` |
| NRVQ-API-7001 | `nrvq.api.stopped` | `norviq/api/main.py` |
| NRVQ-API-7010 | `nrvq.api.policies.listed` | `norviq/api/routers/policies.py` |
| NRVQ-API-7016 | `nrvq.api.policy.reserved_scope` (rejected a direct write to the managed `__pack__` scope) | `norviq/api/routers/policies.py` |
| NRVQ-API-7011 | `nrvq.api.policy.saved` | `norviq/api/routers/policies.py` |
| NRVQ-API-7012 | `nrvq.api.policies.match_count_failed` (best-effort match count on the policy list; the list still serves). **`nrvq.api.policy.deleted` is `NRVQ-API-7018`, not this code.** | `norviq/api/routers/policies.py` |
| NRVQ-API-7013 | `nrvq.api.policy.rolled_back` | `norviq/api/routers/policies.py` |
| NRVQ-API-7014 | `nrvq.api.policy.dry_run` | `norviq/api/routers/policies.py` |
| NRVQ-API-7015 | `nrvq.api.policy.applied` | `norviq/api/routers/policies.py` |
| NRVQ-API-7020 | `nrvq.api.audit.listed`; also `nrvq.api.deployments.listed` | `norviq/api/routers/audit.py`, `norviq/api/routers/deployments.py` |
| NRVQ-API-7021 | `nrvq.api.audit.stats` | `norviq/api/routers/audit.py` |
| NRVQ-API-7022 | `nrvq.api.audit.top_blocked` | `norviq/api/routers/audit.py` |
| NRVQ-API-7023 | `nrvq.api.audit.volume` | `norviq/api/routers/audit.py` |
| NRVQ-API-7030 | `nrvq.api.agents.listed` | `norviq/api/routers/agents.py` |
| NRVQ-API-7031 | `nrvq.api.agent.trust_updated` — an admin set, capped or lifted an agent's freeze (`PUT /agents/{id}/trust`); carries `actor`, `actor_role`, `score`, `frozen`, `cap`. Its failure is `nrvq.api.agent.trust_persist_failed` (NRVQ-API-7033) | `norviq/api/routers/agents.py` |
| NRVQ-API-7061 | `nrvq.api.me.served` (current-user claims) | `norviq/api/routers/me.py` |
| NRVQ-API-7071 | `nrvq.api.mitre.activity_unavailable` (audit activity overlay best-effort; DB unavailable) | `norviq/api/routers/mitre.py` |
| NRVQ-API-7050 | `nrvq.api.asset_graph.served` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7050-ERR | `nrvq.api.asset_graph.error` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7052 | `nrvq.api.asset_graph.scope_denied` (multi-ns: caller requested a namespace outside its claim) | `norviq/api/routers/graphs.py` |
| NRVQ-API-7051 | `nrvq.api.attack_paths.served` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7051-ERR | `nrvq.api.attack_paths.error` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7101 | `nrvq.api.attack_paths.served` (enriched kill-chains, ns-scoped) | `norviq/api/routers/threats.py` |
| NRVQ-API-7102 | `nrvq.api.intent.coverage` / `coverage_eval_failed` (positive-security intent dry-run coverage) | `norviq/api/routers/threats.py` |
| NRVQ-API-7103 | `nrvq.api.intent.draft_created` (DRY-RUN draft; enforcement="draft", never enforces on its own) | `norviq/api/routers/threats.py` |
| NRVQ-API-7104 | `nrvq.api.intent.draft_listed` | `norviq/api/routers/threats.py` |
| NRVQ-API-7080 | `nrvq.api.cluster_info.served` (live cluster+namespaces); also `nrvq.api.mitre.generate_no_classes` | `norviq/api/routers/cluster_info.py`, `norviq/api/routers/mitre.py` |
| NRVQ-API-7081 | `nrvq.api.coverage.served` (coverage-by-category); also `nrvq.api.mitre.generate_batch` | `norviq/api/routers/coverage.py`, `norviq/api/routers/mitre.py` |
| NRVQ-API-7081-ERR | `nrvq.api.coverage.mapping_missing` | `norviq/api/routers/coverage.py` |
| NRVQ-API-7082 | `nrvq.api.agent.tool_usage` (audit-derived) | `norviq/api/routers/agents.py` |
| NRVQ-API-7083 | `nrvq.api.agent.trust_history` (audit-derived) | `norviq/api/routers/agents.py` |
| NRVQ-API-7084 | `nrvq.api.settings.served` (effective settings) | `norviq/api/routers/settings_router.py` |
| NRVQ-API-7085 | `nrvq.api.settings.saved` (override persisted) | `norviq/api/routers/settings_router.py` |
| NRVQ-API-7086 | `nrvq.api.version.served` (single-source version) | `norviq/api/routers/version.py` |
| NRVQ-API-7087 | `nrvq.api.apply.blocked_dry_run_only` (dry-run-only namespace rejects applies) | `norviq/api/routers/settings_router.py` |
| NRVQ-API-7090 | `nrvq.api.apikey.authenticated` (key auth) | `norviq/api/api_keys.py` |
| NRVQ-API-7091 | `nrvq.api.keys.listed` | `norviq/api/routers/keys.py` |
| NRVQ-API-7092 | `nrvq.api.keys.created` | `norviq/api/routers/keys.py` |
| NRVQ-API-7093 | `nrvq.api.keys.revoked` | `norviq/api/routers/keys.py` |
| NRVQ-API-7094 | `nrvq.api.packs.listed` (sector-pack catalog served) | `norviq/api/routers/packs.py` |
| NRVQ-API-7095 | `nrvq.api.pack.enabled` (pack materialized for a namespace) | `norviq/api/routers/packs.py` |
| NRVQ-API-7096 | `nrvq.api.pack.disabled` (pack removed from a namespace) | `norviq/api/routers/packs.py` |
| NRVQ-API-7097 | `nrvq.api.pack.error` (unknown pack id / missing rego or manifest) | `norviq/api/routers/packs.py` |
| NRVQ-API-7098 | `nrvq.api.pack.override_saved` / `override_reverted` (per-ns pack override) | `norviq/api/routers/packs.py` |
| NRVQ-API-7099 | Two events. `nrvq.api.pack.weaken_applied` (fleet-mgmt: LOUD audit — a pack WEAKEN overlay was applied; may relax a pack block, still floored by the comprehensive baseline) and `nrvq.api.insecure_default_secret` (boot: the JWT secret is the shipped default, empty, or <16 chars — tokens are forgeable. Warning always; **refuses to start** under `require_strong_secret`) | `norviq/api/routers/packs.py`, `norviq/api/main.py` |
| NRVQ-API-7460 | `nrvq.api.target_cluster_mismatch` (a cluster-scoped mutation carried `X-Nrvq-Target-Cluster` != this deployment's served cluster → 409; the SERVER backstop behind the UI guard) | `norviq/api/auth.py` (`require_target_cluster`) |
| NRVQ-API-7100 | `nrvq.api.policies.effective` (effective-resolution view) | `norviq/api/routers/policies.py` |
| NRVQ-API-7062 | `nrvq.api.policy.managed_scope_reverted` (admin confirm-deleted an operator-authored `__baseline__`/`__guardrail__`) | `norviq/api/routers/policies.py` |
| NRVQ-API-7063 | `nrvq.api.settings.warmed` (per-ns posture mirror warmed at startup; fires on every API process start, including with `count=0`) | `norviq/api/routers/settings_router.py` |
| NRVQ-API-7115 | `nrvq.api.search.served` (scoped ⌘K search across tools/agents/policies) | `norviq/api/routers/search.py` |
| NRVQ-API-7121 | `nrvq.api.agent.deregistered` (admin removed a decommissioned agent identity from the registry; carries `actor`, `actor_role` and `frozen`/`capped`, which are always `false` because a frozen or capped agent is refused, NRVQ-API-7143) | `norviq/api/routers/agents.py` |
| NRVQ-API-7122 | `nrvq.api.apikey.expired` (an expired API key was presented — rejected like a revoked one) | `norviq/api/api_keys.py` |
| NRVQ-API-7123 | `nrvq.api.policy.remediation_accumulated` (applying a compliance control UNIONED into the class's remediation overlay) | `norviq/api/routers/policies.py` |
| NRVQ-API-7124 | `nrvq.api.policy.remediation_control_reverted` (one control removed from the accumulated overlay; remaining controls re-materialized) | `norviq/api/routers/policies.py` |
| NRVQ-API-7002 | `nrvq.api.not_ready` (503 from `/readyz` — a backend is unreachable; drains traffic instead of CrashLooping) | `norviq/api/routers/health.py` |
| NRVQ-API-7012 | also `nrvq.api.policies.match_count_failed` (best-effort match count for the policy list) | `norviq/api/routers/policies.py` |
| NRVQ-API-7017 | `nrvq.api.policy.reserved_scope` (write rejected against a managed/reserved scope) | `norviq/api/routers/policies.py` |
| NRVQ-API-7018 | `nrvq.api.policy.deleted` | `norviq/api/routers/policies.py` |
| NRVQ-API-7019 | `nrvq.api.policy.write_scope_denied` (caller's namespace claim does not cover the write target) | `norviq/api/routers/policies.py` |
| NRVQ-API-7024 | `nrvq.api.audit.export` (audit evidence export served) | `norviq/api/routers/audit.py` |
| NRVQ-API-7032 | `nrvq.api.agents.registry_read_failed` | `norviq/api/routers/agents.py` |
| NRVQ-API-7033 | `nrvq.api.agent.registry_read_failed` / `agent.trust_persist_failed` / `agents.last_seen_failed` (degraded registry reads and writes; read paths still serve. `trust_persist_failed` means `PUT /agents/{id}/trust` answered **503** because the registry write, the per-agent lock or the commit failed: a freeze is live but not durable (`live=true`), a cap or clear was not applied (`restored=true` when Redis was put back after a failed commit)) | `norviq/api/routers/agents.py` |
| NRVQ-API-7034 | `nrvq.api.agent.overrides_warmed` — the boot warm wrote the agent freezes and trust caps recorded in `agent_registry` into the store (`count=` how many). Fires once per API process start whose warm completes, including with `count=0`; a start whose every attempt failed logs NRVQ-API-7035 instead. It is the only thing besides an admin trust change that writes them, so after the store loses its data they are absent until an API process logs this again | `norviq/api/routers/agents.py` |
| NRVQ-API-7035 | **`nrvq.startup.agent_overrides_warm_failed`** — every attempt of the boot warm of agent freezes and trust caps failed (`attempts=`, `error=`; 3 attempts, 1 s then 2 s apart, each cut off at 10 s). **Alert on this**: that process serves without having written them, so after a store loss frozen agents are enforced as not frozen and capped ones as uncapped until an API process starts and logs NRVQ-API-7034. Restart the API (`kubectl -n <namespace> rollout restart deployment/norviq-api`) once the cause is fixed. Through 0.2.5 a failed query or store write logged only a WARNING under this code, and the count it returned read like "nothing is frozen" | `norviq/api/routers/agents.py`, `norviq/startup_retry.py`, `norviq/api/main.py` |
| NRVQ-API-7158 | `nrvq.startup.agent_overrides_warm_retry` — one attempt of the boot warm of agent freezes and trust caps failed, or ran past 10 s, and is retried (`attempt=`, `delay=`; 3 attempts, 1 s then 2 s apart, `norviq.startup_retry.warm_with_backoff`). Transient on its own; NRVQ-API-7035 follows if the last attempt fails too | `norviq/api/routers/agents.py`, `norviq/startup_retry.py` |
| NRVQ-API-7040 / 7041 | `nrvq.api.ws_audit.open` / `close` (live audit WebSocket) | `norviq/api/main.py` |
| NRVQ-API-7136 | `nrvq.api.body_too_large` — request body over `max_request_body_bytes` (256 KiB), rejected with **413** before parsing. Alertable: the sidecar turns any 4xx from `/evaluate` into a hard block, so a burst of these is a misconfigured client or an abuse probe, and this log is the only record the cap fired (the reject path returns before the metric) | `norviq/api/body_limit.py` |
| NRVQ-API-7060 / 7060-ERR | `nrvq.attack_graph.computed` / `computed_all` / `compute_failed` (on-demand attack-path recompute) | `norviq/api/routers/attack_graph_compute.py` |
| NRVQ-API-7064 | `nrvq.startup.policy_sync_dropped` (a policy-sync message was dropped at boot) | `norviq/api/main.py` |
| NRVQ-API-7070-ERR | `nrvq.api.mitre.mapping_missing` | `norviq/api/routers/mitre.py` |
| NRVQ-API-7072..7079 | MITRE overlay best-effort paths: `affected_unavailable` (7072), `snapshot_failed` (7073), `trend_unavailable` (7074), `export_record_failed` (7075), `export` (7076), `generate` (7077), `active_classes_unavailable` (7078), `generate_escalate` (7079). The `*_unavailable` ones degrade the overlay, never the decision path. | `norviq/api/routers/mitre.py` |
| NRVQ-API-7105 | `nrvq.api.intent.suggest` (positive-security intent suggestion) | `norviq/api/routers/threats.py` |
| NRVQ-API-7110 | `nrvq.api.retention.drafts_expired`, plus `nrvq.api.capability.defend` and `nrvq.api.toolverb.promote` | `norviq/api/retention.py`, `norviq/api/routers/threats.py` |
| NRVQ-API-7111 | `nrvq.api.retention.gc_failed`, plus `nrvq.api.toolverb.demote` | `norviq/api/retention.py`, `norviq/api/routers/threats.py` |
| NRVQ-API-7112 | `nrvq.api.retention.drafts_capped` (per-namespace draft ceiling evicted the oldest), plus `nrvq.api.graph.node_removed` (admin removed an asset-graph node) | `norviq/api/retention.py`, `norviq/api/routers/graphs.py` |
| NRVQ-API-7113 | `nrvq.api.retention.cap_failed` | `norviq/api/retention.py` |
| NRVQ-API-7114 | `nrvq.api.intent.draft_dismissed` | `norviq/api/routers/threats.py` |
| NRVQ-API-7120 | `nrvq.api.policy.scope_cap_exceeded` (namespace hit `policy_scope_cap_per_namespace`, 200 distinct `(ns, class)` scopes) | `norviq/api/routers/policies.py` |
| NRVQ-API-7132 | `nrvq.api.policy.intent_without_baseline` — an intent policy was refused (409) because no baseline or controls policy exists under it, so the intent would be the only thing standing between the agent and the tool | `norviq/api/routers/policies.py` |
| NRVQ-API-7133 | **`nrvq.api.rate_limit.fail_open`** — Redis was unreachable so the HTTP rate limiter let the request through (availability over strictness; log-throttled to once per 30s). Alert on this: while it fires, the HTTP throttle is not enforcing | `norviq/api/rate_limit.py` |
| NRVQ-API-7134 | **`nrvq.api.rate_limit.exceeded`** — the HTTP-layer throttle returned **429** for this route class | `norviq/api/rate_limit.py` |
| NRVQ-API-7135 | `nrvq.api.policy.priority_band_denied` — a write tried to claim a priority band it isn't allowed to | `norviq/api/routers/policies.py` |
| NRVQ-API-7137 | `nrvq.api.settings.mirror_failed` — an admin saved per-namespace posture, the row committed and the console shows it applied, but the Redis mirror the evaluator hot path reads did not update. **Alert on this**: enforcement is running on the previous or global posture while the UI claims otherwise | `norviq/api/routers/settings_router.py` |
| NRVQ-API-7138 | `nrvq.startup.ns_settings_warm_failed` — every attempt of the boot warm of per-namespace posture failed (`attempts=`, `error=`; same schedule as 7035), so after a store loss *every* persisted per-ns posture is absent from Redis and the evaluator falls back to global config until an API process starts and logs NRVQ-API-7063. Wider blast radius than 7137, same meaning: saved posture is not the posture being enforced. Restart the API once the cause is fixed | `norviq/api/routers/settings_router.py`, `norviq/startup_retry.py`, `norviq/api/main.py` |
| NRVQ-API-7159 | `nrvq.startup.ns_settings_warm_retry` — one attempt of the boot warm of per-namespace posture failed, or ran past 10 s, and is retried (`attempt=`, `delay=`; 3 attempts, 1 s then 2 s apart). Transient on its own; NRVQ-API-7138 follows if the last attempt fails too | `norviq/api/routers/settings_router.py`, `norviq/startup_retry.py` |
| NRVQ-API-7139 | `nrvq.api.baseline.rematerialized` — at startup, a namespace's saved baseline controls were re-compiled from their stored effects because the stored module differed from what this release compiles, or there was none (`had_module=false`: rows an earlier release saved without writing the module) | `norviq/api/routers/baseline_router.py` |
| NRVQ-API-7140 | `nrvq.api.baseline.rematerialize_failed` — re-compiling one namespace's saved baseline controls at startup failed; that namespace keeps its old module, which cannot replace the chart's baseline (NRVQ-ENG-2068) | `norviq/api/routers/baseline_router.py` |
| NRVQ-API-7141 | `nrvq.api.baseline.rematerialize_skipped_foreign` — a `__controls__` policy the baseline controls API did not write (its name is not `baseline-controls:<preset>`) was left as it is | `norviq/api/routers/baseline_router.py` |
| NRVQ-API-7142 | `nrvq.startup.baseline_controls_rematerialize_failed` — the startup re-compile of saved baseline controls failed as a whole (for example the database was unreachable); no namespace was re-compiled | `norviq/api/main.py` |
| NRVQ-API-7143 | `nrvq.api.agent.deregister_refused` — `DELETE /agents/{id}` answered **409** because the agent is frozen or under a trust cap (`frozen`, `capped`, `actor`). Deleting the registry row would have lifted the control; lift it with `PUT /agents/{id}/trust` (score 1.0) first | `norviq/api/routers/agents.py` |
| NRVQ-API-7144 | `nrvq.api.agent.deregister_check_failed` — `DELETE /agents/{id}` could not take the per-agent lock, read the registry row or the live freeze/cap keys, or commit, and answered **503** without deleting anything | `norviq/api/routers/agents.py` |
| NRVQ-API-7145 | `nrvq.api.agent.trust_reset` — the audit record of `POST /agents/{id}/trust/reset`: an admin cleared the agent's behavioural history and profile. Carries `actor`, `actor_role`, `score_before`, `violation_count` (the registry's cumulative count, which the reset keeps), `history_entries_cleared`, `history_blocks_cleared`, `keys_cleared`, and the `frozen`/`trust_cap` that stay in force | `norviq/api/routers/agents.py` |
| NRVQ-API-7146 | `nrvq.api.agent.trust_reset_failed` — the reset could not take the per-agent lock or run its Redis transaction and answered **503**; the counts and the delete are one MULTI, so nothing was cleared | `norviq/api/routers/agents.py` |
| NRVQ-API-7147 | `nrvq.api.agent.trust_live_failed` — `PUT /agents/{id}/trust` wrote the registry but Redis did not take the change, and answered **503**. `durable=true`: a freeze is committed and takes effect at the next API start (`warm_agent_overrides`), so alert on it — the agent is not frozen yet. `durable=false`: a cap or clear was rolled back, nothing changed | `norviq/api/routers/agents.py` |

## WHK

The Go admission webhook: the injector (mutating admission) and the CRD controller that syncs
`NrvqPolicy`/`NrvqClass`/`NrvqConfig` to the API. This is the path an operator debugs when an agent
pod starts **without** a sidecar, or when a CRD write doesn't reach the console.

**Server / lifecycle** — `webhook/main.go`

| Code | Meaning |
|---|---|
| NRVQ-WHK-4000 | webhook server starting |
| NRVQ-WHK-4001 | TLS cert load failed (the `norviq-webhook-tls` Secret is missing or unreadable) |
| NRVQ-WHK-4002 | server failed to start |
| NRVQ-WHK-4010 | panic recovered in a handler |
| NRVQ-WHK-4011 | graceful shutdown |

**Admission / injection** — `webhook/handler.go`

| Code | Meaning |
|---|---|
| NRVQ-WHK-4003 | sidecar injected (the success line) |
| NRVQ-WHK-4004 | AdmissionReview unmarshal failed |
| NRVQ-WHK-4005 | response marshal failed |
| NRVQ-WHK-4006 | pod unmarshal failed |
| NRVQ-WHK-4007 | injection opted out for this pod (`norviq-injection=disabled` / `norviq.io/skip-injection`) |
| NRVQ-WHK-4008 | pod already fully injected, skipping |
| NRVQ-WHK-4009 | patch creation failed; also logged when a pod-level opt-out is **ignored** because `webhook.injection.allowPodOptOut=false` |
| NRVQ-WHK-4012 | dry-run injection (admission `dryRun`, nothing persisted) |
| NRVQ-WHK-4013 | wrong Content-Type |
| NRVQ-WHK-4014 | AdmissionReview read failed |
| NRVQ-WHK-4015 | invalid agent-class label; injecting with an empty class |
| NRVQ-WHK-4034 | **enforcement-integrity denial** — the request tried to self-stamp as already-injected or otherwise bypass injection, and was refused. Also used by the controller for a cross-namespace policy rejection. |

**CRD controller** — `webhook/controller.go`

| Code | Meaning |
|---|---|
| NRVQ-WHK-4020 / 4021 | controller init failed (in-cluster config) / controller failed (dynamic client) |
| NRVQ-WHK-4022 / 4023 | controller starting / informer cache synced |
| NRVQ-WHK-4024 | unexpected object type in handler |
| NRVQ-WHK-4025 | API sync failed for a policy |
| NRVQ-WHK-4026 | policy synced to the API successfully; also "service token minted" |
| NRVQ-WHK-4027 | policy deleted from the API; also "service token mint failed" |
| NRVQ-WHK-4028 | work queue full — sync/class/config/delete item skipped |
| NRVQ-WHK-4029 | preset rego file not found (`webhook/presets/`) |
| NRVQ-WHK-4030 | unexpected object type on delete |
| NRVQ-WHK-4031 | API delete failed |
| NRVQ-WHK-4032 | invalid rego rejected (never reaches OPA) |
| NRVQ-WHK-4033 | **blocked unauthorized sidecar image** — a `NrvqConfig` tried to point injection at an image other than the pinned one |
| NRVQ-WHK-4035 | finalizer add failed / finalizer conflict, retrying |
| NRVQ-WHK-4036 | finalizer remove failed; also "ignoring mutable sidecar tag override, keeping the pinned image" |
| NRVQ-WHK-4037 | invalid `clusterPriority` rejected; also "no API secret to mint a sidecar token — the thin-proxy sidecar will fail closed" |
| NRVQ-WHK-4038 | class status update failed; also sidecar token mint failed |
| NRVQ-WHK-4039 / 4040 | config status update failed / policy status update failed |
| NRVQ-WHK-4041 | forcing finalizer removal after timeout (prevents a stuck delete) |
| NRVQ-WHK-4042 | controller using OIDC client-credentials identity; also "namespace baseline keyed to target namespace" |
| NRVQ-WHK-4043 | OIDC client-credentials token failed; falling back to HS256 |
| NRVQ-WHK-4044 / 4045 | internal CA cert unreadable / contained no valid PEM certificates |
| NRVQ-WHK-4046 | internal-TLS API client build failed; using the fail-closed client |
| NRVQ-WHK-4059 | retrying an unsynced policy — the 60s retry sweep found an `NrvqPolicy` left in `Error`/`Pending` (a sync that failed against a transiently-down API) and is re-queueing it. Informational: one line per policy per sweep until it reaches `Active`. Deterministic failures (invalid rego, deleted class) are **not** retried and do not log this. |

**Sidecar mTLS cert minting** — `webhook/injector.go`

| Code | Meaning |
|---|---|
| NRVQ-WHK-4047 | internal CA cert unreadable for sidecar mTLS — **falls back to plaintext + JWT** |
| NRVQ-WHK-4048 | sidecar client-cert mint failed — falls back to plaintext + JWT |
| NRVQ-WHK-4049..4058 | CA material problems during minting: CA cert read (4049), CA key read (4050), key generation (4051), serial generation (4052), signing (4053), CA cert PEM not a CERTIFICATE block (4054), CA cert parse (4055), CA key PEM decode (4056), PKCS#8 key not a `crypto.Signer` (4057), unsupported PKCS#8/PKCS#1/SEC1 key (4058) |

## AUTH

OIDC / JWKS token validation. Distinct prefix from `NRVQ-SIEM-14xxx`.

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-AUTH-14000 | `nrvq.auth.oidc_validated` | `norviq/api/auth.py` |
| NRVQ-AUTH-14001 | `nrvq.auth.oidc_rejected` (bad iss/aud/exp/sig/alg or conflicting ns) | `norviq/api/auth.py` |
| NRVQ-AUTH-14002 | `nrvq.auth.jwks_refreshed` | `norviq/api/jwks.py` |
| NRVQ-AUTH-14003 | `nrvq.auth.jwks_unknown_kid` (after bounded refresh) | `norviq/api/jwks.py` |
| NRVQ-AUTH-14004 | `nrvq.auth.jwks_fetch_failed` (fail-closed) | `norviq/api/jwks.py` |
| NRVQ-AUTH-14005 | `nrvq.auth.legacy_hs256` (migration telemetry) | `norviq/api/auth.py` |
| NRVQ-AUTH-14006 | `nrvq.auth.apikey_failed` (repeated nrvq_ auth failures over threshold) | `norviq/api/api_keys.py` |
| NRVQ-AUTH-14007 | `nrvq.auth.apikey_throttled` (API-key auth attempts throttled after sustained failures) | `norviq/api/api_keys.py` |
| NRVQ-AUTH-14010 | `nrvq.auth.login_ok` (local username/password login succeeded) | `norviq/api/routers/auth_login.py` |
| NRVQ-AUTH-14011 | `nrvq.auth.password_changed` (forced/self-service password change) | `norviq/api/routers/auth_login.py` |
| NRVQ-AUTH-14012 | `nrvq.auth.login_failed` / `login_locked` / `change_password_denied` (bad creds, lockout, wrong current pw) | `norviq/api/routers/auth_login.py` |
| NRVQ-AUTH-14013 | `nrvq.auth.default_admin_seeded` (boot seeded the default admin, must_change=true) | `norviq/api/routers/auth_login.py` |
| NRVQ-AUTH-14014 | `nrvq.auth.default_admin_password` (still on the shipped default password — warn; refuse boot under require_strong_secret) | `norviq/api/main.py` |
| NRVQ-AUTH-14015 | `nrvq.auth.logout_ok` (session token revoked server-side until its own exp) | `norviq/api/routers/auth_login.py` |
| NRVQ-AUTH-14016 | `nrvq.auth.revoked_token_rejected` (a logged-out token was presented — 401 / ws close 1008) | `norviq/api/auth.py` |
| NRVQ-AUTH-14017 | `nrvq.auth.revocation_store_degraded` (Redis denylist write ERROR / read WARNING — in-process mirror still holds the revocation) | `norviq/api/session_revocation.py` |
| NRVQ-AUTH-14018 | `nrvq.auth.must_change_blocked` (a must_change=true token — still on a default/reset password — was refused off the change-password/logout/me paths, 403) | `norviq/api/auth.py` |
| NRVQ-AUTH-14019 | `nrvq.auth.identity_binding_denied` (a bound credential asserted a DIFFERENT `agent_class`/`spiffe_id` on /evaluate — 403; agent_class selects the enforced policy, spiffe_id keys trust + the freeze kill-switch) | `norviq/api/auth.py` |
| NRVQ-AUTH-14020 | `nrvq.auth.identity_unbound_denied` (strict mode `auth_require_bound_agent_identity`: a non-admin credential carrying NO identity binding was refused — 403) | `norviq/api/auth.py` |
| NRVQ-AUTH-14024 | `nrvq.auth.revocation_persist_failed` (ERROR: revocations could not be written to Postgres `revoked_tokens` — refused, or no answer within `timeout_s` seconds (`error=TimeoutError: ...`): 2 for a logout; for `source=redis_import`, entries a process imported from Redis, 30 on the process's first pass and 5 after. A logout's token is already refused everywhere — the mirror and Redis are written before Postgres is tried (unless a 14017 says the Redis write failed too) — and the logout still answers 200. The entries stay queued, without a cap; every sync pass retries them (14027 when they land) and rewrites them into Redis) | `norviq/api/session_revocation.py` |
| NRVQ-AUTH-14025 | `nrvq.auth.revocation_sync_failed` (WARNING: a background sync pass could not read/write Postgres within 5s, `op=store`, with `unpersisted=<n>` queued keys still waiting — the mirror stands as of the last pass, peers' newer logouts still arrive through Redis — or could not write Redis, `op=reconcile_cache`). Also the retry line `nrvq.startup.revocations_load_retry` while startup waits for the store (each attempt bounded at 30s) | `norviq/api/session_revocation.py`, `norviq/api/main.py` |
| NRVQ-AUTH-14026 | `nrvq.auth.revocations_synced` (INFO: `entries` = keys a pass added to this process's memory. At startup, `startup=true`: every live key in Postgres plus any imported from Redis. After that, only when non-zero: keys new to this process since the last pass — peers' logouts, or imports after a Redis loss — with `mirror=<n>`, the keys it now holds) | `norviq/api/main.py`, `norviq/api/session_revocation.py` |
| NRVQ-AUTH-14027 | `nrvq.auth.revocations_persisted_late` (INFO: queued 14024 revocations have now landed in Postgres) | `norviq/api/session_revocation.py` |
| NRVQ-AUTH-14028 | `nrvq.auth.revocation_cache_reseeded` (WARNING: Redis had lost the logout denylist — restart without its RDB, failover to an empty replica, flush, or the first 0.2.6 boot, since 0.2.5 never set the marker — and it was rebuilt from this process's memory. Logged by each process whose pass finds the marker missing, so processes starting or passing at about the same time each log it once; the rewrites are idempotent) | `norviq/api/session_revocation.py` |
| NRVQ-AUTH-14029 | `nrvq.startup.revocations_load_failed` (ERROR: startup REFUSED — the durable revocation set could not be loaded after retries; a pod that served with an empty mirror could accept logged-out tokens) | `norviq/api/main.py` |
| NRVQ-AUTH-14031 | `nrvq.auth.revocations_unpersisted_at_shutdown` (ERROR: an API process shut down with `entries=<n>` logouts Postgres never got, after one last try. They are in Redis, and the next API process to boot imports them into Postgres; until then a Redis data loss would drop them) | `norviq/api/session_revocation.py` |

## FLT

Multi-cluster fleet. Spoke relay + hub fleet-api. Distinct prefix from `NRVQ-AUTH-14xxx`.

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-FLT-15000 | `nrvq.fleet.relay_pushed` / `relay_started` | `norviq/fleet_relay.py` |
| NRVQ-FLT-15001 | `nrvq.fleet.relay_failed` (fire-and-forget, logged only) | `norviq/fleet_relay.py` |
| NRVQ-FLT-15002 | `nrvq.fleet.heartbeat` / `heartbeat_sent` | `norviq/fleet/routers/ingest.py`, `norviq/fleet_relay.py` |
| NRVQ-FLT-15003 | `nrvq.fleet.rollup_received` | `norviq/fleet/routers/ingest.py` |
| NRVQ-FLT-15004 | `nrvq.fleet.clusters_listed` | `norviq/fleet/routers/fleet.py` |
| NRVQ-FLT-15005 | `nrvq.fleet.audit_summary` | `norviq/fleet/routers/fleet.py` |
| NRVQ-FLT-15009 | `nrvq.fleet.cluster_scope_denied` (403) | `norviq/api/auth.py` (`scoped_cluster`) |
| NRVQ-FLT-15010 | `nrvq.fleet.relay_not_configured` (no-op) | `norviq/fleet_relay.py` |
| NRVQ-FLT-15011 | `nrvq.fleet.db_connected` / `started` | `norviq/fleet/db.py`, `norviq/fleet/main.py` |
| NRVQ-FLT-15012 | `nrvq.fleet.not_ready` (503) | `norviq/fleet/routers/health.py` |
| NRVQ-FLT-15013 | `nrvq.fleet.insecure_default_secret` | `norviq/fleet/main.py` |
| NRVQ-FLT-15014 | `nrvq.fleet.stopped` | `norviq/fleet/main.py` |
| NRVQ-FLT-15015 | `nrvq.fleet.bundle_signed` (hub built+signed a bundle) | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15016 | `nrvq.fleet.puller_started` (the bundle puller came up) | `norviq/fleet_puller.py` |
| NRVQ-FLT-15017 | `nrvq.fleet.bundle_not_newer` (replay/rollback rejected) | `norviq/fleet_puller.py` |
| NRVQ-FLT-15018 | `nrvq.fleet.bundle_verify_failed` (tamper/wrong-key/unsigned/wrong-cluster) | `norviq/fleet_puller.py` |
| NRVQ-FLT-15019 | `nrvq.fleet.bundle_expired` / `not_yet_valid` | `norviq/fleet_puller.py` |
| NRVQ-FLT-15020 | `nrvq.fleet.rollout_reported` | `norviq/fleet_puller.py`, `fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15021 | `nrvq.fleet.policy_authored` | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15023 | `nrvq.fleet.policy.reserved_scope` (rejected a fleet push to `__baseline__`/`__pack__` — 422) | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15028, NRVQ-FLT-15029, NRVQ-FLT-15030, NRVQ-FLT-15031, NRVQ-FLT-15032, NRVQ-FLT-15033, NRVQ-FLT-15034, NRVQ-FLT-15035, NRVQ-FLT-15027 | `nrvq.fleet.policy.confirm_required` (fleet-wide push without `confirm_fleet_wide` — 422) | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15022 | `nrvq.fleet.bundle_applied` / `bundle_apply_failed` | `norviq/fleet_puller.py` |
| NRVQ-FLT-15028 | `nrvq.fleet.bundle_retracted` (spoke reconcile deletes a retracted key) | `norviq/fleet_puller.py` |
| NRVQ-FLT-15029 | `nrvq.fleet.policy_retracted` (hub retract endpoint) | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15030 | `nrvq.fleet.join_token_minted` (hub mints a join token) | `norviq/fleet/routers/fleet.py` |
| NRVQ-FLT-15031 | `nrvq.fleet.join_token_claimed` (single-use claim) | `norviq/fleet/routers/fleet.py` |
| NRVQ-FLT-15032 | `nrvq.fleet.cluster_removed` (hub deregister) | `norviq/fleet/routers/fleet.py` |
| NRVQ-FLT-15033 | `nrvq.fleet.join_rejected` (bad/expired token) | `norviq/api/routers/fleet_enroll.py` |
| NRVQ-FLT-15034 | `nrvq.fleet.joined` (spoke enrolled) | `norviq/api/routers/fleet_enroll.py` |
| NRVQ-FLT-15035 | `nrvq.fleet.left` (spoke de-enrolled, sheds pushed policy) | `norviq/api/routers/fleet_enroll.py` |
| NRVQ-FLT-15040 | `nrvq.fleet.console_url_rejected` (a spoke-reported `console_url` with a non-http(s) scheme was blanked on write — stored-XSS defense) | `norviq/fleet/schemas.py` |
| NRVQ-FLT-15041 | `nrvq.fleet.endpoint_rejected` (SSRF: a spoke-reported `endpoint` with a non-http(s) scheme was blanked on write) | `norviq/fleet/schemas.py` |
| NRVQ-FLT-15042 | `nrvq.fleet.drilldown_ssrf_blocked` (SSRF: drill-down refused a cluster `endpoint` resolving to loopback/link-local/private/metadata before minting/dialing) | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15024 | `nrvq.fleet.spiffe_id_changed` (SVID binding change) | `norviq/fleet/routers/ingest.py` |
| NRVQ-FLT-15025 | `nrvq.fleet.drilldown_served` / `drilldown_failed` | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15026 | `nrvq.fleet.drilldown_residency_blocked` | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15043 | `nrvq.fleet.pull_failed` — a bundle pull failed; the fleet member keeps serving its last good bundle, so policy is stale rather than absent | `norviq/fleet_puller.py` |
| NRVQ-FLT-15044 | `nrvq.fleet.puller_no_trust_root` — the puller has no trust root, so bundle signatures cannot be verified. **Alert on this**: it is the precondition for accepting an unsigned bundle | `norviq/fleet_puller.py` |
| NRVQ-FLT-15045 | `nrvq.fleet.bundle_reserved_scope_skipped` — a signed bundle carried a cluster-managed scope (`__baseline__`, `__controls__`, `__pack__*`, `__egress__`, `__mcp__`) and the spoke refused to apply it. **Alert on this**: the hub refuses to author or bundle these, so one reaching a spoke means the hub is old, misconfigured or compromised | `norviq/fleet_puller.py` |

## DB

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-DB-9000 | `nrvq.db.connected` | `norviq/api/db/session.py` |
| NRVQ-DB-9001 | `nrvq.db.tables_created` | `norviq/api/db/session.py` |
| NRVQ-DB-9002 | Two events. `nrvq.db.closed` (normal shutdown) and `nrvq.db.default_partition_skipped` (WARNING — the `audit_log` DEFAULT partition backstop could not be created; best-effort, never fatal) | `norviq/api/db/session.py` |
| NRVQ-DB-9003 | Two events. `nrvq.db.schema_compat_applied` (INFO — additive schema-compat statements ran) and **`nrvq.db.partition_create_failed`** (ERROR — a monthly `audit_log` partition could not be created). See below. | `norviq/api/db/session.py` |
| NRVQ-DB-9010..9028 | cache connect/hit/set/invalidate + token-revocation + per-ns posture mirror + 9028 hashed-policy-key legacy-entry skip | `norviq/engine/cache.py` |
| NRVQ-DB-9030..9031 | cache pubsub listen/receive | `norviq/engine/cache.py` |
| NRVQ-DB-9032 | cache pubsub policy-mutation subscribe (`nrvq.cache.policy_mutations_listening`) | `norviq/engine/cache.py` |
| NRVQ-DB-9034 / 9035 | The API's first Postgres connection (`ping_db`, a `SELECT 1` after `init_db` builds the engine) **exhausted** its backoff / one attempt failed and is being retried. 5 attempts, sleeping 1, 2, 4, 8 s between them: a refused Postgres gives up after about 15 s, then startup fails and the pod restarts. Event names keep the old `nrvq.startup.init_db_retry` / `_failed`. The equivalent pair for the Redis cache connect is `NRVQ-REG-9034` / `NRVQ-REG-9035` (same schedule) — an inconsistent prefix, but that is what the code emits. | `norviq/api/main.py`, `norviq/startup_retry.py` |
| NRVQ-DB-DEBUG-* | startup/connect/create-table diagnostics | `norviq/api/main.py`, `norviq/api/db/session.py` |

### NRVQ-DB-9003 — `nrvq.db.partition_create_failed`

`audit_log` is partitioned by month. Startup provisions a **rolling window** of monthly partitions
(current + look-ahead) plus a `audit_log_default` DEFAULT partition as a backstop, so a write past the
last provisioned month lands somewhere instead of raising.

The one way a monthly `CREATE ... PARTITION OF` legitimately fails: rows for that month already landed
in DEFAULT (look-ahead lapsed), and Postgres refuses to split them out —
*"updated partition constraint for default partition would be violated by some row"*. **Startup does
not brick over it**: writes keep landing in DEFAULT, so no audit data is lost. It is logged loudly
because it needs a human — move those rows out of DEFAULT and re-create the month's partition, or the
table stays unpartitioned for that range and retention pruning gets slower over time.

## ENG

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-ENG-2000 | `nrvq.engine.error` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2001 | `nrvq.engine.allowed` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2002 | `nrvq.engine.escalated` fallback path | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2003 | `nrvq.engine.fallback` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2004 | `nrvq.engine.cache_hit` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2005 | `nrvq.engine.policy_loaded` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2006 | `nrvq.engine.invalid_identity` (invalid SPIFFE id → named fail-closed `invalid_spiffe_identity`) | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2057 | `nrvq.engine.unattributed_block` (a block reached persist with empty/`default_allow` rule_id → clamped to `unattributed_block` + alarm) | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2058 | `nrvq.engine.posture.mirror_unavailable` (per-ns settings mirror read failed → global posture) | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2059 | `nrvq.engine.posture.monitor_softened` (ns audit/monitor mode softened a would-block/escalate to allow-but-log) | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2060 | `nrvq.engine.trust.override_check_failed` (durable trust-cap read failed → no cap, fail-open) | `norviq/engine/trust/calculator.py` |
| NRVQ-ENG-2010 | `nrvq.engine.blocked` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2015 | `nrvq.engine.escalated` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2020 | `nrvq.engine.timeout` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2021 | `nrvq.engine.timeout_fallback` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2030 | `nrvq.engine.policy_hot_reloaded` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2031 | `nrvq.engine.policy_unloaded` (evaluator unload on delete) | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2040..2050 | trust calculator/profile/history/cache codes | `norviq/engine/trust/*`, `norviq/engine/evaluator.py` |
| NRVQ-ENG-2067 | `nrvq.engine.trust.freeze_check_failed` — the trust-freeze check itself errored, so a frozen agent may be scored as if it were not frozen. Split off the 2040..2050 range because that range also carries routine INFO | `norviq/engine/trust/calculator.py` |
| NRVQ-ENG-2068 | `nrvq.engine.baseline.controls_do_not_supersede` — a namespace's saved controls are not exactly what this release compiles from the chart's baseline (another preset, the chart's own rego, or a module an earlier release compiled and the startup re-render has not replaced), so the chart's baseline stays a floor and an Off or Monitor looser than it does not take effect. Check NRVQ-API-7140 / 7141; logged once per pair | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2069 | `nrvq.engine.baseline.supersede_check_failed` — comparing the saved controls with the chart's baseline raised; the chart's baseline is kept as a floor (fail closed) | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2070 | `nrvq.opa.legacy_literals_upgraded` (INFO, once per policy key and stored source) — a policy holds a bare `{}`/`set()`/`[]`/`[][_]` that OPA 1.21 rejects, on a line exactly as a 0.2.5-or-earlier generator wrote it, and that line was compiled as the typed empty form (the same value) instead; `shapes` names which. Only code lines are rewritten, never one inside a raw string, and only in a module carrying that generator's header — or, for `allow_names`/`allow_skeletons` and `cap_tools`, its package (`norviq.intent.*`, `norviq.remediation.capability.*`), so a hand-written line there is rewritten too. The stored row is not modified. Regenerating the policy from its source (builder, intent, MCP registry) stores the current form | `norviq/engine/evaluator.py`, `norviq/engine/empty_literals.py` |
| NRVQ-ENG-2071 | `nrvq.opa.module_rejected` (ERROR, once per policy key and stored source) — OPA refused to compile a policy — a response carrying a compile-stage code (`rego_type_error`, `rego_parse_error`, ...); any other refusal, such as a 413, keeps its own message: `key` is the policy key, `error` is OPA's own message. Every call that policy governs is blocked as `evaluator_error` until it is fixed; this is the line that says which policy and why | `norviq/engine/evaluator.py` |
| NRVQ-ENG-DEBUG-* | OPA I/O and evaluator debug traces | `norviq/engine/evaluator.py` |

## UI

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-UI-4601 | `nrvq.ui.remote_cluster_mutation_blocked` (a cluster-scoped write to the LOCAL api was refused because a REMOTE cluster is the active context — editing applies to the served cluster only) | `ui/src/api/clusterGuard.ts` (enforced in `ui/src/api/client.ts` `apiSend`) |

## SDC — injected sidecar

The enforcement sidecar the webhook injects into agent pods. These are the codes to grep when an agent
pod is up but its tool calls are all failing, or when a pod is stuck `NotReady`.

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-SDC-3000..3005 | `nrvq.sidecar.started` / `connection_error` / `processed` / `audit_error`+`process_error` / `socket_closed` / `stopped` | `norviq/sidecar/proxy.py` |
| NRVQ-SDC-3006 | `nrvq.sidecar.socket_chmod_failed` (WARNING — the UDS permissions could not be tightened) | `norviq/sidecar/proxy.py` |
| NRVQ-SDC-3010..3012 | `nrvq.sidecar.http.processed` / `http.decode_error` (bad or non-object JSON body) / `http.process_error` | `norviq/sidecar/http_fallback.py` |
| **NRVQ-SDC-3013** | `nrvq.sidecar.readyz.opa_unreachable` — `/readyz` could not reach OPA over localhost, so it returns **not-ready**. Because the OPA sidecar binds `127.0.0.1` and carries no kubelet probes, this is the **only** signal that surfaces OPA health to the kubelet. Seeing it means the replica is being drained on purpose, not that the app crashed. | `norviq/sidecar/http_fallback.py` |
| NRVQ-SDC-3020..3024 | `nrvq.sidecar.pubsub_failed` / `policy_reloaded` (a `norviq:policy:invalidated` event re-read the policy from Postgres) / `reload_failed` (ERROR: the re-read failed, or no policy loader is bound; the previous entry is kept) / `pubsub_watcher_started` / `policy_unloaded` (3024: the event named a policy with no row, so it was dropped, which is how a delete reaches the embedded engine) | `norviq/sidecar/proxy.py` |
| NRVQ-SDC-3030 | `nrvq.sidecar.remote_evaluator.ready` (thin proxy wired to the central API) | `norviq/sidecar/remote_evaluator.py` |
| NRVQ-SDC-3031 | `nrvq.sidecar.remote_evaluator.fail_closed` — the call to the central `/evaluate` failed, so the tool call was **blocked**. A burst of these is a control-plane reachability/auth problem (missing or rejected `NRVQ_API_TOKEN`), not a policy decision. | `norviq/sidecar/remote_evaluator.py` |
| NRVQ-SDC-3032 | Two events, both about proxy mode: `nrvq.sidecar.mode.proxy` (startup, with the resolved `api_url`) and `nrvq.sidecar.remote_evaluator.mtls_enabled` (the injected client cert/CA were accepted and internal mTLS is active). Both are startup INFO. **`remote_evaluator.fail_open` was also on this code and is now `NRVQ-SDC-3036`** — a filter written for these two was silencing it | `norviq/sidecar/proxy.py`, `norviq/sidecar/remote_evaluator.py` |
| NRVQ-SDC-3036 | **`nrvq.sidecar.remote_evaluator.fail_open`** — the control plane was unreachable (5xx/timeout/connect error) and `sdk_fallback_mode` is `allow`, so this tool call ran **unjudged** with `rule_id="thin_proxy_fail_open"`. This is the signal that agents are currently ungoverned. Deliberately not on 3032 with the startup INFO lines, because a filter written for those hides it | `norviq/sidecar/remote_evaluator.py` |
| **NRVQ-SDC-3033** | `nrvq.sidecar.mode.embedded` — this workload evaluates **locally** with its own `RedisCache` + OPA + `PolicyLoader` instead of proxying to the central API. Expected on the `norviq-engine` Deployment, which pins `NRVQ_SIDECAR_MODE=embedded`, and on air-gapped/edge injected sidecars. Seeing it on a pod you expected to be a thin proxy means `NRVQ_SIDECAR_MODE` was overridden. | `norviq/sidecar/proxy.py` |
| NRVQ-SDC-3045 / 3046 | Embedded engine startup could not reach a datastore: one attempt failed and is being retried (WARNING, `nrvq.startup.engine_cache_connect_retry` for Redis, `nrvq.sidecar.datastore_retry` with `store=postgres` for the policy warm) / the bounded backoff is **exhausted** and startup fails, so the pod restarts (ERROR, `…_failed` / `nrvq.sidecar.datastore_unreachable`). Same 1, 2, 4, 8 s schedule as the API (about 15 s per store). The Redis connect retries any error, like the API's; the Postgres warm retries only an unreachable store (refused, unresolvable, timed out, Postgres 57P03), so an auth failure or a bad row surfaces at once. | `norviq/sidecar/proxy.py`, `norviq/startup_retry.py` |

## REG / GRP / AUD / RED / TEL / CLI / SDK / IDT

| Component | Codes | Source |
|---|---|---|
| REG | NRVQ-REG-5000..5008, 5010..5023 (5016 includes `nrvq.policy.remote_unloaded`, an API replica dropped a policy because a peer deleted it, or because an upsert event arrived for a row that was already gone (`operation=upsert`); 5022 = `nrvq.policy.reloaded`, the embedded engine re-read a policy from Postgres after a `norviq:policy:invalidated` event, with the `enforcement_mode` it now enforces; **5023** = `nrvq.policy.reload_unloaded`, INFO — that event named a policy with no row, so the engine dropped it, as a cold start would; `delete()` publishes the event for this, and `was_loaded=false` means there was nothing to drop. A Postgres error is never read as a missing row: it surfaces as NRVQ-SDC-3022 and the entry is kept); plus NRVQ-REG-9034/9035 (Redis cache-connect backoff exhausted / retrying — see the DB note above) | `norviq/engine/policy_loader.py`, `norviq/api/main.py` |
| GRP | NRVQ-GRP-11000, 11001, 11010..11017 (11017 = `nrvq.engine.graph.restored`, the lazy snapshot restore that survives a pod restart) | `norviq/engine/graph/*`, `norviq/engine/evaluator.py` |
| AUD | NRVQ-AUD-6000..6008 | `norviq/engine/audit_emitter.py`, `norviq/engine/evaluator.py` |
| AUD (retention) | NRVQ-AUD-6009 (`nrvq.retention.started`), 6010 (`nrvq.retention.pruned`), 6012 (`nrvq.retention.prune_failed`), 6013 (`nrvq.retention.step_failed` — one table's prune isolated-failed) | `norviq/api/audit_retention.py` (unified background retention pruner) |
| RED | NRVQ-RED-13000..13009 (13007 = `nrvq.redteam.persist_failed`, 13008 = `suite_concurrent_rejected` (the process-wide `redteam_suite_global_concurrency` cap), 13009 = `nrvq.redteam.retention`) | `norviq/redteam/*`, `norviq/api/routers/redteam.py` |
| TEL | NRVQ-TEL-12000..12007 | `norviq/telemetry/*` |
| CLI | NRVQ-CLI-8000..8004 | `norviq/cli/*` |
| SDK | NRVQ-SDK-1000, 1002, 1010..1013, 1020..1022, 1030..1032 (langchain), 1040..1044 (langgraph), 1050..1053 (crewai), 1060..1063 (autogen), 1070..1073 (semantic-kernel). 1043/1073 = output-DLP redaction (opt-in); 1044/1053/1063 = the `protect()` fail-closed-by-default warning on `allow_unwrapped=True`. | `norviq/sdk/*` |
| IDT | NRVQ-IDT-10000..10006 | `norviq/engine/identity.py` |
| AUTH | NRVQ-AUTH-14000..14007, 14010..14029, 14031 (14024..14029 and 14031: durable logout revocation) | `norviq/api/auth.py`, `norviq/api/jwks.py`, `norviq/api/routers/auth_login.py`, `norviq/api/main.py`, `norviq/api/session_revocation.py` |
| FLT | NRVQ-FLT-15000..15005, 15009..15035, 15040..15042 | `norviq/fleet/*`, `norviq/fleet_relay.py`, `norviq/fleet_puller.py` |

## Full Code Index

Every `NRVQ-*` literal present in `norviq/**/*.py`, `webhook/*.go` and `ui/src/**` (test files
excluded), grouped by component. Regenerate by grepping those trees — this list is the check that a
newly added code got documented above.

```text
NRVQ-API-7000, NRVQ-API-7001, NRVQ-API-7002, NRVQ-API-7010, NRVQ-API-7011, NRVQ-API-7012, NRVQ-API-7013,
NRVQ-API-7014, NRVQ-API-7015, NRVQ-API-7016, NRVQ-API-7017, NRVQ-API-7018, NRVQ-API-7019, NRVQ-API-7020,
NRVQ-API-7021, NRVQ-API-7022, NRVQ-API-7023, NRVQ-API-7024, NRVQ-API-7030, NRVQ-API-7031, NRVQ-API-7032,
NRVQ-API-7033, NRVQ-API-7034, NRVQ-API-7035, NRVQ-API-7040, NRVQ-API-7041, NRVQ-API-7050, NRVQ-API-7050-ERR,
NRVQ-API-7051, NRVQ-API-7051-ERR, NRVQ-API-7052, NRVQ-API-7060, NRVQ-API-7060-ERR, NRVQ-API-7061,
NRVQ-API-7062, NRVQ-API-7063, NRVQ-API-7064, NRVQ-API-7070, NRVQ-API-7070-ERR, NRVQ-API-7071, NRVQ-API-7072,
NRVQ-API-7073, NRVQ-API-7074, NRVQ-API-7075, NRVQ-API-7076, NRVQ-API-7077, NRVQ-API-7078, NRVQ-API-7079,
NRVQ-API-7080, NRVQ-API-7081, NRVQ-API-7081-ERR, NRVQ-API-7082, NRVQ-API-7083, NRVQ-API-7084, NRVQ-API-7085,
NRVQ-API-7086, NRVQ-API-7087, NRVQ-API-7090, NRVQ-API-7091, NRVQ-API-7092, NRVQ-API-7093, NRVQ-API-7094,
NRVQ-API-7095, NRVQ-API-7096, NRVQ-API-7097, NRVQ-API-7098, NRVQ-API-7099, NRVQ-API-7100, NRVQ-API-7101,
NRVQ-API-7102, NRVQ-API-7103, NRVQ-API-7104, NRVQ-API-7105, NRVQ-API-7110, NRVQ-API-7111, NRVQ-API-7112,
NRVQ-API-7113, NRVQ-API-7114, NRVQ-API-7115, NRVQ-API-7120, NRVQ-API-7121, NRVQ-API-7122, NRVQ-API-7123,
NRVQ-API-7124, NRVQ-API-7132, NRVQ-API-7136, NRVQ-API-7137, NRVQ-API-7138, NRVQ-API-7133, NRVQ-API-7134, NRVQ-API-7135, NRVQ-API-7143, NRVQ-API-7144, NRVQ-API-7145, NRVQ-API-7146, NRVQ-API-7147, NRVQ-API-7158, NRVQ-API-7159, NRVQ-API-7460

NRVQ-WHK-4000, NRVQ-WHK-4001, NRVQ-WHK-4002, NRVQ-WHK-4003, NRVQ-WHK-4004, NRVQ-WHK-4005, NRVQ-WHK-4006,
NRVQ-WHK-4007, NRVQ-WHK-4008, NRVQ-WHK-4009, NRVQ-WHK-4010, NRVQ-WHK-4011, NRVQ-WHK-4012, NRVQ-WHK-4013,
NRVQ-WHK-4014, NRVQ-WHK-4015, NRVQ-WHK-4020, NRVQ-WHK-4021, NRVQ-WHK-4022, NRVQ-WHK-4023, NRVQ-WHK-4024,
NRVQ-WHK-4025, NRVQ-WHK-4026, NRVQ-WHK-4027, NRVQ-WHK-4028, NRVQ-WHK-4029, NRVQ-WHK-4030, NRVQ-WHK-4031,
NRVQ-WHK-4032, NRVQ-WHK-4033, NRVQ-WHK-4034, NRVQ-WHK-4035, NRVQ-WHK-4036, NRVQ-WHK-4037, NRVQ-WHK-4038,
NRVQ-WHK-4039, NRVQ-WHK-4040, NRVQ-WHK-4041, NRVQ-WHK-4042, NRVQ-WHK-4043, NRVQ-WHK-4044, NRVQ-WHK-4045,
NRVQ-WHK-4046, NRVQ-WHK-4047, NRVQ-WHK-4048, NRVQ-WHK-4049, NRVQ-WHK-4050, NRVQ-WHK-4051, NRVQ-WHK-4052,
NRVQ-WHK-4053, NRVQ-WHK-4054, NRVQ-WHK-4055, NRVQ-WHK-4056, NRVQ-WHK-4057, NRVQ-WHK-4058,
NRVQ-WHK-4059

NRVQ-ENG-DEBUG-1, NRVQ-ENG-DEBUG-2, NRVQ-ENG-DEBUG-3, NRVQ-ENG-DEBUG-4, NRVQ-ENG-DEBUG-5, NRVQ-ENG-2000,
NRVQ-ENG-2001, NRVQ-ENG-2002, NRVQ-ENG-2003, NRVQ-ENG-2004, NRVQ-ENG-2005, NRVQ-ENG-2006, NRVQ-ENG-2010,
NRVQ-ENG-2015, NRVQ-ENG-2020, NRVQ-ENG-2021, NRVQ-ENG-2030, NRVQ-ENG-2031, NRVQ-ENG-2040, NRVQ-ENG-2041,
NRVQ-ENG-2042, NRVQ-ENG-2043, NRVQ-ENG-2044, NRVQ-ENG-2045, NRVQ-ENG-2046, NRVQ-ENG-2047, NRVQ-ENG-2048,
NRVQ-ENG-2049, NRVQ-ENG-2050, NRVQ-ENG-2051, NRVQ-ENG-2052, NRVQ-ENG-2053, NRVQ-ENG-2054, NRVQ-ENG-2055,
NRVQ-ENG-2056, NRVQ-ENG-2057, NRVQ-ENG-2058, NRVQ-ENG-2059, NRVQ-ENG-2060, NRVQ-ENG-2070, NRVQ-ENG-2071,
NRVQ-ENG-DEBUG-ERR,
NRVQ-ENG-DEBUG-INPUT, NRVQ-ENG-DEBUG-OPA, NRVQ-ENG-DEBUG-OPA-IN, NRVQ-ENG-DEBUG-QUERY

NRVQ-DB-DEBUG-1, NRVQ-DB-DEBUG-2, NRVQ-DB-DEBUG-2-ERR, NRVQ-DB-DEBUG-2A, NRVQ-DB-DEBUG-2B, NRVQ-DB-DEBUG-2C,
NRVQ-DB-DEBUG-2D, NRVQ-DB-DEBUG-5, NRVQ-DB-DEBUG-6, NRVQ-DB-9000,
NRVQ-DB-9001, NRVQ-DB-9002, NRVQ-DB-9003, NRVQ-DB-9010, NRVQ-DB-9011, NRVQ-DB-9012, NRVQ-DB-9013,
NRVQ-DB-9014, NRVQ-DB-9015, NRVQ-DB-9016, NRVQ-DB-9017, NRVQ-DB-9018, NRVQ-DB-9019, NRVQ-DB-9020,
NRVQ-DB-9021, NRVQ-DB-9022, NRVQ-DB-9023, NRVQ-DB-9024, NRVQ-DB-9025, NRVQ-DB-9026, NRVQ-DB-9027,
NRVQ-DB-9028, NRVQ-DB-9030, NRVQ-DB-9031, NRVQ-DB-9032, NRVQ-DB-9034, NRVQ-DB-9035,
NRVQ-DB-DEBUG-CONNECT-ARGS, NRVQ-DB-DEBUG-METADATA

NRVQ-FLT-15000, NRVQ-FLT-15001, NRVQ-FLT-15002, NRVQ-FLT-15003, NRVQ-FLT-15004, NRVQ-FLT-15005,
NRVQ-FLT-15009, NRVQ-FLT-15010, NRVQ-FLT-15011, NRVQ-FLT-15012, NRVQ-FLT-15013, NRVQ-FLT-15014,
NRVQ-FLT-15015, NRVQ-FLT-15016, NRVQ-FLT-15017, NRVQ-FLT-15018, NRVQ-FLT-15019, NRVQ-FLT-15020,
NRVQ-FLT-15021, NRVQ-FLT-15022, NRVQ-FLT-15023, NRVQ-FLT-15024, NRVQ-FLT-15025, NRVQ-FLT-15026,
NRVQ-FLT-15027, NRVQ-FLT-15028, NRVQ-FLT-15029, NRVQ-FLT-15030, NRVQ-FLT-15031, NRVQ-FLT-15032,
NRVQ-FLT-15033, NRVQ-FLT-15034, NRVQ-FLT-15035, NRVQ-FLT-15040, NRVQ-FLT-15041, NRVQ-FLT-15042

NRVQ-SDK-1000, NRVQ-SDK-1002, NRVQ-SDK-1010, NRVQ-SDK-1011, NRVQ-SDK-1012, NRVQ-SDK-1013, NRVQ-SDK-1020,
NRVQ-SDK-1021, NRVQ-SDK-1022, NRVQ-SDK-1030, NRVQ-SDK-1031, NRVQ-SDK-1032, NRVQ-SDK-1040, NRVQ-SDK-1041,
NRVQ-SDK-1042, NRVQ-SDK-1043, NRVQ-SDK-1044, NRVQ-SDK-1050, NRVQ-SDK-1051, NRVQ-SDK-1052, NRVQ-SDK-1053,
NRVQ-SDK-1060, NRVQ-SDK-1061, NRVQ-SDK-1062, NRVQ-SDK-1063, NRVQ-SDK-1070, NRVQ-SDK-1071, NRVQ-SDK-1072,
NRVQ-SDK-1073

NRVQ-REG-5000, NRVQ-REG-5001, NRVQ-REG-5002, NRVQ-REG-5003, NRVQ-REG-5004, NRVQ-REG-5005, NRVQ-REG-5006,
NRVQ-REG-5007, NRVQ-REG-5008, NRVQ-REG-5010, NRVQ-REG-5011, NRVQ-REG-5012, NRVQ-REG-5013, NRVQ-REG-5014,
NRVQ-REG-5015, NRVQ-REG-5016, NRVQ-REG-5017, NRVQ-REG-5018, NRVQ-REG-5019, NRVQ-REG-5020, NRVQ-REG-5021,
NRVQ-REG-5022, NRVQ-REG-5023, NRVQ-REG-9034, NRVQ-REG-9035

NRVQ-SDC-3000, NRVQ-SDC-3001, NRVQ-SDC-3002, NRVQ-SDC-3003, NRVQ-SDC-3004, NRVQ-SDC-3005, NRVQ-SDC-3006,
NRVQ-SDC-3010, NRVQ-SDC-3011, NRVQ-SDC-3012, NRVQ-SDC-3013, NRVQ-SDC-3020, NRVQ-SDC-3021, NRVQ-SDC-3022,
NRVQ-SDC-3023, NRVQ-SDC-3024, NRVQ-SDC-3030, NRVQ-SDC-3031, NRVQ-SDC-3032, NRVQ-SDC-3036, NRVQ-SDC-3033,
NRVQ-SDC-3045, NRVQ-SDC-3046

NRVQ-AUTH-14000, NRVQ-AUTH-14001, NRVQ-AUTH-14002, NRVQ-AUTH-14003, NRVQ-AUTH-14004, NRVQ-AUTH-14005,
NRVQ-AUTH-14006, NRVQ-AUTH-14007, NRVQ-AUTH-14010, NRVQ-AUTH-14011, NRVQ-AUTH-14012, NRVQ-AUTH-14013,
NRVQ-AUTH-14014, NRVQ-AUTH-14015, NRVQ-AUTH-14016, NRVQ-AUTH-14017, NRVQ-AUTH-14018, NRVQ-AUTH-14019, NRVQ-AUTH-14020,
NRVQ-AUTH-14024, NRVQ-AUTH-14025, NRVQ-AUTH-14026, NRVQ-AUTH-14027, NRVQ-AUTH-14028, NRVQ-AUTH-14029,
NRVQ-AUTH-14031

NRVQ-AUD-6000, NRVQ-AUD-6001, NRVQ-AUD-6002, NRVQ-AUD-6003, NRVQ-AUD-6004, NRVQ-AUD-6005, NRVQ-AUD-6006,
NRVQ-AUD-6007, NRVQ-AUD-6008, NRVQ-AUD-6009, NRVQ-AUD-6010, NRVQ-AUD-6012, NRVQ-AUD-6013

NRVQ-GRP-11000, NRVQ-GRP-11001, NRVQ-GRP-11010, NRVQ-GRP-11011, NRVQ-GRP-11012, NRVQ-GRP-11013,
NRVQ-GRP-11014, NRVQ-GRP-11015, NRVQ-GRP-11016, NRVQ-GRP-11017

NRVQ-RED-13000, NRVQ-RED-13001, NRVQ-RED-13002, NRVQ-RED-13003, NRVQ-RED-13004, NRVQ-RED-13005,
NRVQ-RED-13006, NRVQ-RED-13007, NRVQ-RED-13008, NRVQ-RED-13009

NRVQ-TEL-12000, NRVQ-TEL-12001, NRVQ-TEL-12002, NRVQ-TEL-12003, NRVQ-TEL-12004, NRVQ-TEL-12005,
NRVQ-TEL-12006, NRVQ-TEL-12007

NRVQ-IDT-10000, NRVQ-IDT-10001, NRVQ-IDT-10002, NRVQ-IDT-10003, NRVQ-IDT-10004, NRVQ-IDT-10005,
NRVQ-IDT-10006

NRVQ-CLI-8000, NRVQ-CLI-8001, NRVQ-CLI-8002, NRVQ-CLI-8003, NRVQ-CLI-8004

NRVQ-SIEM-14000, NRVQ-SIEM-14001, NRVQ-SIEM-14002

NRVQ-UI-4601
```
