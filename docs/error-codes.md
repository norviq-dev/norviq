# Norviq Error Codes

Every structured log line carries a stable `code="NRVQ-<COMPONENT>-<n>"` field. Grep for the code, not
the message text — messages get reworded, codes don't.

Codes come from log/error literals in `norviq/**/*.py` (control plane, engine, sidecar, SDK, CLI),
`webhook/*.go` (the Go admission webhook + CRD controller), and `ui/src/**` (one console-side guard).

A code is a **stable identifier for a situation, not a 1:1 alias for one message**. A handful are
reused across two related events (noted inline below) — `NRVQ-DB-9002`, `NRVQ-DB-9003`,
`NRVQ-API-7099` and `NRVQ-SDC-3032` are the ones most likely to surprise you.

`*-DEBUG-*` codes are development traces, not operator signals; they are listed in the index but not
individually described.

## Registry Summary

| Component | Unique Codes | Primary Sources |
|---|---:|---|
| API | 85 | `norviq/api/main.py`, `norviq/api/routers/*` |
| WHK | 55 | `webhook/main.go`, `webhook/handler.go`, `webhook/controller.go`, `webhook/injector.go` |
| ENG | 44 | `norviq/engine/evaluator.py`, `norviq/engine/trust/*`, `norviq/engine/opa_client.py` |
| DB | 42 | `norviq/api/db/session.py`, `norviq/engine/cache.py`, `norviq/api/main.py` |
| FLT | 36 | `norviq/fleet/*`, `norviq/fleet_relay.py`, `norviq/fleet_puller.py` |
| SDK | 29 | `norviq/sdk/*` |
| REG | 23 | `norviq/engine/policy_loader.py` |
| SDC | 19 | `norviq/sidecar/*` |
| AUTH | 17 | `norviq/api/auth.py`, `norviq/api/jwks.py`, `norviq/api/routers/auth_login.py` |
| AUD | 13 | `norviq/engine/audit_emitter.py`, `norviq/api/audit_retention.py` |
| GRP | 10 | `norviq/engine/graph/*` |
| RED | 10 | `norviq/redteam/*`, `norviq/api/routers/redteam.py` |
| TEL | 8 | `norviq/telemetry/*` |
| IDT | 7 | `norviq/engine/identity.py` |
| CLI | 5 | `norviq/cli/main.py`, `norviq/cli/api_client.py` |
| SIEM | 3 | `norviq/api/siem.py` |
| UI | 1 | `ui/src/api/clusterGuard.ts` |

Total unique codes: **407** (including `*-DEBUG-*` traces).

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
| NRVQ-API-7020 | `nrvq.api.audit.listed`; also `nrvq.api.deployments.listed` and `nrvq.api.policy.priority_band_denied` (a write tried to claim a priority band it isn't allowed to) | `norviq/api/routers/audit.py`, `norviq/api/routers/deployments.py`, `norviq/api/routers/policies.py` |
| NRVQ-API-7021 | `nrvq.api.audit.stats` | `norviq/api/routers/audit.py` |
| NRVQ-API-7022 | `nrvq.api.audit.top_blocked` | `norviq/api/routers/audit.py` |
| NRVQ-API-7023 | `nrvq.api.audit.volume` | `norviq/api/routers/audit.py` |
| NRVQ-API-7030 | `nrvq.api.agents.listed` | `norviq/api/routers/agents.py` |
| NRVQ-API-7031 | `nrvq.api.agent.trust_updated`; also `nrvq.api.agent.trust_persist_failed` | `norviq/api/routers/agents.py` |
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
| NRVQ-API-7080 | `nrvq.api.cluster_info.served` (live cluster+namespaces); also **`nrvq.api.rate_limit.fail_open`** — Redis was unreachable so the HTTP rate limiter let the request through (availability over strictness; log-throttled to once per 30s) — and `nrvq.api.mitre.generate_no_classes` | `norviq/api/routers/cluster_info.py`, `norviq/api/rate_limit.py`, `norviq/api/routers/mitre.py` |
| NRVQ-API-7081 | `nrvq.api.coverage.served` (coverage-by-category); also **`nrvq.api.rate_limit.exceeded`** — the HTTP-layer throttle returned **429** for this route class — and `nrvq.api.mitre.generate_batch` | `norviq/api/routers/coverage.py`, `norviq/api/rate_limit.py`, `norviq/api/routers/mitre.py` |
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
| NRVQ-API-7063 | `nrvq.api.settings.warmed` / `settings.mirror_failed` (per-ns posture mirror warm/write) | `norviq/api/routers/settings_router.py` |
| NRVQ-API-7115 | `nrvq.api.search.served` (scoped ⌘K search across tools/agents/policies) | `norviq/api/routers/search.py` |
| NRVQ-API-7121 | `nrvq.api.agent.deregistered` (admin removed a decommissioned agent identity from the registry) | `norviq/api/routers/agents.py` |
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
| NRVQ-API-7033 | `nrvq.api.agent.registry_read_failed` / `agent.trust_persist_failed` / `agents.last_seen_failed` (degraded registry writes; read paths still serve) | `norviq/api/routers/agents.py` |
| NRVQ-API-7034 / 7035 | `nrvq.api.agent.overrides_warmed` / `overrides_warm_failed` (durable trust-override cache warm at boot and on write) | `norviq/api/routers/agents.py`, `norviq/api/main.py` |
| NRVQ-API-7040 / 7041 | `nrvq.api.ws_audit.open` / `close` (live audit WebSocket) | `norviq/api/main.py` |
| NRVQ-API-7050 | also `nrvq.api.body_too_large` (request body over `max_request_body_bytes`, 256 KiB — rejected before parsing) | `norviq/api/body_limit.py` |
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
| NRVQ-FLT-15016 | `nrvq.fleet.puller_started` / `pull_failed` / `puller_no_trust_root` | `norviq/fleet_puller.py` |
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

## DB

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-DB-9000 | `nrvq.db.connected` | `norviq/api/db/session.py` |
| NRVQ-DB-9001 | `nrvq.db.tables_created` | `norviq/api/db/session.py` |
| NRVQ-DB-9002 | Two events. `nrvq.db.closed` (normal shutdown) and `nrvq.db.default_partition_skipped` (WARNING — the `audit_log` DEFAULT partition backstop could not be created; best-effort, never fatal) | `norviq/api/db/session.py` |
| NRVQ-DB-9003 | Two events. `nrvq.db.schema_compat_applied` (INFO — additive schema-compat statements ran) and **`nrvq.db.partition_create_failed`** (ERROR — a monthly `audit_log` partition could not be created). See below. | `norviq/api/db/session.py` |
| NRVQ-DB-9010..9028 | cache connect/hit/set/invalidate + token-revocation + per-ns posture mirror + 9028 hashed-policy-key legacy-entry skip | `norviq/engine/cache.py` |
| NRVQ-DB-9030..9031 | cache pubsub listen/receive | `norviq/engine/cache.py` |
| NRVQ-DB-9032..9033 | migration applied/failed | `norviq/api/main.py` |
| NRVQ-DB-9034 / 9035 | `init_db` connect **exhausted** its backoff / a single connect attempt is being retried. The equivalent pair for the Redis cache connect is `NRVQ-REG-9034` / `NRVQ-REG-9035` — an inconsistent prefix, but that is what the code emits. | `norviq/api/main.py` |
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
| NRVQ-SDC-3020..3023 | `nrvq.sidecar.pubsub_failed` / `policy_reloaded` / `reload_failed` / `pubsub_watcher_started` | `norviq/sidecar/proxy.py` |
| NRVQ-SDC-3030 | `nrvq.sidecar.remote_evaluator.ready` (thin proxy wired to the central API) | `norviq/sidecar/remote_evaluator.py` |
| NRVQ-SDC-3031 | `nrvq.sidecar.remote_evaluator.fail_closed` — the call to the central `/evaluate` failed, so the tool call was **blocked**. A burst of these is a control-plane reachability/auth problem (missing or rejected `NRVQ_API_TOKEN`), not a policy decision. | `norviq/sidecar/remote_evaluator.py` |
| NRVQ-SDC-3032 | Two events, both about proxy mode: `nrvq.sidecar.mode.proxy` (startup, with the resolved `api_url`) and `nrvq.sidecar.remote_evaluator.mtls_enabled` (the injected client cert/CA were accepted and internal mTLS is active) | `norviq/sidecar/proxy.py`, `norviq/sidecar/remote_evaluator.py` |
| **NRVQ-SDC-3033** | `nrvq.sidecar.mode.embedded` — this workload evaluates **locally** with its own `RedisCache` + OPA + `PolicyLoader` instead of proxying to the central API. Expected on the `norviq-engine` Deployment, which pins `NRVQ_SIDECAR_MODE=embedded`, and on air-gapped/edge injected sidecars. Seeing it on a pod you expected to be a thin proxy means `NRVQ_SIDECAR_MODE` was overridden. | `norviq/sidecar/proxy.py` |

## REG / GRP / AUD / RED / TEL / CLI / SDK / IDT

| Component | Codes | Source |
|---|---|---|
| REG | NRVQ-REG-5000..5008, 5010..5021; plus NRVQ-REG-9034/9035 (Redis cache-connect backoff exhausted / retrying — see the DB note above) | `norviq/engine/policy_loader.py`, `norviq/api/main.py` |
| GRP | NRVQ-GRP-11000, 11001, 11010..11017 (11017 = `nrvq.engine.graph.restored`, the lazy snapshot restore that survives a pod restart) | `norviq/engine/graph/*`, `norviq/engine/evaluator.py` |
| AUD | NRVQ-AUD-6000..6008 | `norviq/engine/audit_emitter.py`, `norviq/engine/evaluator.py` |
| AUD (retention) | NRVQ-AUD-6009 (`nrvq.retention.started`), 6010 (`nrvq.retention.pruned`), 6012 (`nrvq.retention.prune_failed`), 6013 (`nrvq.retention.step_failed` — one table's prune isolated-failed) | `norviq/api/audit_retention.py` (unified background retention pruner) |
| RED | NRVQ-RED-13000..13009 (13007 = `nrvq.redteam.persist_failed`, 13008 = `suite_concurrent_rejected` (the process-wide `redteam_suite_global_concurrency` cap), 13009 = `nrvq.redteam.retention`) | `norviq/redteam/*`, `norviq/api/routers/redteam.py` |
| TEL | NRVQ-TEL-12000..12007 | `norviq/telemetry/*` |
| CLI | NRVQ-CLI-8000..8004 | `norviq/cli/*` |
| SDK | NRVQ-SDK-1000, 1002, 1010..1013, 1020..1022, 1030..1032 (langchain), 1040..1044 (langgraph), 1050..1053 (crewai), 1060..1063 (autogen), 1070..1073 (semantic-kernel). 1043/1073 = output-DLP redaction (opt-in); 1044/1053/1063 = the `protect()` fail-closed-by-default warning on `allow_unwrapped=True`. | `norviq/sdk/*` |
| IDT | NRVQ-IDT-10000..10006 | `norviq/engine/identity.py` |
| AUTH | NRVQ-AUTH-14000..14007, 14010..14018 | `norviq/api/auth.py`, `norviq/api/jwks.py`, `norviq/api/routers/auth_login.py`, `norviq/api/main.py` |
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
NRVQ-API-7124, NRVQ-API-7460

NRVQ-WHK-4000, NRVQ-WHK-4001, NRVQ-WHK-4002, NRVQ-WHK-4003, NRVQ-WHK-4004, NRVQ-WHK-4005, NRVQ-WHK-4006,
NRVQ-WHK-4007, NRVQ-WHK-4008, NRVQ-WHK-4009, NRVQ-WHK-4010, NRVQ-WHK-4011, NRVQ-WHK-4012, NRVQ-WHK-4013,
NRVQ-WHK-4014, NRVQ-WHK-4015, NRVQ-WHK-4020, NRVQ-WHK-4021, NRVQ-WHK-4022, NRVQ-WHK-4023, NRVQ-WHK-4024,
NRVQ-WHK-4025, NRVQ-WHK-4026, NRVQ-WHK-4027, NRVQ-WHK-4028, NRVQ-WHK-4029, NRVQ-WHK-4030, NRVQ-WHK-4031,
NRVQ-WHK-4032, NRVQ-WHK-4033, NRVQ-WHK-4034, NRVQ-WHK-4035, NRVQ-WHK-4036, NRVQ-WHK-4037, NRVQ-WHK-4038,
NRVQ-WHK-4039, NRVQ-WHK-4040, NRVQ-WHK-4041, NRVQ-WHK-4042, NRVQ-WHK-4043, NRVQ-WHK-4044, NRVQ-WHK-4045,
NRVQ-WHK-4046, NRVQ-WHK-4047, NRVQ-WHK-4048, NRVQ-WHK-4049, NRVQ-WHK-4050, NRVQ-WHK-4051, NRVQ-WHK-4052,
NRVQ-WHK-4053, NRVQ-WHK-4054, NRVQ-WHK-4055, NRVQ-WHK-4056, NRVQ-WHK-4057, NRVQ-WHK-4058

NRVQ-ENG-DEBUG-1, NRVQ-ENG-DEBUG-2, NRVQ-ENG-DEBUG-3, NRVQ-ENG-DEBUG-4, NRVQ-ENG-DEBUG-5, NRVQ-ENG-2000,
NRVQ-ENG-2001, NRVQ-ENG-2002, NRVQ-ENG-2003, NRVQ-ENG-2004, NRVQ-ENG-2005, NRVQ-ENG-2006, NRVQ-ENG-2010,
NRVQ-ENG-2015, NRVQ-ENG-2020, NRVQ-ENG-2021, NRVQ-ENG-2030, NRVQ-ENG-2031, NRVQ-ENG-2040, NRVQ-ENG-2041,
NRVQ-ENG-2042, NRVQ-ENG-2043, NRVQ-ENG-2044, NRVQ-ENG-2045, NRVQ-ENG-2046, NRVQ-ENG-2047, NRVQ-ENG-2048,
NRVQ-ENG-2049, NRVQ-ENG-2050, NRVQ-ENG-2051, NRVQ-ENG-2052, NRVQ-ENG-2053, NRVQ-ENG-2054, NRVQ-ENG-2055,
NRVQ-ENG-2056, NRVQ-ENG-2057, NRVQ-ENG-2058, NRVQ-ENG-2059, NRVQ-ENG-2060, NRVQ-ENG-DEBUG-ERR,
NRVQ-ENG-DEBUG-INPUT, NRVQ-ENG-DEBUG-OPA, NRVQ-ENG-DEBUG-OPA-IN, NRVQ-ENG-DEBUG-QUERY

NRVQ-DB-DEBUG-1, NRVQ-DB-DEBUG-2, NRVQ-DB-DEBUG-2-ERR, NRVQ-DB-DEBUG-2A, NRVQ-DB-DEBUG-2B, NRVQ-DB-DEBUG-2C,
NRVQ-DB-DEBUG-2D, NRVQ-DB-DEBUG-3, NRVQ-DB-DEBUG-4, NRVQ-DB-DEBUG-5, NRVQ-DB-DEBUG-6, NRVQ-DB-9000,
NRVQ-DB-9001, NRVQ-DB-9002, NRVQ-DB-9003, NRVQ-DB-9010, NRVQ-DB-9011, NRVQ-DB-9012, NRVQ-DB-9013,
NRVQ-DB-9014, NRVQ-DB-9015, NRVQ-DB-9016, NRVQ-DB-9017, NRVQ-DB-9018, NRVQ-DB-9019, NRVQ-DB-9020,
NRVQ-DB-9021, NRVQ-DB-9022, NRVQ-DB-9023, NRVQ-DB-9024, NRVQ-DB-9025, NRVQ-DB-9026, NRVQ-DB-9027,
NRVQ-DB-9028, NRVQ-DB-9030, NRVQ-DB-9031, NRVQ-DB-9032, NRVQ-DB-9033, NRVQ-DB-9034, NRVQ-DB-9035,
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
NRVQ-REG-9034, NRVQ-REG-9035

NRVQ-SDC-3000, NRVQ-SDC-3001, NRVQ-SDC-3002, NRVQ-SDC-3003, NRVQ-SDC-3004, NRVQ-SDC-3005, NRVQ-SDC-3006,
NRVQ-SDC-3010, NRVQ-SDC-3011, NRVQ-SDC-3012, NRVQ-SDC-3013, NRVQ-SDC-3020, NRVQ-SDC-3021, NRVQ-SDC-3022,
NRVQ-SDC-3023, NRVQ-SDC-3030, NRVQ-SDC-3031, NRVQ-SDC-3032, NRVQ-SDC-3033

NRVQ-AUTH-14000, NRVQ-AUTH-14001, NRVQ-AUTH-14002, NRVQ-AUTH-14003, NRVQ-AUTH-14004, NRVQ-AUTH-14005,
NRVQ-AUTH-14006, NRVQ-AUTH-14007, NRVQ-AUTH-14010, NRVQ-AUTH-14011, NRVQ-AUTH-14012, NRVQ-AUTH-14013,
NRVQ-AUTH-14014, NRVQ-AUTH-14015, NRVQ-AUTH-14016, NRVQ-AUTH-14017, NRVQ-AUTH-14018

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
