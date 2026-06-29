# Norviq Error Codes

Generated from `norviq/**/*.py` log/error code literals (`NRVQ-*`).

## Registry Summary

| Component | Unique Codes | Primary Sources |
|---|---:|---|
| API | 23 | `norviq/api/main.py`, `norviq/api/routers/*` |
| AUD | 9 | `norviq/engine/audit_emitter.py` |
| AUTH | 6 | `norviq/api/auth.py`, `norviq/api/jwks.py` |
| FLT | 23 | `norviq/fleet/*`, `norviq/fleet_relay.py`, `norviq/fleet_puller.py` |
| CLI | 5 | `norviq/cli/main.py`, `norviq/cli/api_client.py` |
| DB | 34 | `norviq/api/db/session.py`, `norviq/engine/cache.py`, `norviq/api/main.py` |
| ENG | 36 | `norviq/engine/evaluator.py`, `norviq/engine/trust/*`, `norviq/engine/opa_client.py` |
| GRP | 9 | `norviq/engine/graph/*` |
| IDT | 7 | `norviq/engine/identity.py` |
| RED | 6 | `norviq/redteam/*`, `norviq/api/routers/redteam.py` |
| REG | 15 | `norviq/engine/policy_loader.py` |
| SDC | 12 | `norviq/sidecar/*` |
| SDK | 15 | `norviq/sdk/*` |
| SIEM | 3 | `norviq/api/siem.py` |
| TEL | 8 | `norviq/telemetry/*` |

Total documented unique codes: **211**

## API

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-API-7000 | `nrvq.api.started` | `norviq/api/main.py` |
| NRVQ-API-7001 | `nrvq.api.stopped` | `norviq/api/main.py` |
| NRVQ-API-7010 | `nrvq.api.policies.listed` | `norviq/api/routers/policies.py` |
| NRVQ-API-7011 | `nrvq.api.policy.saved` | `norviq/api/routers/policies.py` |
| NRVQ-API-7012 | `nrvq.api.policy.deleted` | `norviq/api/routers/policies.py` |
| NRVQ-API-7013 | `nrvq.api.policy.rolled_back` | `norviq/api/routers/policies.py` |
| NRVQ-API-7014 | `nrvq.api.policy.dry_run` | `norviq/api/routers/policies.py` |
| NRVQ-API-7015 | `nrvq.api.policy.applied` | `norviq/api/routers/policies.py` |
| NRVQ-API-7020 | `nrvq.api.audit.listed` | `norviq/api/routers/audit.py` |
| NRVQ-API-7021 | `nrvq.api.audit.stats` | `norviq/api/routers/audit.py` |
| NRVQ-API-7022 | `nrvq.api.audit.top_blocked` | `norviq/api/routers/audit.py` |
| NRVQ-API-7023 | `nrvq.api.audit.volume` | `norviq/api/routers/audit.py` |
| NRVQ-API-7030 | `nrvq.api.agents.listed` | `norviq/api/routers/agents.py` |
| NRVQ-API-7031 | `nrvq.api.agent.trust_updated` | `norviq/api/routers/agents.py` |
| NRVQ-API-7061 | `nrvq.api.me.served` (A3: current-user claims) | `norviq/api/routers/me.py` |
| NRVQ-API-7050 | `nrvq.api.asset_graph.served` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7050-ERR | `nrvq.api.asset_graph.error` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7051 | `nrvq.api.attack_paths.served` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7051-ERR | `nrvq.api.attack_paths.error` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7080 | `nrvq.api.cluster_info.served` (F046 live cluster+namespaces) | `norviq/api/routers/cluster_info.py` |
| NRVQ-API-7081 | `nrvq.api.coverage.served` (F046 coverage-by-category) | `norviq/api/routers/coverage.py` |
| NRVQ-API-7081-ERR | `nrvq.api.coverage.mapping_missing` | `norviq/api/routers/coverage.py` |
| NRVQ-API-7082 | `nrvq.api.agent.tool_usage` (F046 audit-derived) | `norviq/api/routers/agents.py` |
| NRVQ-API-7083 | `nrvq.api.agent.trust_history` (F046 audit-derived) | `norviq/api/routers/agents.py` |
| NRVQ-API-7084 | `nrvq.api.settings.served` (F046 effective settings) | `norviq/api/routers/settings_router.py` |
| NRVQ-API-7085 | `nrvq.api.settings.saved` (F046 override persisted) | `norviq/api/routers/settings_router.py` |
| NRVQ-API-7086 | `nrvq.api.version.served` (F046 single-source version) | `norviq/api/routers/version.py` |
| NRVQ-API-7090 | `nrvq.api.apikey.authenticated` (F046 key auth) | `norviq/api/api_keys.py` |
| NRVQ-API-7091 | `nrvq.api.keys.listed` (F046) | `norviq/api/routers/keys.py` |
| NRVQ-API-7092 | `nrvq.api.keys.created` (F046) | `norviq/api/routers/keys.py` |
| NRVQ-API-7093 | `nrvq.api.keys.revoked` (F046) | `norviq/api/routers/keys.py` |

## AUTH

OIDC / JWKS token validation (IDENTITY epic A1/A2). Distinct prefix from `NRVQ-SIEM-14xxx`.

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-AUTH-14000 | `nrvq.auth.oidc_validated` | `norviq/api/auth.py` |
| NRVQ-AUTH-14001 | `nrvq.auth.oidc_rejected` (bad iss/aud/exp/sig/alg or conflicting ns) | `norviq/api/auth.py` |
| NRVQ-AUTH-14002 | `nrvq.auth.jwks_refreshed` | `norviq/api/jwks.py` |
| NRVQ-AUTH-14003 | `nrvq.auth.jwks_unknown_kid` (after bounded refresh) | `norviq/api/jwks.py` |
| NRVQ-AUTH-14004 | `nrvq.auth.jwks_fetch_failed` (fail-closed) | `norviq/api/jwks.py` |
| NRVQ-AUTH-14005 | `nrvq.auth.legacy_hs256` (migration telemetry) | `norviq/api/auth.py` |

## FLT

Multi-cluster fleet (F045). Spoke relay + hub fleet-api. Distinct prefix from `NRVQ-AUTH-14xxx`.

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
| NRVQ-FLT-15015 | `nrvq.fleet.bundle_signed` (P2: hub built+signed a bundle) | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15016 | `nrvq.fleet.puller_started` / `pull_failed` / `puller_no_trust_root` | `norviq/fleet_puller.py` |
| NRVQ-FLT-15017 | `nrvq.fleet.bundle_not_newer` (replay/rollback rejected) | `norviq/fleet_puller.py` |
| NRVQ-FLT-15018 | `nrvq.fleet.bundle_verify_failed` (tamper/wrong-key/unsigned/wrong-cluster) | `norviq/fleet_puller.py` |
| NRVQ-FLT-15019 | `nrvq.fleet.bundle_expired` / `not_yet_valid` | `norviq/fleet_puller.py` |
| NRVQ-FLT-15020 | `nrvq.fleet.rollout_reported` | `norviq/fleet_puller.py`, `fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15021 | `nrvq.fleet.policy_authored` | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15022 | `nrvq.fleet.bundle_applied` / `bundle_apply_failed` | `norviq/fleet_puller.py` |
| NRVQ-FLT-15024 | `nrvq.fleet.spiffe_id_changed` (S3: SVID binding change) | `norviq/fleet/routers/ingest.py` |
| NRVQ-FLT-15025 | `nrvq.fleet.drilldown_served` / `drilldown_failed` (P3) | `norviq/fleet/routers/fleet_policy.py` |
| NRVQ-FLT-15026 | `nrvq.fleet.drilldown_residency_blocked` (P4) | `norviq/fleet/routers/fleet_policy.py` |

## DB

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-DB-9000 | `nrvq.db.connected` | `norviq/api/db/session.py` |
| NRVQ-DB-9001 | `nrvq.db.tables_created` | `norviq/api/db/session.py` |
| NRVQ-DB-9002 | `nrvq.db.closed` | `norviq/api/db/session.py` |
| NRVQ-DB-9003 | `nrvq.db.schema_compat_applied` | `norviq/api/db/session.py` |
| NRVQ-DB-9010..9022 | cache connect/hit/set/invalidate series | `norviq/engine/cache.py` |
| NRVQ-DB-9030..9031 | cache pubsub listen/receive | `norviq/engine/cache.py` |
| NRVQ-DB-9032..9033 | migration applied/failed | `norviq/api/main.py` |
| NRVQ-DB-DEBUG-* | startup/connect/create-table diagnostics | `norviq/api/main.py`, `norviq/api/db/session.py` |

## ENG

| Code | Message (event key) | Source |
|---|---|---|
| NRVQ-ENG-2000 | `nrvq.engine.error` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2001 | `nrvq.engine.allowed` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2002 | `nrvq.engine.escalated` fallback path | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2003 | `nrvq.engine.fallback` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2004 | `nrvq.engine.cache_hit` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2005 | `nrvq.engine.policy_loaded` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2010 | `nrvq.engine.blocked` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2015 | `nrvq.engine.escalated` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2020 | `nrvq.engine.timeout` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2021 | `nrvq.engine.timeout_fallback` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2030 | `nrvq.engine.policy_hot_reloaded` | `norviq/engine/evaluator.py` |
| NRVQ-ENG-2040..2050 | trust calculator/profile/history/cache codes | `norviq/engine/trust/*`, `norviq/engine/evaluator.py` |
| NRVQ-ENG-DEBUG-* | OPA I/O and evaluator debug traces | `norviq/engine/evaluator.py` |

## REG / GRP / AUD / RED / SDC / TEL / CLI / SDK / IDT

| Component | Codes | Source |
|---|---|---|
| REG | NRVQ-REG-5000..5008, 5010..5015 | `norviq/engine/policy_loader.py` |
| GRP | NRVQ-GRP-11000,11001,11010..11016 | `norviq/engine/graph/*`, `norviq/engine/evaluator.py` |
| AUD | NRVQ-AUD-6000..6007 | `norviq/engine/audit_emitter.py`, `norviq/engine/evaluator.py` |
| RED | NRVQ-RED-13000..13005 | `norviq/redteam/*`, `norviq/api/routers/redteam.py` |
| SDC | NRVQ-SDC-3000..3005,3010,3011,3020..3023 | `norviq/sidecar/*` |
| TEL | NRVQ-TEL-12000..12007 | `norviq/telemetry/*` |
| CLI | NRVQ-CLI-8000..8004 | `norviq/cli/*` |
| SDK | NRVQ-SDK-1000,1002,1010..1013,1020..1022,1030..1032,1040..1042 | `norviq/sdk/*` |
| IDT | NRVQ-IDT-10000..10006 | `norviq/engine/identity.py` |
| AUTH | NRVQ-AUTH-14000..14005 | `norviq/api/auth.py`, `norviq/api/jwks.py` |
| FLT | NRVQ-FLT-15000..15026 | `norviq/fleet/*`, `norviq/fleet_relay.py` |

## Full Code Index

```text
NRVQ-API-7000, NRVQ-API-7001, NRVQ-API-7002, NRVQ-API-7010, NRVQ-API-7011, NRVQ-API-7012, NRVQ-API-7013, NRVQ-API-7014, NRVQ-API-7015, NRVQ-API-7020, NRVQ-API-7021, NRVQ-API-7022, NRVQ-API-7023, NRVQ-API-7024, NRVQ-API-7030, NRVQ-API-7031, NRVQ-API-7032, NRVQ-API-7050, NRVQ-API-7050-ERR, NRVQ-API-7051, NRVQ-API-7051-ERR, NRVQ-API-7061, NRVQ-API-7080, NRVQ-API-7081, NRVQ-API-7081-ERR, NRVQ-API-7082, NRVQ-API-7083, NRVQ-API-7084, NRVQ-API-7085, NRVQ-API-7086, NRVQ-API-7090, NRVQ-API-7091, NRVQ-API-7092, NRVQ-API-7093, NRVQ-API-7099
NRVQ-AUD-6000, NRVQ-AUD-6001, NRVQ-AUD-6002, NRVQ-AUD-6003, NRVQ-AUD-6004, NRVQ-AUD-6005, NRVQ-AUD-6006, NRVQ-AUD-6007, NRVQ-AUD-6008
NRVQ-CLI-8000, NRVQ-CLI-8001, NRVQ-CLI-8002, NRVQ-CLI-8003, NRVQ-CLI-8004
NRVQ-DB-9000, NRVQ-DB-9001, NRVQ-DB-9002, NRVQ-DB-9003, NRVQ-DB-9010, NRVQ-DB-9011, NRVQ-DB-9012, NRVQ-DB-9013, NRVQ-DB-9014, NRVQ-DB-9015, NRVQ-DB-9016, NRVQ-DB-9017, NRVQ-DB-9018, NRVQ-DB-9019, NRVQ-DB-9020, NRVQ-DB-9021, NRVQ-DB-9022, NRVQ-DB-9030, NRVQ-DB-9031, NRVQ-DB-9032, NRVQ-DB-9033, NRVQ-DB-DEBUG-1, NRVQ-DB-DEBUG-2, NRVQ-DB-DEBUG-2-ERR, NRVQ-DB-DEBUG-2A, NRVQ-DB-DEBUG-2B, NRVQ-DB-DEBUG-2C, NRVQ-DB-DEBUG-2D, NRVQ-DB-DEBUG-3, NRVQ-DB-DEBUG-4, NRVQ-DB-DEBUG-5, NRVQ-DB-DEBUG-6, NRVQ-DB-DEBUG-CONNECT-ARGS, NRVQ-DB-DEBUG-METADATA
NRVQ-ENG-2000, NRVQ-ENG-2001, NRVQ-ENG-2002, NRVQ-ENG-2003, NRVQ-ENG-2004, NRVQ-ENG-2005, NRVQ-ENG-2010, NRVQ-ENG-2015, NRVQ-ENG-2020, NRVQ-ENG-2021, NRVQ-ENG-2030, NRVQ-ENG-2040, NRVQ-ENG-2041, NRVQ-ENG-2042, NRVQ-ENG-2043, NRVQ-ENG-2044, NRVQ-ENG-2045, NRVQ-ENG-2046, NRVQ-ENG-2047, NRVQ-ENG-2048, NRVQ-ENG-2049, NRVQ-ENG-2050, NRVQ-ENG-2051, NRVQ-ENG-2052, NRVQ-ENG-2053, NRVQ-ENG-2054, NRVQ-ENG-2057, NRVQ-ENG-DEBUG-1, NRVQ-ENG-DEBUG-2, NRVQ-ENG-DEBUG-3, NRVQ-ENG-DEBUG-4, NRVQ-ENG-DEBUG-5, NRVQ-ENG-DEBUG-ERR, NRVQ-ENG-DEBUG-INPUT, NRVQ-ENG-DEBUG-OPA, NRVQ-ENG-DEBUG-OPA-IN
NRVQ-GRP-11000, NRVQ-GRP-11001, NRVQ-GRP-11010, NRVQ-GRP-11011, NRVQ-GRP-11012, NRVQ-GRP-11013, NRVQ-GRP-11014, NRVQ-GRP-11015, NRVQ-GRP-11016
NRVQ-AUTH-14000, NRVQ-AUTH-14001, NRVQ-AUTH-14002, NRVQ-AUTH-14003, NRVQ-AUTH-14004, NRVQ-AUTH-14005
NRVQ-FLT-15000, NRVQ-FLT-15001, NRVQ-FLT-15002, NRVQ-FLT-15003, NRVQ-FLT-15004, NRVQ-FLT-15005, NRVQ-FLT-15009, NRVQ-FLT-15010, NRVQ-FLT-15011, NRVQ-FLT-15012, NRVQ-FLT-15013, NRVQ-FLT-15014, NRVQ-FLT-15015, NRVQ-FLT-15016, NRVQ-FLT-15017, NRVQ-FLT-15018, NRVQ-FLT-15019, NRVQ-FLT-15020, NRVQ-FLT-15021, NRVQ-FLT-15022, NRVQ-FLT-15024, NRVQ-FLT-15025, NRVQ-FLT-15026
NRVQ-IDT-10000, NRVQ-IDT-10001, NRVQ-IDT-10002, NRVQ-IDT-10003, NRVQ-IDT-10004, NRVQ-IDT-10005, NRVQ-IDT-10006
NRVQ-RED-13000, NRVQ-RED-13001, NRVQ-RED-13002, NRVQ-RED-13003, NRVQ-RED-13004, NRVQ-RED-13005
NRVQ-REG-5000, NRVQ-REG-5001, NRVQ-REG-5002, NRVQ-REG-5003, NRVQ-REG-5004, NRVQ-REG-5005, NRVQ-REG-5006, NRVQ-REG-5007, NRVQ-REG-5008, NRVQ-REG-5010, NRVQ-REG-5011, NRVQ-REG-5012, NRVQ-REG-5013, NRVQ-REG-5014, NRVQ-REG-5015
NRVQ-SDC-3000, NRVQ-SDC-3001, NRVQ-SDC-3002, NRVQ-SDC-3003, NRVQ-SDC-3004, NRVQ-SDC-3005, NRVQ-SDC-3010, NRVQ-SDC-3011, NRVQ-SDC-3020, NRVQ-SDC-3021, NRVQ-SDC-3022, NRVQ-SDC-3023
NRVQ-SDK-1000, NRVQ-SDK-1002, NRVQ-SDK-1010, NRVQ-SDK-1011, NRVQ-SDK-1012, NRVQ-SDK-1013, NRVQ-SDK-1020, NRVQ-SDK-1021, NRVQ-SDK-1022, NRVQ-SDK-1030, NRVQ-SDK-1031, NRVQ-SDK-1032, NRVQ-SDK-1040, NRVQ-SDK-1041, NRVQ-SDK-1042
NRVQ-SIEM-14000, NRVQ-SIEM-14001, NRVQ-SIEM-14002
NRVQ-TEL-12000, NRVQ-TEL-12001, NRVQ-TEL-12002, NRVQ-TEL-12003, NRVQ-TEL-12004, NRVQ-TEL-12005, NRVQ-TEL-12006, NRVQ-TEL-12007
```
