# Norviq Error Codes

Generated from `norviq/**/*.py` log/error code literals (`NRVQ-*`).

## Registry Summary

| Component | Unique Codes | Primary Sources |
|---|---:|---|
| API | 18 | `norviq/api/main.py`, `norviq/api/routers/*` |
| AUD | 8 | `norviq/engine/audit_emitter.py` |
| CLI | 5 | `norviq/cli/main.py`, `norviq/cli/api_client.py` |
| DB | 34 | `norviq/api/db/session.py`, `norviq/engine/cache.py`, `norviq/api/main.py` |
| ENG | 31 | `norviq/engine/evaluator.py`, `norviq/engine/trust/*` |
| GRP | 9 | `norviq/engine/graph/*` |
| IDT | 4 | `norviq/engine/identity.py` |
| RED | 6 | `norviq/redteam/*`, `norviq/api/routers/redteam.py` |
| REG | 15 | `norviq/engine/policy_loader.py` |
| SDC | 12 | `norviq/sidecar/*` |
| SDK | 15 | `norviq/sdk/*` |
| TEL | 8 | `norviq/telemetry/*` |

Total documented unique codes: **165**

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
| NRVQ-API-7050 | `nrvq.api.asset_graph.served` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7050-ERR | `nrvq.api.asset_graph.error` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7051 | `nrvq.api.attack_paths.served` | `norviq/api/routers/graphs.py` |
| NRVQ-API-7051-ERR | `nrvq.api.attack_paths.error` | `norviq/api/routers/graphs.py` |

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
| IDT | NRVQ-IDT-10000..10003 | `norviq/engine/identity.py` |

## Full Code Index

```text
NRVQ-API-7000, NRVQ-API-7001, NRVQ-API-7010, NRVQ-API-7011, NRVQ-API-7012, NRVQ-API-7013, NRVQ-API-7014, NRVQ-API-7015, NRVQ-API-7020, NRVQ-API-7021, NRVQ-API-7022, NRVQ-API-7023, NRVQ-API-7030, NRVQ-API-7031, NRVQ-API-7050, NRVQ-API-7050-ERR, NRVQ-API-7051, NRVQ-API-7051-ERR
NRVQ-AUD-6000, NRVQ-AUD-6001, NRVQ-AUD-6002, NRVQ-AUD-6003, NRVQ-AUD-6004, NRVQ-AUD-6005, NRVQ-AUD-6006, NRVQ-AUD-6007
NRVQ-CLI-8000, NRVQ-CLI-8001, NRVQ-CLI-8002, NRVQ-CLI-8003, NRVQ-CLI-8004
NRVQ-DB-9000, NRVQ-DB-9001, NRVQ-DB-9002, NRVQ-DB-9003, NRVQ-DB-9010, NRVQ-DB-9011, NRVQ-DB-9012, NRVQ-DB-9013, NRVQ-DB-9014, NRVQ-DB-9015, NRVQ-DB-9016, NRVQ-DB-9017, NRVQ-DB-9018, NRVQ-DB-9019, NRVQ-DB-9020, NRVQ-DB-9021, NRVQ-DB-9022, NRVQ-DB-9030, NRVQ-DB-9031, NRVQ-DB-9032, NRVQ-DB-9033, NRVQ-DB-DEBUG-1, NRVQ-DB-DEBUG-2, NRVQ-DB-DEBUG-2-ERR, NRVQ-DB-DEBUG-2A, NRVQ-DB-DEBUG-2B, NRVQ-DB-DEBUG-2C, NRVQ-DB-DEBUG-2D, NRVQ-DB-DEBUG-3, NRVQ-DB-DEBUG-4, NRVQ-DB-DEBUG-5, NRVQ-DB-DEBUG-6, NRVQ-DB-DEBUG-CONNECT-ARGS, NRVQ-DB-DEBUG-METADATA
NRVQ-ENG-2000, NRVQ-ENG-2001, NRVQ-ENG-2002, NRVQ-ENG-2003, NRVQ-ENG-2004, NRVQ-ENG-2005, NRVQ-ENG-2010, NRVQ-ENG-2015, NRVQ-ENG-2020, NRVQ-ENG-2021, NRVQ-ENG-2030, NRVQ-ENG-2040, NRVQ-ENG-2041, NRVQ-ENG-2042, NRVQ-ENG-2043, NRVQ-ENG-2044, NRVQ-ENG-2045, NRVQ-ENG-2046, NRVQ-ENG-2047, NRVQ-ENG-2048, NRVQ-ENG-2049, NRVQ-ENG-2050, NRVQ-ENG-DEBUG-1, NRVQ-ENG-DEBUG-2, NRVQ-ENG-DEBUG-3, NRVQ-ENG-DEBUG-4, NRVQ-ENG-DEBUG-5, NRVQ-ENG-DEBUG-ERR, NRVQ-ENG-DEBUG-INPUT, NRVQ-ENG-DEBUG-OPA, NRVQ-ENG-DEBUG-OPA-IN
NRVQ-GRP-11000, NRVQ-GRP-11001, NRVQ-GRP-11010, NRVQ-GRP-11011, NRVQ-GRP-11012, NRVQ-GRP-11013, NRVQ-GRP-11014, NRVQ-GRP-11015, NRVQ-GRP-11016
NRVQ-IDT-10000, NRVQ-IDT-10001, NRVQ-IDT-10002, NRVQ-IDT-10003
NRVQ-RED-13000, NRVQ-RED-13001, NRVQ-RED-13002, NRVQ-RED-13003, NRVQ-RED-13004, NRVQ-RED-13005
NRVQ-REG-5000, NRVQ-REG-5001, NRVQ-REG-5002, NRVQ-REG-5003, NRVQ-REG-5004, NRVQ-REG-5005, NRVQ-REG-5006, NRVQ-REG-5007, NRVQ-REG-5008, NRVQ-REG-5010, NRVQ-REG-5011, NRVQ-REG-5012, NRVQ-REG-5013, NRVQ-REG-5014, NRVQ-REG-5015
NRVQ-SDC-3000, NRVQ-SDC-3001, NRVQ-SDC-3002, NRVQ-SDC-3003, NRVQ-SDC-3004, NRVQ-SDC-3005, NRVQ-SDC-3010, NRVQ-SDC-3011, NRVQ-SDC-3020, NRVQ-SDC-3021, NRVQ-SDC-3022, NRVQ-SDC-3023
NRVQ-SDK-1000, NRVQ-SDK-1002, NRVQ-SDK-1010, NRVQ-SDK-1011, NRVQ-SDK-1012, NRVQ-SDK-1013, NRVQ-SDK-1020, NRVQ-SDK-1021, NRVQ-SDK-1022, NRVQ-SDK-1030, NRVQ-SDK-1031, NRVQ-SDK-1032, NRVQ-SDK-1040, NRVQ-SDK-1041, NRVQ-SDK-1042
NRVQ-TEL-12000, NRVQ-TEL-12001, NRVQ-TEL-12002, NRVQ-TEL-12003, NRVQ-TEL-12004, NRVQ-TEL-12005, NRVQ-TEL-12006, NRVQ-TEL-12007
```
