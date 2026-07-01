# Fleet MVP P1 (FEAT F045) — multi-cluster read-only, 2026-06-28, gated off, uncommitted

Multi-cluster fleet R3 Phase-1 (read-only visibility), Option A hub-and-spoke. All gated off by default.

## New code
- `norviq/fleet/` package (hub): `models.py` (SEPARATE FleetBase + Cluster/AgentRollup/AuditRollup),
  `db.py` (separate engine, fleet_init_db/fleet_get_session/fleet_create_tables, NRVQ_FLEET_PG_URL),
  `schemas.py`, `main.py` (create_fleet_app + own lifespan), `routers/{health,ingest,fleet}.py`,
  `oidc_cc.py` (ClientCredentialsToken).
- `norviq/fleet_relay.py` (spoke): FleetRelayForwarder (mirrors api/siem.py AuditForwarder), wired in
  `norviq/api/main.py` lifespan next to SIEM (start/stop, gated fleet_enabled).
- `norviq/api/auth.py`: `_apply_group_mapping` +cluster claim; new `scoped_cluster`.
- `norviq/config.py`: fleet_* fields (after siem_*). fleet_pg_url HUB ONLY.
- helm: `templates/fleet-hub.yaml` (gated fleet.hub.enabled) + relay env in configmap/secret (gated
  fleet.enabled) + values.yaml `fleet:` block (incl. hub.nodePort).
- ui: `src/api/fleet.ts` + `src/pages/Fleet.tsx` + route in App.tsx + gated nav in ExpandedPanel.tsx
  (VITE_FLEET_API_URL). vite-env.d.ts.

## Tests
`tests/fleet/test_fleet_api.py` (9: heartbeat/rollup upsert, aggregated reads, cluster-scope 403),
`tests/fleet/test_fleet_relay.py` (relay_once payloads; start() no-op), `tests/api/test_oidc_auth.py`
(+4 cluster-scope). Bare TestClient + dependency_overrides[fleet_get_session] + FakeFleetSession.

## Live (scripts/fleet-local/, 2 kind clusters)
fleet-a hub+spoke, fleet-b spoke; cross-cluster over the shared kind net (NodePort 31090, node container IP).
Heartbeat+register, cross-cluster aggregate, RBAC 403, hub-down fail-safe (spoke still blocks). All gated; AKS untouched.

## Key guards/gotchas
- Two independent DeclarativeBase + engines (spoke Base/init_db vs FleetBase/fleet_init_db).
- SET-absolute rollup upserts (idempotent).
- helm chart templates the Namespace -> pre-create ns with helm ownership, install without --create-namespace.
- Codes NRVQ-FLT-15000..15014. registry/F045 + architecture/F045.*.mmd. Zero new regressions.
