# IDENTITY epic software core (A1/A2/B2) — 2026-06-28, gated default-off, uncommitted

Symbols/files added or changed (all gated to today's behavior by default):

## A1 OIDC dual-mode auth
- `norviq/api/auth.py`: new `_validate_token(token)` (shared HS256/OIDC dispatch on JWT header `alg`,
  single-alg allowlists -> alg-confusion-safe), `_validate_oidc(token, header)`, `_apply_group_mapping(claims)`.
  `get_current_user` + `decode_token` are now **async**. `_ROLE_RANK` admin>service>viewer.
- `norviq/api/jwks.py` (NEW): `JwksClient` (`get_key(kid)`, `_refresh(force)`; kid cache + TTL +
  bounded unknown-kid refetch + fail-closed). `get_jwks_client()` singleton. Test seam = inject `http_client`
  or monkeypatch `norviq.api.auth.get_jwks_client`.
- `norviq/api/main.py`: ws/audit now `await decode_token(raw)`.
- No new dependency: jose 3.5.0 uses pure-python `rsa`/`ecdsa` backends (cryptography absent).

## A2 mapping + per-user audit
- `_apply_group_mapping` in auth.py (groups -> role/namespace).
- `norviq/api/routers/policies.py`: `actor`/`actor_role` added to log lines NRVQ-API-7011/7012/7013/7015.
- `helm/norviq/templates/configmap.yaml` + `values.yaml` `oidc:` block + `config.spiffeMode`.

## B2 real SPIFFE resolver
- `norviq/engine/identity.py`: `_resolve_from_socket` dispatches on `settings.spiffe_mode`. New
  `_resolve_workload_api()`, `_svid_source()` (pyspiffe seam), module-level `_parse_norviq_spiffe_id()`,
  `SpiffeResolutionError`, `_PYSPIFFE_AVAILABLE` import guard. mock mode unchanged.
- `pyproject.toml`: optional extra `spiffe = ["spiffe>=0.2"]`.

## Config (norviq/config.py)
- `oidc_enabled`(F), `oidc_issuer/audience/jwks_url`, `oidc_jwks_cache_ttl_s`, `oidc_jwks_min_refresh_s`,
  `oidc_group_claim`, `oidc_group_mappings` (dict), `legacy_hs256_enabled`(T), `spiffe_mode`("mock").

## Tests
- `tests/api/test_oidc_auth.py` (16) — synthetic-JWKS RS256 matrix incl. alg-confusion; JwksClient cache/fail-closed.
- `tests/engine/test_identity.py` (+6) — workload-api spoof-ignored / fail-closed / wrong-domain / missing-pyspiffe / parse.

Codes: NRVQ-AUTH-14000..14005, NRVQ-IDT-10004..10006 (docs/error-codes.md).
Deferred: A3 console PKCE, A4 cutover, B1 SPIRE-on-AKS, B3 injector socket, B4 controller->SVID.
