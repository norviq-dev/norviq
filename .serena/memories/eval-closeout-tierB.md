# Customer-Eval Closeout — bounded C1–C4 (2026-06-28, uncommitted)

Follows `mem:eval-tier-a-remediation`. Repo `norviq-migration/repo`. No auto-commit.

## C1 — base64 evasion (R2) · `comprehensive.rego`
`base64_decoded_threat`: each base64-charset `tool_params` value is `base64.decode`d and the decoded
text re-scanned against `injection_patterns`, `sql_patterns`, a multi-char `decoded_shell_patterns`
(single metachars excluded → no FP on random bytes), and the dashed-SSN regex → `decision="block"`,
`rule_id="base64_decoded_threat"`; added to `non_allow_triggered`. Decoded-clean base64 still only
`audit`s. **Attacks 75/75** (was 72). Tests: `tests/attacks/test_policy_bypass.py`.

## C2 — turnkey webhook TLS (R1, helm-hook only) · F021
`helm/norviq/templates/webhook-config.yaml` (MutatingWebhookConfiguration, gated
`webhook.injection.enabled`, empty caBundle) + `webhook-cert-job.yaml` (pre/post-install hook Job +
hook-scoped SA/Role/RoleBinding for secrets and ClusterRole/Binding for mutatingwebhookconfigurations;
self-signs cert → `norviq-webhook-tls` → patches caBundle). `values.yaml webhook.injection.{enabled,
certJobImage}`. Static `webhook/deploy/*.yaml` kept.

## C3 — RBAC bindings + prod doc (P2-14) · F021
`templates/rbac-bindings.yaml` (gated `rbac.exampleBindings.enabled`) renders ClusterRoleBindings from
`values.yaml rbac.bindings[]`. `docs/engineering/production-config.md` (linked from ops guide).

## C4 — SIEM export + forwarder (R5) · F017/F016
`GET /api/v1/audit/export?format=ndjson|csv&range=&namespace=&decision=` in
`norviq/api/routers/audit.py` (`_stream_audit_rows` keyset-paged StreamingResponse, auth +
`scoped_namespace`, `NRVQ-API-7024`). `norviq/api/siem.py` `AuditForwarder` (gated `siem_enabled`,
`NRVQ-SIEM-14000/14001/14002`) started/stopped in `main.py` lifespan. Config `siem_*` + helm `siem.*`
+ `NRVQ_SIEM_*` configmap. Tests `tests/api/test_audit_export.py`, `test_siem_forwarder.py`.

## Verify
`make lint` clean; `make test` 387 pass / **same 6 pre-existing fail** (see
`mem:eval-tier-a-remediation`) / 1 skip; vitest 37/37; tsc clean; `helm lint` + `helm template`
per gate flag. Live: export unauth 401 / admin ndjson+csv 200 / viewer cross-ns 403; base64-injection
blocks. New codes in `docs/error-codes.md`. .mmd diagrams NOT regenerated (additive: gated endpoint/
class + helm yaml).
