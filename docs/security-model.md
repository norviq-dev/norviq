<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Norviq Contributors -->

# Security Model

Norviq's trust boundaries and threat model, stated plainly: what it defends, what trusts what, and
where the honest limits of the current design are.

## What Norviq defends

Norviq is a policy enforcement point (PEP) for LLM agent tool calls: it enforces per-identity
allow/block/escalate/audit decisions on the *inputs* of a tool call (`tool_name` + `tool_params`)
before the tool body runs. The core security property is **fail-closed evaluation** — if OPA errors,
times out, the caller's SPIFFE identity is malformed, or no policy is loaded for an enforcing
namespace, the call is **blocked**, never silently allowed. See [Concepts → Decisions](concepts.md#decisions)
for the full list of named fail-closed paths.

Norviq's enforcement point is on tool call **inputs**, not outputs. An allowed call whose tool *body*
returns sensitive data is outside the input-PEP's view — see
[`pep-input-only-scope.md`](engineering/pep-input-only-scope.md) for the documented boundary and the
opt-in output-DLP hook that partially mitigates it. Treat this as an explicit scope statement, not a
gap that was missed: policy coverage of egress/export tools on their *inputs* (blocking the export
call itself, regardless of what the export would have contained) is the primary control.

## Trust boundaries

```
Agent pod                    Sidecar (PEP)              Central API/Engine           OPA
┌──────────────┐    UDS      ┌────────────┐   HTTPS+JWT ┌──────────────────┐  HTTP  ┌────┐
│ agent code    │ ─────────► │ norviq-     │ ──────────► │ /api/v1/evaluate │ ─────► │ OPA│
│ (LangGraph/   │  tool call │ proxy       │  service    │  engine + trust  │ query  │(per│
│  SDK/adapter) │            │ sidecar     │  token      │  calculator      │        │pod)│
└──────────────┘            └────────────┘             └──────────────────┘        └────┘
                                    │                              │
                              SPIFFE SVID                     Postgres + Redis
                              (workload identity)             (policies, audit,
                                                                trust state)
```

- **The sidecar (PEP)** — injected into the agent's pod by the mutating webhook, it intercepts the
  agent's tool calls over a local Unix domain socket and forwards them to the central engine. It
  presents the workload's SPIFFE SVID as identity, not a bearer secret the agent code controls. In
  `proxy` mode (the default) the sidecar holds no policy state itself — it's a thin forwarder, so
  compromising one sidecar exposes only that pod's own traffic, not the policy set.
- **The central API/engine** — validates the caller's service JWT, resolves the caller's SPIFFE
  identity to `(namespace, agent_class)`, collects candidate policies, computes the trust score
  server-side, and queries OPA. This is where the actual allow/block decision is made — the sidecar
  and the SDK never decide locally.
- **OPA** — evaluates Rego against the input document `_build_input` constructs (see
  [`opa-input-schema.md`](engineering/opa-input-schema.md)). Each deployment runs OPA per-replica (the
  in-pod sidecar model, `NRVQ_OPA_URL` pointing at `localhost:8181`, or a per-process managed server in
  dev/tests) rather than one shared OPA serving the whole fleet, so a compromised OPA instance is
  contained to its own replica. Every policy pushed to OPA is independently re-checked by the real OPA
  compiler (`opa check`) against a locked-down capabilities file that strips dangerous builtins
  (`http.send`, `opa.runtime`, `net.*`, `io.*`, `rego.parse_module`, `trace`, `print`) — this is
  defense-in-depth *behind* the API-layer reject on forbidden Rego tokens, not the only gate.
- **The database** — Postgres holds policies, audit records, and the agent registry; Redis holds
  short-TTL evaluation cache, trust state, and rate-limit counters. Trust is always **recomputed
  server-side from Redis on every call** — a caller-supplied `trust_score` in the request body is
  explicitly discarded (`payload.model_dump(exclude={"trust_score"})`) so a client can never assert its
  own trustworthiness.
- **SPIFFE identity** — the trust root for *which agent this is*. In `workload-api` mode the sidecar
  fetches a real SVID from the SPIFFE Workload API and fails closed on any socket/SVID error (no
  fallback to an env-var identity). `mock` mode (env-var identity) exists for local dev/tests/attack
  suite and should not be used where identity spoofing across pods is a live threat.
- **Tenant/namespace isolation** — namespace-scoped data (policies, audit, asset graph, agents)
  defaults to `namespace="default"` when a caller omits the parameter (fail-safe: incomplete data, not
  an accidental cross-tenant leak), and a `namespace=all` admin view requires an explicit opt-in gated
  by role. See [`namespace-scoping.md`](engineering/namespace-scoping.md).

## AuthN/Z

**Token validation** — `norviq/api/auth.py` supports two mutually exclusive paths, each pinned to a
single-algorithm allowlist so an attacker cannot downgrade an OIDC RS256/ES256 token into an
HS256-with-the-public-key forgery (alg-confusion):

- **Legacy HS256** — a shared secret (`api_secret_key` / `NRVQ_API_SECRET_KEY`) signs short-lived
  session tokens for local username/password login. The API refuses to boot with the built-in default
  secret or default admin password when `require_strong_secret` is true (the default) — a forgeable
  default secret would be a fleet-wide trust-root compromise, so this fails closed rather than booting
  insecurely.
- **OIDC RS256/ES256** — validated against the IdP's JWKS by key id; IdP group claims are mapped to a
  Norviq `(role, namespace, cluster)` tuple. An unmapped-but-authenticated user gets the
  least-privilege floor (`viewer`, no namespace, no cluster) rather than falling through to broader
  access, and conflicting group mappings (e.g. two groups claiming different namespaces) fail closed
  rather than picking one silently.

Logged-out tokens are rejected server-side via a revocation check (a signature-valid but logged-out
JWT is dead, not just client-discarded), and a token minted with `must_change=True` (the seeded
default admin, or any account after an admin-triggered reset) is locked to only the
change-password/logout/`me` routes until the password is actually changed.

**Role model** — three roles: `admin` (full access), `service` (machine principals only — the webhook
controller syncing CRDs, the fleet relay; least-privilege, cannot self-elevate to a human's
write paths), and `viewer` (read scoped to its own namespace claim, no namespace claim = no data).
There is no separate "policy editor" role today — policy mutation endpoints require `admin` (or
`admin_or_service` for the narrow CRD-sync create/delete paths the controller uses); a human who needs
to edit policies needs the `admin` role.

**Namespace scoping** — `scoped_namespace`/`read_namespace` in `auth.py` bind every namespace-scoped
request to the caller's JWT/API-key namespace claim: an admin (or a claim of `"*"`) may read/write any
namespace or request `namespace=all`; anyone else is pinned to their own claimed namespace, and a
human with *no* namespace claim gets a 403 rather than defaulting to broad access. `scoped_cluster`
applies the same pattern to the multi-cluster fleet dimension.

## Multi-tenancy

Policies and audit records are namespace-scoped by construction (the loader key is
`{namespace}:{agent_class}`, and audit rows carry the originating namespace). On the OPA side, every
pushed policy gets its **own package** (`norviq.managed.<sanitized-key>`), derived from a hash of the
full `namespace:agent_class` key — this guarantees two tenants' policies can never collide into one
OPA module even if their keys sanitize to similar strings. Cross-namespace reads require an explicit
`namespace=all` request and a role permitted to make it (see AuthN/Z above); the default behavior on
every scoped endpoint is single-tenant.

## Known design decisions / non-goals

These are stated intentionally, as operator responsibilities and threat-model notes — not gaps that
were missed:

- **Sidecar injection is opt-out-able by design.** The mutating webhook injects into every pod in a
  namespace labeled `norviq-injection=enabled`, *unless* the pod itself carries
  `norviq-injection=disabled` or the `norviq.io/skip-injection` annotation. This is documented,
  intentional per-pod flexibility (e.g. exempting an infra pod from a labeled namespace) — but it also
  means a workload that can set its own pod annotations/labels before admission can opt itself out of
  enforcement. Treat namespace labeling as the enforcement boundary, and restrict who can set those
  labels/annotations via RBAC if per-pod opt-out is a concern in your environment.
- **CRD-level policy business rules are enforced by the controller, not a Kubernetes
  ValidatingAdmissionPolicy.** `webhook/controller.go` validates `NrvqPolicy` semantics — cross-namespace
  targets, `clusterPriority` bounds (500-1000, restricted to the admin policy namespace), and Rego
  content — when it syncs a CRD to the central API, and logs+skips a CRD that fails validation. A
  CRD that fails this check still exists in the cluster (`kubectl get nrvqpolicy` shows it) but is
  never synced to the enforcement engine — so a malformed or malicious CRD applied directly via
  `kubectl` is inert rather than rejected at admission time. (One exception: NrvqPolicy *creation* in
  unlabeled tenant namespaces is denied at admission by a ValidatingAdmissionPolicy tied to
  `norviq.io/policy-quota=enabled`, which exists specifically for quota/flood protection — that's a
  narrower control than full business-rule validation.) RBAC on who can create `NrvqPolicy`/`NrvqClass`
  objects is the operator-side mitigation.
- **Single JWT signing secret is the legacy-auth trust root.** In the HS256 login path, one shared
  secret (`api_secret_key`) signs every session token; compromising it lets an attacker forge tokens
  for any role. `require_strong_secret` (default on) refuses to boot on a weak/default secret, but
  operators running OIDC should prefer it over the legacy path where a centralized IdP and per-key
  JWKS validation removes this single-secret exposure.
- **The input-side PEP does not inspect tool outputs by default** (see "What Norviq defends" above) —
  an allowed call's return payload is outside the enforcement point's view unless the opt-in
  output-DLP hook is enabled.
- **`mock` SPIFFE mode trusts environment variables for identity.** It exists for local dev, tests,
  and the attack suite; running it in a multi-tenant cluster where pods can influence their own
  environment removes the identity-spoofing protection that `workload-api` mode provides.

## Supply chain

- **OPA binary** is pinned and checksummed in the build, not pulled loose at runtime.
- **Container images** are gated by Trivy (`build.yml` post-build scan on `main`); the SAST gate
  (`.github/workflows/security.yml` + `.pre-commit-config.yaml`) runs gitleaks, bandit, semgrep, and
  eslint-security diff-aware against every PR — new HIGH/CRITICAL findings fail the build,
  never backlogged (see [`security-baseline.md`](engineering/security-baseline.md) for the full triage
  rule and the whole-repo-scan ratchet plan).
- **FOSSA** dependency scanning covers open-source license/security posture (badge on the repo
  README).
- **Third-party GitHub Actions are being SHA-pinned**, not tag-pinned, so a compromised upstream tag
  can't silently swap in malicious code in CI — a mutable tag pointing at a security-relevant action is
  a real supply-chain risk (the trivy-action project itself had a compromise). This pinning is
  in-progress: `trivy-action` is done; `azure/login`, `azure/setup-helm`, `actions/checkout`,
  `docker/*-action`, and `actions/setup-*` are tracked follow-up.

## Reporting a vulnerability

Found a security issue? Do not open a public GitHub issue. Norviq's coordinated-disclosure process
lives in `SECURITY.md` at the repo root — follow it to report privately.
