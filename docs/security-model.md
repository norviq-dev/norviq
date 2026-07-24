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
for the full list of named fail-closed paths. Three worth stating explicitly here, because each is a
place where a naive implementation fails *open*:

- **Unknown agent class / no policy loaded** → `block`, `rule_id=no_policy_loaded`
  (`norviq/engine/evaluator.py::_no_policy_decision`), whenever `enforcement_mode=block` and
  `no_policy_decision=deny` — both the shipped defaults. An unrecognised `(namespace, agent_class)` is
  denied, not waved through on the theory that "no rule matched".
- **Policy subsystem not yet warm** → `block`, `rule_id=policy_load_pending`, kept as a *distinct* reason
  so a startup race is never silently mistaken for a genuine "this tenant has no policies" state.
- **Any sidecar-side error** → `drop`. An undecodable body, a JSON body that is not an object, or an
  interceptor/identity/validation exception all return `{"action": "drop"}` rather than forwarding
  (`norviq/sidecar/proxy.py`, `norviq/sidecar/http_fallback.py`). Forwarding on the error path would be a
  bypass reachable by sending malformed input, so the error path is the enforcement path.

`enforcement_mode=audit` deliberately inverts the no-policy default to allow — that is shadow mode, and
it is a visibility posture, not an enforcement one. A small set of `rule_id`s stays hard even in audit
mode (`trust_frozen`, `policy_load_pending`, `evaluator_error`, `evaluator_invalid_payload`,
`rate_limit_exceeded`), so an admin trust freeze cannot be lifted by flipping a namespace to audit.

**Norviq's PEP is cooperative, not interposing.** This is the single most important scope statement in
this document. The sidecar does not sit in the network path of the tool invocation and does not execute
the tool. The agent's SDK asks the sidecar for a verdict over a Unix domain socket (or the HTTP
fallback), the sidecar answers `{"action": "forward"|"drop"}` (`norviq/sidecar/proxy.py::_process_request`,
`norviq/sidecar/http_fallback.py`), and **the agent process then executes — or declines to execute — the
tool itself**. Norviq *authorizes*; it does not *interpose*. A pod that ignores the SDK, or agent code
that calls a tool without routing it through the interceptor, reaches that tool directly. That is a
runtime bypass, and it is inherent to the cooperative design — not a bug.

Two things bound it, and neither closes it completely:

- **`agentEgressPolicy` (opt-in, default off, `helm/norviq/values.yaml`)** renders a default-deny egress
  NetworkPolicy (or CiliumNetworkPolicy, with FQDN allowlisting) for the agent namespaces: an agent pod
  may egress only to the Norviq API, DNS, and an operator-approved CIDR/FQDN allowlist. This bounds
  bypass at the **network** layer — it does not restore per-call parameter policy, and it **requires a
  NetworkPolicy-enforcing CNI** (Calico/Cilium; kindnet silently ignores NetworkPolicy).
- **Injection integrity** — the webhook wires the socket and env into app *and* init containers, and
  `webhook.injection.allowPodOptOut=false` removes the per-pod opt-out (see below).

Non-cooperative enforcement (the sidecar executing tools on the agent's behalf) is a roadmap item, not a
property of the current release. Do not describe Norviq as "intercepting" tool calls in the interposition
sense.

Norviq's enforcement point is on tool call **inputs**, not outputs. An allowed call whose tool *body*
returns sensitive data is outside the input-PEP's view — see
[`pep-input-only-scope.md`](engineering/pep-input-only-scope.md) for the documented boundary and the
opt-in output-DLP hook that partially mitigates it. Treat this as an explicit scope statement, not a
gap that was missed: policy coverage of egress/export tools on their *inputs* (blocking the export
call itself, regardless of what the export would have contained) is the primary control.

## Trust boundaries

```
Agent pod                     Sidecar (PEP)              Central API/Engine        OPA (in-pod)
┌────────────────┐            ┌──────────────┐             ┌──────────────────┐          ┌─────────────┐
│ agent code     │  ask ───►  │ norviq-proxy │  HTTPS+JWT  │ /api/v1/evaluate │  HTTP    │ OPA sidecar │
│ (SDK/adapter)  │  ◄─ verdict│ sidecar      │  ─────────► │ engine + trust   │ ───────► │ 127.0.0.1   │
│ EXECUTES the   │  fwd/drop  │ (PEP)        │  svc token  │ calculator       │          │ :8181       │
│ tool itself    │            │              │             │                  │          │ no Service  │
└────────────────┘            └──────────────┘             └──────────────────┘          └─────────────┘
                                     │                              │
                               SPIFFE SVID                   Postgres + Redis
                               (workload identity)           (policies, audit, trust state)
```

Read the first arrow carefully: it is a **question and an answer**, not a data path. The tool call does
not traverse the sidecar.

- **The sidecar (PEP)** — injected into the agent's pod by the mutating webhook, it answers
  forward/drop on the agent's tool calls over a local Unix domain socket; the agent executes the tool
  (see the cooperative-PEP note above). It presents the workload's SPIFFE SVID as identity, not a
  bearer secret the agent code controls. In `proxy` mode (the default for *injected* sidecars —
  `webhook.injection.sidecarMode`, `webhook/config.go`) the sidecar holds no policy state itself: it's a
  thin forwarder, so compromising one sidecar exposes only that pod's own traffic, not the policy set.
  Note that the standalone `norviq-engine` Deployment is a different thing and is pinned to
  `NRVQ_SIDECAR_MODE=embedded` in the chart — it evaluates locally against its own OPA sidecar rather
  than forwarding, because nothing mints it an `NRVQ_API_TOKEN` and a thin proxy there would fail closed
  on every call.
- **The injected sidecar's container hardening** — `runAsNonRoot`, `runAsUser: 65534`,
  `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, all capabilities dropped,
  `seccompProfile: RuntimeDefault` (`webhook/injector.go::sidecarSecurityContext`). Because the root
  filesystem is read-only and the internal-mTLS client must materialize its cert/key as files for the
  stdlib TLS loader, the injector also adds a **tmpfs** scratch volume (`emptyDir` with
  `medium: Memory`, 16Mi) mounted at `/tmp`. That volume is mounted into the **sidecar only** — never
  the app container, and deliberately not the shared `norviq-socket` volume the app does mount — so the
  client private key is never readable by the workload and never lands on a real disk. Asserted by
  `webhook/injector_writable_tmp_test.go`, which fails if anyone "fixes" a temp-dir crash by turning
  `readOnlyRootFilesystem` off.
- **The central API/engine** — validates the caller's service JWT, resolves the caller's SPIFFE
  identity to `(namespace, agent_class)`, collects candidate policies, computes the trust score
  server-side, and queries OPA. This is where the actual allow/block decision is made — the sidecar
  and the SDK never decide locally.
- **OPA** — evaluates Rego against the input document `_build_input` constructs (see
  [`opa-input-schema.md`](engineering/opa-input-schema.md)). Each deployment runs OPA per-replica (the
  in-pod sidecar model, `NRVQ_OPA_URL` pointing at `localhost:8181`, or a per-process managed server in
  dev/tests) rather than one shared OPA serving the whole fleet, so a compromised OPA instance is
  contained to its own replica.

  **Both OPA sidecars bind loopback only** — `--addr=127.0.0.1:8181` in `api-deployment.yaml` and
  `engine-deployment.yaml` — and **no Service fronts port 8181** in the chart. This matters because
  OPA's admin API is unauthenticated and read-**write**: anything that can reach it can replace the
  policy bundle, i.e. rewrite the decision point. The only consumer is the app in the same pod, over
  `http://localhost:8181`, so a `0.0.0.0` bind bought nothing and exposed the PDP to every other pod in
  the cluster. Two consequences follow, both deliberate:
  - **A compromised co-resident pod is in scope for this threat model.** Norviq does not assume the
    rest of the cluster is trustworthy. Loopback binding is precisely the control for a neighbouring
    workload that can dial arbitrary pod IPs. It does *not* defend against an attacker who already has
    code execution inside the API or engine pod itself — at that point they are on the same loopback.
  - **The OPA containers carry no kubelet probes.** A kubelet probe dials the *pod IP*, so it can never
    reach a loopback-bound listener and would hold the pod `NotReady` forever. OPA health is instead
    asserted by the app's own readiness endpoint, reached over localhost by the actual consumer: the
    engine's `/readyz` calls `opa.health()` and returns 503 when it fails
    (`norviq/sidecar/http_fallback.py`), so a replica that cannot reach its own PDP leaves the Service
    endpoints rather than advertising enforcement it cannot perform. Liveness stays on `/healthz` on
    purpose — an OPA outage should drain the replica, not restart-loop it. Both properties are pinned by
    `tests/helm/test_opa_bind_is_loopback.py` and `tests/helm/test_network_exposure_matrix.py`.

  Every policy pushed to OPA is independently re-checked by the real OPA
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

### Adversaries in scope

Stated explicitly, because "what we assume is trusted" is the part of a threat model most often left
implicit:

| Adversary | In scope? | Primary control |
|-----------|-----------|-----------------|
| A manipulated / prompt-injected agent making tool calls it shouldn't | **Yes** — the core case | Policy on tool-call inputs + trust escalation |
| A **compromised co-resident pod** dialing other pods' IPs | **Yes** | OPA binds loopback and is fronted by no Service; internal mTLS on the API path |
| An agent workload trying to read the sidecar's mTLS key | **Yes** | tmpfs is mounted into the sidecar only, never the app container or the shared socket volume |
| A pod author self-exempting from injection | **Yes, if you close it** | `webhook.injection.allowPodOptOut=false` (default `true`) + RBAC on pod labels |
| An authenticated user reaching another tenant's data | **Yes** | JWT namespace claim binding (`scoped_namespace` / `read_namespace`), per-tenant OPA packages |
| A client asserting its own trust score | **Yes** | `trust_score` stripped from the request and recomputed server-side |
| Agent code that bypasses the SDK entirely | **Partially** | `agentEgressPolicy` bounds it at the network layer; cooperative design cannot fully close it |
| Code execution inside the API or engine pod | **No** | Same loopback as OPA; assume full PDP compromise |
| Cluster-admin compromise | **No** | Explicitly out of scope (see `SECURITY.md`) |
| Malicious tool *output* reaching the LLM | **No, by default** | Input-side policy coverage; opt-in output-DLP hook |

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

- **Sidecar injection is opt-out-able by default.** The mutating webhook injects into every pod in a
  namespace labeled `norviq-injection=enabled`, *unless* the pod itself carries
  `norviq-injection=disabled` or the `norviq.io/skip-injection` annotation. This is documented,
  intentional per-pod flexibility (e.g. exempting an infra pod from a labeled namespace) — but it also
  means a workload that can set its own pod annotations/labels before admission can opt itself out of
  enforcement. **Set `webhook.injection.allowPodOptOut=false`** (env `NRVQ_ALLOW_POD_OPT_OUT`, default
  `true` for backward compatibility) to make the injector ignore the per-pod opt-out entirely, so no pod
  author in a labeled namespace can self-exempt and the namespace-uniform guarantee holds
  (`webhook/handler.go`). Otherwise treat namespace labeling as the enforcement boundary and restrict
  who can set those labels/annotations via RBAC.
- **CRD-level policy business rules are enforced by the controller, not at admission.**
  `webhook/controller.go` validates `NrvqPolicy` semantics — cross-namespace targets, `clusterPriority`
  bounds (500-1000, restricted to the admin policy namespace), and Rego content — when it syncs a CRD to
  the central API, and logs+skips a CRD that fails validation. A CRD that fails this check still exists
  in the cluster (`kubectl get nrvqpolicy` shows it) but is never synced to the enforcement engine — so a
  malformed or malicious CRD applied directly via `kubectl` is inert rather than rejected at admission
  time. **There is no ValidatingAdmissionPolicy in this chart.** The only namespace-level guard is an
  opt-in `ResourceQuota` (`helm/norviq/templates/resource-quota.yaml`) that caps
  `count/nrvqpolicies.norviq.io` at 100, and only in the namespaces listed in `policyQuotaNamespaces`.
  That is flood/quota protection, not validation, and it is not admission-time rejection of bad content.
  RBAC on who can create `NrvqPolicy`/`NrvqClass` objects is the operator-side mitigation.
- **`NrvqClass` and `NrvqConfig` are only partially wired to the engine.** The controller syncs
  `NrvqPolicy` objects to the central API and reconciles `.status` on all three kinds, and it reads
  `NrvqConfig.spec.sidecar.image` (rejecting an unauthorized or mutable-tag override). It does **not**
  push `NrvqClass.spec.allowedTools` / `blockedTools` / `maxCallsPerMinute` / `initialTrustScore` /
  `trustThreshold`, nor `NrvqConfig.spec.trust.*`, into the engine — those fields validate against the
  CRD schema and are then inert. Configure enforcement through policies and namespace settings, and see
  [`trust-score-design.md`](trust-score-design.md) for what this means for the `scope_drift` trust
  signal specifically.
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
  (`.github/workflows/security.yml` + `.pre-commit-config.yaml`) runs gitleaks, bandit, and semgrep
  diff-aware against every PR — new HIGH/CRITICAL findings fail the build, never backlogged.
  **eslint-security** (eslint-plugin-security) additionally scans the whole `ui/src` fail-closed — any
  finding fails the build — adding JS/TS-specific security rules (eval, unsafe-regex, child_process,
  bidi-characters, …) on top of semgrep's `ui/src` pass (see
  [`security-baseline.md`](engineering/security-baseline.md) for the full triage rule and the
  whole-repo-scan ratchet plan).
- **FOSSA** dependency scanning covers open-source license/security posture (badge on the repo
  README).
- **Third-party GitHub Actions are SHA-pinned**, not tag-pinned, so a compromised upstream tag can't
  silently swap in malicious code in CI — a mutable tag pointing at a security-relevant action is a real
  supply-chain risk (the trivy-action project itself had a compromise). `actions/checkout`,
  `actions/setup-python`, `actions/setup-node`, `docker/*-action`, `aquasecurity/trivy-action`,
  `azure/setup-helm`, `sigstore/cosign-installer`, and `pypa/gh-action-pypi-publish` are all pinned to a
  commit SHA. Three remain tag-pinned and are tracked follow-up: `actions/upload-artifact@v4`,
  `bridgecrewio/checkov-action@v12`, and `fossas/fossa-action@v1.7.0`.

## Reporting a vulnerability

Found a security issue? Do not open a public GitHub issue. Norviq's coordinated-disclosure process
lives in `SECURITY.md` at the repo root — follow it to report privately.
