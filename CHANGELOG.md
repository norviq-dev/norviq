# Changelog

All notable changes, newest first. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow SemVer. Each 0.2.x entry is a summary — the linked GitHub release is the full account,
grouped by upgrade impact, security relevance and operator-visible behaviour. Entries for 0.2.0 and
earlier are taken from the annotated tags, the only record those versions have.

Seventeen released versions. The `pre-public-cleanup-20260712` tag is not a release and is omitted.
Three versions published incompletely — `v0.1.0` shipped no chart, `v0.1.1` shipped it unsigned,
`v0.2.0` shipped no chart — and their headings say so: they are listed because they happened, not
because they should be installed.

## [0.2.5] — 2026-08-20 — log codes that named two things at once

- **Eleven log codes renumbered** so an alertable event no longer shares a code with routine traffic.
  Old codes keep matching — they just stop matching the event you cared about. `sidecar.remote_evaluator.fail_open`
  `NRVQ-SDC-3032` → **`3036`**; `api.rate_limit.fail_open` `7080` → **`7133`**; `api.rate_limit.exceeded`
  `7081` → **`7134`**; `api.policy.priority_band_denied` `7020` → **`7135`**; `api.body_too_large` `7050` →
  **`7136`**; `settings.mirror_failed` / `ns_settings_warm_failed` `7063` → **`7137`** / **`7138`**;
  `trust.freeze_check_failed` `ENG-2050` → **`2067`**; `fleet.pull_failed` / `puller_no_trust_root`
  `FLT-15016` → **`15043`** / **`15044`**; `mcp.servers.control_plane_unreachable` `MCP-5070` → **`5077`**.
- The sidecar's fail-open — the record that a call ran **unjudged** — was on the same code as two startup
  INFO lines, and the error reference described that code as "two events, both about proxy mode". A
  filter written from the docs silenced it. The sidecar code takes effect only after agent pods are rolled.
- MCP Gate A now says when a server decision is **unavailable** (`NRVQ-MCP-5076`) instead of reading as clean.
- The console no longer prints "no blocks" over a namespace whose posture it could not read.

Full notes: https://github.com/norviq-dev/norviq/releases/tag/v0.2.5

## [0.2.4] — 2026-08-20 — two chart values that were connected to nothing

- set `config.rateLimit` or `config.violationPenalty` in values — they were connected to **nothing** and now take effect. Check your values before upgrading
- reference sidecar credential Secrets by name — **the names change** — the hash suffix is now unconditional
- use the `norviq.io/workload` pod label to pick an identity — it is now a **fallback**, not an override; the attested owner chain wins
- apply generated intent policies, or call `/system-health` as a no-scope viewer — those requests now **409 / 403** where they used to succeed
- run the fleet hub — its Postgres DSN moved from a ConfigMap into `norviq-secrets` (only when `fleet.hub.enabled=true`)
- A tool name could invert the one positive-security policy in the product
- One approved MCP tool call could execute twice
- Gate A never scanned the `initialize` handshake
- Running the red-team suite silently escalated every real agent it simulated against

Full notes: https://github.com/norviq-dev/norviq/releases/tag/v0.2.4

## [0.2.3] — 2026-08-19 — a PEP refusal recorded as an allow, and defaults documented backwards

- **A PEP refusal was persisted as an allow on the cache-hit path**, so the attack graph and trust scoring
  never saw refusals; a sidecar that refused every call scored as a perfectly compliant agent.
- **Four defaults were documented as the opposite of what ships.** `config.noPolicyDecision`: docs said
  `deny (fail-closed)`, ships **`allow`**. `webhook.injection.fallbackMode`: docs said `block (fail-closed)`,
  ships **`allow`**. `auth.requireBoundAgentIdentity`: docs said `false`, ships **`true`**.
  `gracefulShutdown.preStopSleepSeconds`: docs said `3`, ships **`15`**. The docs
  described a stricter product than the chart installs; the chart/configmap/config.py parity test compared
  three machine sources to each other and passed — nothing read prose.
- **The secret scanner scanned zero commits** (`HEAD..HEAD` on pushes to `main`) and reported clean.
- kind-e2e: the browser install is bounded so a stall cannot eat the job; OPA download retried in image builds.

Full notes: https://github.com/norviq-dev/norviq/releases/tag/v0.2.3

## [0.2.2] — 2026-08-19 — a 4xx must never open the circuit breaker into fail-open

- **An expired credential silently disabled enforcement.** The SDK's `PolicyEngineClient` counted every
  `HTTPStatusError` toward its circuit breaker, 4xx included, and the breaker is checked at the *top* of
  `evaluate()` — so three consecutive 401s opened it, every later call returned `fallback_decision()`, and the
  rule that makes a 4xx block was never reached. With shipped defaults (threshold 3, fallback `allow`) a
  revoked credential became a governance bypass. A 4xx now never opens the breaker; only genuine
  unreachability (5xx, timeout, connect error) honours the configured fallback.

Full notes: https://github.com/norviq-dev/norviq/releases/tag/v0.2.2

## [0.2.1] — 2026-08-18 — agent_class is attested, not asserted

- mint `role=service` credentials without an `agent_class` — they now get **403** on every evaluate. Set `auth.requireBoundAgentIdentity=false`, roll pods, re-issue keys, set it back
- rely on the baseline observing rather than blocking — **17 of 21 controls now ship `deny`**. Controls you set explicitly are untouched; ones you never touched move to their new default
- parse `GET /threats/attack-paths` — `cls` and `trust` can now be **null**, and `src_kind` is new
- set `NRVQ_API_URL` implicitly — it now follows `NRVQ_POLICY_ENGINE_URL` instead of defaulting to a name that only resolves in the API's own namespace
- run `helm install` with a `policyQuotaNamespaces` entry that does not exist — the chart now **refuses to render** instead of dying half-applied

Full notes: https://github.com/norviq-dev/norviq/releases/tag/v0.2.1

## [0.2.0] — 2026-08-11 — MCP action firewall, Visual Policy Builder, and Campaign 2 — chart not published

- The MCP action-firewall and Visual Policy Builder work, plus the security
- findings from Campaign 2 (a browser-driven red/blue campaign against a live
- AKS cluster).
- Enforcement fixes:
- the MCP answer plane compared the decision string by hand, so monitor

## [0.1.10] — 2026-07-30 — performance release

- Caller-observed enforcement latency on AKS: p50 115ms -> 59ms (-49%), p95 172ms -> 93ms (-46%).
- The dominant fix was a chart default, not code: the api CPU limit of 500m throttled the API on 92.5% of
- CFS periods, adding ~60ms of dead wait to every call. The same defect class was worse in the embedded
- sidecar profile, where it made that mode SLOWER than the proxy default it exists to beat.
- Also: redis[hiredis] (21x on the trust history read), credential redaction in logged connection URLs, and

## [0.1.9] — 2026-07-30

- (tag carries a subject only)

## [0.1.8] — 2026-07-29

- (tag carries a subject only)

## [0.1.7] — 2026-07-29

- (tag carries a subject only)

## [0.1.6] — 2026-07-28

- (tag carries a subject only)

## [0.1.5] — 2026-07-28

- (tag carries a subject only)

## [0.1.4] — 2026-07-28 — completes v0.1.3, whose wheel could not publish

- Completes v0.1.3, whose chart and images published but whose wheel could not: that tag carried a
- release.yml which published via a reusable workflow, a configuration PyPI's Trusted Publishing
- rejects. The upload is now inline, and the Trusted Publisher is registered against release.yml.
- Security:
- GHSA-537c-gmf6-5ccf (HIGH, CVSS 7.5) — cryptography floored at 48.0.1 in [project] dependencies

## [0.1.3] — 2026-07-28 — security floors

- Security:
- GHSA-537c-gmf6-5ccf (HIGH, CVSS 7.5) — cryptography floored at 48.0.1; wheels below it
- statically link a vulnerable OpenSSL. Declared in [project] dependencies so pip honours it.
- GHSA-mh99-v99m-4gvg — brace-expansion 5.0.8.
- GHSA-v2hh-gcrm-f6hx (HIGH, CVSS 7.5) — fast-uri 3.1.4.

## [0.1.2] — 2026-07-27 — first fully signed release

- Runtime policy enforcement for LLM agent tool calls on Kubernetes: a PEP/PDP that intercepts each call,
- resolves the workload's identity, evaluates it against OPA/Rego policy, and returns
- allow / block / escalate / audit before the tool runs.
- Supersedes two partial releases. v0.1.0 published only the wheel — the TLS-bootstrap image failed the
- fail-closed trivy gate because the kubectl baked into it vendored golang.org/x/net CVEs; kubectl is now

## [0.1.1] — 2026-07-27 — first complete public release — chart unsigned

- Supersedes v0.1.0, which published the PyPI wheel but failed to release the chart and images: the
- fail-closed trivy gate refused the bootstrap image because the kubectl binary baked into it vendored a
- golang.org/x/net with fixable HIGH/CRITICAL CVEs. kubectl is now removed entirely — the TLS bootstrap
- hooks talk to the Kubernetes API with curl and the pod's service-account token, so the image carries no
- Go runtime and passes the gate clean.

## [0.1.0] — 2026-07-27 — first public release — wheel only

- Runtime policy enforcement for LLM agent tool calls on Kubernetes: a PEP/PDP that
- intercepts each call, resolves the workload's identity, evaluates it against OPA/Rego
- policy, and returns allow / block / escalate / audit before the tool runs.
- Ships the engine, API, console, admission webhook and a first-party TLS-bootstrap image
- (all linux/amd64 + linux/arm64), the Helm chart, and the Python SDK with adapters for
