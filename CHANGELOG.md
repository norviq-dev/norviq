# Changelog

All notable changes, newest first. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow SemVer. Each 0.2.x entry is a summary — the linked GitHub release is the full account,
grouped by upgrade impact, security relevance and operator-visible behaviour. Entries for 0.2.0 and
earlier are taken from the annotated tags, the only record those versions have.

Seventeen released versions. The `pre-public-cleanup-20260712` tag is not a release and is omitted.
Three versions published incompletely — `v0.1.0` shipped no chart, `v0.1.1` shipped it unsigned,
`v0.2.0` shipped no chart — and their headings say so: they are listed because they happened, not
because they should be installed.

## [Unreleased] — 0.2.6 — the namespace baseline enforces by default

**Upgrade impact — read before `helm upgrade`.**

- **The namespace baseline now blocks.** `baselineClusterPolicy.enforcementMode` defaults to `block`
  (it was `audit`). 20 of its 21 controls refuse the call (two MCP controls hold it for approval
  instead); `scope_violation_dangerous_tool` only records. The console's Baseline controls now default to
  the same: they showed `strict_default_block`, `llm02_data_leakage` and `base64_decoded_threat` at
  Monitor while the baseline blocked them. Set `baselineClusterPolicy.enforcementMode=audit` to keep the
  0.2.5 posture. Measured before the change: 0 false positives over a 51-case benign corpus, with every
  control at deny.
- **A class policy no longer loosens the baseline.** The namespace and cluster baselines are floors: a
  baseline control's block applies even where a class policy allows. Through 0.2.5 any class policy
  outranked the baseline (stored at priority 1), so an enforcing baseline would have switched off for
  every class that had a policy. To relax one control, set its effect in the console's Baseline
  controls: once saved, a namespace's control effects replace the chart's baseline there, for every
  agent class, and each control does what the console shows; a control you did not change keeps doing
  what the baseline did. Controls saved by an earlier release are recompiled from their stored settings
  when the API starts, so they take effect without re-saving, and a control left at its old default
  takes the new one (Monitor becomes Enforce for the three above). The cluster baseline is not replaced.
- **Agents that install packages are refused.** `llm05_supply_chain` blocks `install_package`,
  `load_plugin`, `download_script` and `eval` by tool name, including installs from public PyPI. Set
  that control to `monitor`, or allow the tool in your own policy.
- **Callers of `norviq-engine:8282` from other pods must send a service token**, the same Bearer token
  `/api/v1/evaluate` takes. Nothing in the chart calls it.
- **Local sidecar image names are refused unless you opt in.** `norviq/norviq-engine:*` is accepted
  only with `webhook.allowLocalSidecarImages=true`. Published images are unaffected.
- **Default Redis is Valkey 8.1, and an upgrade from 0.2.5's bundled Redis starts it with an empty
  store.** `valkey/valkey:8.1-alpine` (BSD-3-Clause, minor-pinned) replaces `redis:7-alpine`, which had
  moved to Redis 7.4 and its RSALv2/SSPLv1 licence. Redis 7.4 writes RDB format 12, which Valkey 8.1
  cannot read. Pointed at 0.2.5's data on `norviq-redis-pvc`, it exits with `Can't handle RDB format
  version 12` and `helm upgrade` times out. Valkey now keeps its data in a `valkey/` subdirectory of
  that volume, so it starts empty. **That resets** trust history and behavioural profiles (agents are
  re-learned from a neutral baseline), the logout denylist (a token logged out under 0.2.5 is accepted
  again until it expires, at most `auth.sessionTtlSeconds`, default 1h), sessions, login-lockout and
  rate-limit counters, and the policy and evaluation caches, which are rebuilt from Postgres.
  **Everything in Postgres survives**: policies and their versions, the audit log, users and API keys,
  namespace settings, and the agent freezes and trust caps recorded in `agent_registry`. Each API pod
  writes those back into the store when it starts. Look for `NRVQ-API-7034` in an API pod's log after
  the upgrade. `NRVQ-API-7035` means they were not restored, so restart the API. **Nothing is
  deleted:** 0.2.5's dump stays at the root of the volume, and `helm rollback` to 0.2.5 finds it. A
  later upgrade picks Valkey's data up from where it was at the rollback. Stores you run yourself
  (`redis.enabled=false`) are unaffected.
- **`redis.ha.enabled=true` is not covered by that.** The RedisFailover keeps Redis 7.4 dumps on its own
  volumes (`norviq-redis-ha-data-*`), which the chart cannot redirect, and a Valkey replica cannot load
  a full sync from a Redis 7.4 master. Keep `images.redis` on `redis:7.4-alpine` under HA until you
  migrate it yourself.
- **Third-party images are pinned by digest.** opa, valkey, postgres, nginx, busybox, curl and the CNPG
  operand render as `repo:tag@sha256:…` (`global.thirdPartyImageDigests`). With `global.imageRegistry`
  the digest is kept, so a mirror filled by `docker pull` + `docker push` (which changes the digest)
  fails with `manifest unknown`: re-copy with `crane copy` / `skopeo copy --all`, or set
  `global.thirdPartyImageDigests=null`. An overridden tag renders without a pin.
- **The optional SDK extras need newer frameworks.** `norviq[crewai]` requires `crewai[litellm]>=1.15.29`
  (was `>=1.0`) and `norviq[langgraph]` requires `langgraph>=1.2.14` (was `>=0.2`). `norviq[crewai]`,
  `norviq[mcp]` and `norviq[frameworks]` require `mcp>=1.30.0,<2` (was `>=1.28.1,<2`), and
  `norviq[frameworks]` takes the same crewai and langgraph floors (its crewai floor was `>=0.80`). An
  install that also pins an older crewai, langgraph or mcp no longer resolves; pip reports the conflict.
  The floors close CVE-2026-118667 (langgraph) and CVE-2026-59951, -116684, -116685 and -116686 (mcp);
  the crewai floor follows from the mcp one, because crewai 1.15.6 through 1.15.28 pin `mcp~=1.28.1`.
  `pip install norviq` and the images (`.[spiffe]`) are unaffected.
- **`auth.enabled: false` and `oidc.legacyHs256Enabled: false` now take effect.** Earlier charts rendered
  both as `"true"`, so local password login and HS256 tokens stayed accepted (the fleet hub's ConfigMap
  likewise). If you set either, make sure nothing still signs in with a local password or an HS256 token
  before you upgrade. The fleet hub's `config.requireStrongSecret` also follows the spoke now: a nulled key
  means on, not off.

**Building from source.** `webhook/go.mod` says `go 1.26.10` (was `1.26.0`): on go1.26.0, govulncheck
reports 47 standard-library advisories, 29 of them reachable from the webhook. An older Go fetches
1.26.10 by itself unless `GOTOOLCHAIN=local` is set, and then the build fails with
`go.mod requires go >= 1.26.10`. The official `golang` images set it, so a local `docker build` of the
webhook from a cached `golang:1.26-alpine` older than 1.26.10 needs `--pull`. `golang.org/x/net` moves
to 0.62.0 (GO-2026-6860, GO-2026-6866).

**Security.** Fixes in the engine's caller authentication, logout token revocation, the webhook's
sidecar image trust and two chart authentication switches that could not be turned off; details in the advisories published with this release. Dependency floors for
pyjwt, aiohttp, urllib3, anyio, multidict, certifi and opentelemetry; DOMPurify 3.4.17 in the console.
Image builds now move `-latest` and version tags only after the scan and signature pass. The FOSSA
dependency gate grades Python again: from 2026-08-19 `.fossa.yml` named the Python target `type: pip`,
which is not a fossa-cli type, so no Python package was scanned and the gate passed on the console and
the webhook alone. The target is `setuptools`, the scanned closure is the one the images install
(`.[spiffe]`), and the job fails when a graph is missing from the scan summary or a line of the Python
input is not in a form fossa-cli reads. The report-only dependency audit now covers every optional
extra as well. In SECURITY.md's accepted exceptions, React Router GHSA-qwww-vcr4-c8h2 is removed (the
pinned 7.18.2 is the first patched release), and chromadb CVE-2026-45830, -45831 and -45833 are added
(no fixed release; reachable only through the optional `crewai` and `frameworks` extras, in no
image).

**Fixed.** `global.imageRegistry` relocates the busybox init image. An agent that retries one refused
call no longer loses trust on every attempt. Two security booleans no longer fall back to off when an
overlay nulls them. The stdio MCP proxy warns when its pin store degrades.

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
