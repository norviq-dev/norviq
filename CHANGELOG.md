# Changelog

All notable changes, newest first. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow SemVer. Each 0.2.x entry is a summary — the linked GitHub release is the full account,
grouped by upgrade impact, security relevance and operator-visible behaviour. Entries for 0.2.0 and
earlier are taken from the annotated tags, the only record those versions have.

Nineteen released versions. The `pre-public-cleanup-20260712` tag is not a release and is omitted.
Three versions published incompletely — `v0.1.0` shipped no chart, `v0.1.1` shipped it unsigned,
`v0.2.0` shipped no chart — and their headings say so: they are listed because they happened, not
because they should be installed.

## [0.2.7] — 2026-11-10 — a pod that carries the injector's parts is refused

**Upgrade impact — read before `helm upgrade`.**

- **The admission webhook refuses a pod whose spec already carries any part the injector adds** (the
  sidecar, its volumes or mounts, `NRVQ_SOCKET_PATH`, the `norviq.io/injected` annotation, MCP proxy
  wrapping) with `NRVQ-WHK-4063`, opted out or not, and a pod placing its own volume, device or
  termination message file under a path the injector mounts at with `NRVQ-WHK-4034`. Re-creating a pod
  from an injected spec (`kubectl get pod -o yaml`, `kubectl debug --copy-to`) now needs the injected
  parts removed first. An opted-out pod running the sidecar image, whatever its command, is refused the
  same way. `NRVQ-WHK-4008` is retired. This covers pods the webhook sees: with `gateOnlyAgentPods` on
  (the default), a pod without `norviq.io/agent-class` never reaches it.
- **The enforcement socket directory (`/var/run/norviq`) is mounted `readOnly` into every container
  except the sidecar.** Containers still connect to the socket as before; a workload that wrote files of
  its own into that directory now gets a read-only filesystem error. `docs/security-model.md` lists what
  the mount does not cover. It takes effect as agent pods are re-created.
- **A client that cannot send a valid request to the engine now blocks the call instead of following
  `fallbackMode`** (bad token, URL or settings, TLS trust, proxy refusal, an answer that is not a
  decision, an unknown error), logged as `NRVQ-SDK-1018` by the SDK client and `NRVQ-SDC-3049` by the
  sidecar, and is not retried. A failure that looks like an outage still follows `fallbackMode`;
  `docs/security-model.md` lists them. Whitespace around `NRVQ_API_TOKEN` is stripped at load.
- **The sidecar blocks a request it cannot encode** (`NRVQ-SDC-3047`), as the SDK client has since
  0.2.6, instead of following `fallbackMode`.

**Security.** 0.2.7 contains security fixes; their advisories publish with the release. Bearer tokens
no longer appear in client error logs. The oauthlib floor moves to 4.0.1 (CVE-2026-49272) for the
crewai and frameworks extras, and the PyPI publish action to v1.14.3.

**Project.** Dependabot removed; dependency updates are made by hand and gated in CI (`SECURITY.md`).

## [0.2.6] — 2026-11-05 — the namespace baseline enforces by default

**Upgrade impact — read before `helm upgrade`.**

- **An agent identity must be one an admin can freeze.** The key API, the evaluator and the admin trust
  routes now share one rule: the id starts with `spiffe://`, is not empty or only whitespace after it, is
  valid UTF-8 without NUL (so both stores can hold it), and is at most 512 characters (the width of the agent-id columns; SPIFFE itself allows 2048 bytes, so longer
  ids are refused everywhere, consistently). `POST /api/v1/keys` refuses (`422`) a `spiffe_id` outside it. The evaluator blocks a call from such
  an identity with `invalid_spiffe_identity` (`NRVQ-ENG-2006`) in every posture: unlike other fail-closed
  blocks it is not softened in a monitor namespace, and no registry row is written for it. It used to check
  only the prefix; with the admin routes now refusing these ids, such an identity would get decisions that
  no freeze could reach. **Existing keys bound to such an
  id keep authenticating, but every evaluation for them now blocks**: re-issue them with a valid
  `spiffe_id`. Look for `NRVQ-ENG-2006` after the upgrade. Registry rows are unaffected.
- **The namespace baseline now blocks.** `baselineClusterPolicy.enforcementMode` defaults to `block`
  (it was `audit`). 20 of its 21 controls act on the call: 17 refuse it, `llm06_excessive_agency` refuses
  destructive tools and holds elevated ones for approval, and `mcp_definition_drift` and
  `mcp_definition_never_scanned` hold it for approval; `scope_violation_dangerous_tool` only records.
  The console's Baseline controls now default to the same: they showed `strict_default_block`,
  `llm02_data_leakage` and `base64_decoded_threat` at Monitor while the baseline blocked them. Measured
  before the change: 0 false positives over a 51-case benign corpus, with every control at deny. Three
  ways to turn it off, each recording the call instead of refusing it (a control switched Off is not
  evaluated at all):
  - every namespace: `--set baselineClusterPolicy.enforcementMode=audit`, the 0.2.5 posture (but see
    the next item for namespaces whose Baseline controls were saved);
  - one namespace: console Target Settings → **Monitor**, or `PUT /api/v1/settings?namespace=<ns>` with
    `{"enforcement_mode": "audit"}` (softens every block in that namespace, your own policies' too,
    except a trust freeze, an invalid agent identity and the rate limit);
  - one control: console Baseline controls → **Monitor** or **Off**, or `PUT /api/v1/baseline/controls`.

  `config.enforcementMode` is not one of them; it never softened a policy's block.
- **`baselineClusterPolicy.enforcementMode=audit` keeps the 0.2.5 posture only where nobody saved the
  console's Baseline controls.** Saved controls enforce whatever the chart's mode, in 0.2.5 too, and from
  0.2.6 they replace the chart's baseline in that namespace. But 0.2.5 stored only the controls that
  differed from its own defaults, which had `strict_default_block`, `llm02_data_leakage` and
  `base64_decoded_threat` at Monitor. In a namespace whose panel was saved under 0.2.5 with those three
  at Monitor — left there, or set there on purpose, which stored nothing because Monitor was the
  default — the 0.2.6 API recompiles the saved controls at startup with 0.2.6's defaults, and the three
  start refusing calls (`execute_sql` becomes `block` / `strict_default_block`), whatever
  `enforcementMode` says. A control 0.2.5 did store, saved at a value other than its 0.2.5 default,
  keeps that value. To keep the three recording, set them to **Monitor** in the panel and save; Monitor
  now differs from their default, so it is stored. `GET /api/v1/baseline/controls?namespace=<ns>`
  shows what each control is set to. A namespace nobody saved the panel for is unaffected beyond the
  default flip: `webhook/presets/strict.rego`, the chart's baseline, has not changed since 0.2.5, so if
  you already ran 0.2.5 with `enforcementMode=block` it refuses what it refused then, and now also for
  classes that have their own policy (next item). Saving the panel
  for the first time under an `audit` install has the same effect as above: that namespace starts
  acting at the effects the panel shows, the 20 at Enforce included, so set the ones you only want
  recorded to Monitor in the same save.
- **A class policy no longer loosens the baseline.** The namespace and cluster baselines are floors: a
  baseline control's block applies even where a class policy allows. Through 0.2.5 any class policy
  outranked the baseline (stored at priority 1), so an enforcing baseline would have switched off for
  every class that had a policy. To relax one control, set its effect in the console's Baseline
  controls; that applies to the whole namespace, because a class policy can no longer exempt itself.
  Once saved, a namespace's control effects replace the chart's baseline there, for every
  agent class, and each control does what the console shows; a control you did not change keeps doing
  what the baseline did. Controls saved by an earlier release are recompiled from their stored settings
  when the API starts, so they take effect without re-saving, and a control left at its old default
  takes the new one (Monitor becomes Enforce for the three above). The cluster baseline is not replaced.
  The saved controls replace the chart's copy only when they are this release's compile of the chart's
  own preset (the default `strict`). Next to a chart baseline on another preset, or one edited in a way
  the compiler does not reproduce (outside its CONTROLS region, or a new control id), both apply and the
  stricter wins, so there the panel relaxes nothing the chart refuses. A head added to the chart's
  CONTROLS region under an existing control id counts as part of that control: switching the control
  Off removes it with the rest of the control.
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
  re-learned from a neutral baseline), sessions, login-lockout and rate-limit counters, the policy and
  evaluation caches (rebuilt from Postgres), and the logout denylist. A token logged out under 0.2.5 is
  accepted again until its own expiry: within `auth.sessionTtlSeconds` (default 1h) for a console
  login, but a token minted with `norviq login --ttl` (or `token_mint --ttl`) lives as long as that
  `--ttl` said. To end every session instead, rotate the signing key in the same upgrade
  (`--set api.secretKey="$(openssl rand -base64 48)"`). That also invalidates every injected sidecar's
  credential and every other token signed with it, so restart your agent workloads afterwards so the
  webhook mints new ones. In a fleet, the hub and every spoke share that key: it signs join tokens and,
  unless OIDC client credentials are configured, the spokes' relay and puller tokens to the hub. Rotate
  it on the hub and on every spoke in the same change, or the spokes stop reaching the hub. **Everything
  in Postgres survives**: policies and their versions, the audit log, users and API keys, namespace
  settings, and the agent freezes and trust caps recorded in `agent_registry`. But the engine enforces
  freezes, trust caps and namespace posture from the store, not from Postgres, and an API process writes
  them into the store only when an admin changes one and once when it starts. **Until a 0.2.6 API pod
  starts after the empty Valkey is up, freezes, trust caps and namespace posture are absent from the
  store.** An absent freeze or cap is enforced as none, and an absent namespace posture falls back to
  the chart-wide setting. 0.2.5's API pods and the engine keep serving in between, and an API pod that
  started before the new Valkey did wrote into the old store, not this one. Nothing writes them back
  while the API runs, so if no API pod starts after Valkey, the gap stays open. If you rely on a
  freeze, scale that agent to zero across the upgrade. When `helm upgrade` has finished, run
  `kubectl -n <namespace> rollout restart deployment/norviq-api` and look for `NRVQ-API-7034` (freezes
  and caps) and `NRVQ-API-7063` (namespace posture) in the new pods' logs. `NRVQ-API-7035` or
  `NRVQ-API-7138` means that pod did not restore them; restart the API again. The same gap opens after
  any later loss of store data: a `FLUSHALL`, a store restart without persistence or from an older
  snapshot, a failover. Restart the API after any of those (Known issues, below). **Nothing is
  deleted:** 0.2.5's dump stays at the root of the volume, and `helm rollback` to 0.2.5 finds it. That
  rollback reloads the store as 0.2.5 left it, so a freeze or trust cap lifted under 0.2.6 is enforced
  again, and a token logged out under 0.2.6 is accepted again until it expires (0.2.5 keeps its denylist
  in the store only); 0.2.5's API writes back what Postgres holds when it starts, so a freeze or cap set
  under 0.2.6 stays. A later upgrade picks Valkey's data up from where it was at the rollback. The
  start-up write adds what Postgres holds but removes nothing, so a freeze or trust cap you lifted while
  rolled back to 0.2.5 is enforced again after the re-upgrade if Valkey held it at the rollback. Lift a
  freeze or cap that came back with `norviq agent reset-trust <id> --score 1.0`, which also clears the
  agent's cap; to lift only a freeze and keep a cap, send that cap instead (`--score 0.5` clears the
  freeze and sets the cap to 0.5). Stores you run yourself (`redis.enabled=false`) are unaffected.
- **HA (`redis.ha.enabled=true`, as in `values-prod.yaml`) moves from Redis 7.4 to Valkey 8.1, as a
  new failover that starts empty.** The RedisFailover's redis and sentinel pods now run
  `redis.ha.image`, default `valkey/valkey:8.1-alpine` (BSD-3-Clause, digest-pinned). Through 0.2.5 the
  redis pods ran `images.redis` (`redis:7-alpine`, by then Redis 7.4, RSALv2/SSPLv1) and the sentinels
  ran the operator's own default image. The key keeps its `redis` name. Valkey cannot take over 0.2.5's
  failover in place: Redis 7.4 writes RDB format 12, in its dumps and in the full sync it sends a
  replica, and Valkey 8.1 reads format 11 at most, so it can neither load the old volumes nor replicate
  from the old master (it exits with `Can't handle RDB format version 12`). `helm --wait` does not watch
  the operator's pods, so a rolling swap would have reported success while redundancy drained away.
  The failover is therefore renamed from `norviq-redis-ha` to `norviq-valkey-ha`: `helm upgrade`
  creates it on new volumes (StatefulSet `rfr-norviq-valkey-ha`) and deletes the old RedisFailover.
  The master Service keeps its name (`redis.ha.serviceName`, default `norviq-redis-ha`), so
  `NRVQ_REDIS_URL` is unchanged; the Service has no endpoints until the operator has elected a Valkey
  master, and the API's own retry covers that window. **The store starts empty**, with the same
  consequences as the bundled store's upgrade above: trust history, behavioural profiles, sessions,
  counters, caches and the logout denylist are reset, and freezes, trust caps and namespace posture
  are absent from the store until an API pod starts against it. Do the same afterwards: when `helm
  upgrade` has finished and the `rfr-norviq-valkey-ha` pods are Ready, run `kubectl -n <namespace>
  rollout restart deployment/norviq-api` and look for `NRVQ-API-7034` and `NRVQ-API-7063`. Everything
  in Postgres survives. **Unlike the bundled store, 0.2.5's data is not kept for a rollback.** The
  Spotahome operator gives a failover's volume claims an owner reference to their RedisFailover unless
  `keepAfterDeletion` is set, which 0.2.5's chart did not set, so deleting `norviq-redis-ha` lets
  Kubernetes delete its claims, and their volumes then follow the storage class's reclaim policy. A
  `helm rollback` to 0.2.5 brings back an empty Redis 7.4 failover (and deletes the Valkey one the same
  way). If you want a copy of the old store, take it before the upgrade (`redis-cli --rdb` against the
  master); only Redis 7.4 or later can read it. Pointing `redis.ha.image` back at a Redis image does not
  avoid the new, empty failover: the name changes whatever it runs. If you overrode `images.redis` for
  HA, move that override to `redis.ha.image`.
- **OPA 1.21 rejects an empty collection literal that is read from, and a few other forms 1.19
  accepted.** OPA moves from 1.19.1 to 1.21.4 (see Security). Its type checker types a bare `{}`,
  `set()` or `[]` as having no members, so `names[x]`, `names[_]`, `not names[x]` or `xs[_]` over one is a
  compile error, and so is comparing a collection whose contents it knows with an empty literal
  (`limits == {}`, or `L == set()` after `L := set()`). `count()` still accepts an empty literal. Also new
  since 1.19: `in` is type-checked (`1 in {"a"}` is an error), and under `import future.keywords` a rule
  named `and` or `or`, or a `not` directly before a brace literal (`not {"a"}[x]`), is a parse error. A
  policy that does not compile blocks every call it governs as `evaluator_error`.
  **Norviq's own policies are handled.** The builder, composer, intent, capability, MCP-registry and
  egress generators now write typed empty forms (same value, same kind). Policies stored by 0.2.5 and
  earlier are compiled with those exact generated lines rewritten the same way, never a line inside a
  raw string, and only in a module carrying the generator's own header — except that `allow_names` /
  `allow_skeletons := {}` are rewritten in any `package norviq.intent.*` module and `cap_tools := {}` in
  any `package norviq.remediation.capability.*` module, hand-written or not (the replacement is the same
  value). The stored row is not changed, so `helm rollback` reads it as it was. `NRVQ-ENG-2070` logs each
  rewritten policy once. **Other hand-written Rego is not rewritten.** Check yours before upgrading with
  the 1.21.4 binary and the chart's capabilities file, which catches every case above:
  `curl -fsSLO https://github.com/open-policy-agent/opa/releases/download/v1.21.4/opa_linux_amd64_static`,
  `echo "2ab571f367f293bb19523b76f92f1945bbf245003392c7f392903f95c2b9b630  opa_linux_amd64_static" | sha256sum -c -`
  (OPA's published checksum, the one the api and engine images pin), then
  `chmod +x opa_linux_amd64_static && ./opa_linux_amd64_static check --v0-compatible --capabilities=helm/norviq/files/opa-capabilities.json <policy>.rego`.
  Write an empty literal you read from as a comprehension that yields nothing, of the same kind: `{}` as
  `{k: k | k := ""; false}`, `set()` as `{s | s := ""; false}`, `[]` as `[s | s := ""; false]`; and test
  emptiness with `count(x) == 0` rather than `x == {}`. After the upgrade `NRVQ-ENG-2071` names any policy
  OPA still refuses to compile (its key and OPA's error).
- **Third-party images are pinned by digest.** opa, valkey, postgres, nginx, busybox, curl, the CNPG
  operand and the HA failover's redis render as `repo:tag@sha256:…` (`global.thirdPartyImageDigests`). With `global.imageRegistry`
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
- **`DELETE /api/v1/agents/{spiffe_id}` answers `409` while the agent is frozen or under a trust cap.**
  The registry row it deletes is the durable copy of both, so deregistering used to lift them: the
  identity came back unfrozen on its next call. Lift the control first with `PUT .../trust` and score
  `1.0` (logged with its actor), then delete. DELETE still keeps the agent's history and profile. A
  frozen or capped agent is no longer aged out by `agentRegistryRetentionDays` either. To clear an
  agent's behavioural record, use the new `POST /api/v1/agents/{spiffe_id}/trust/reset` (CLI
  `norviq agent reset-history`): admin only, logged as `NRVQ-API-7145` with the actor, the score and
  violation count before, and the keys cleared. It does not lift a freeze or cap.
- **`PUT /api/v1/agents/{spiffe_id}/trust` answers `503` when the freeze or cap was not persisted.** It
  used to log `NRVQ-API-7033` and answer `200`. A freeze or cap on an agent the registry has not seen yet
  now creates its registry row, so the next API start writes it back after a store loss. Before, it
  lived only in Redis. With Redis down a freeze or a new or lower cap is persisted and answers `503` (it
  takes effect at the next API start) where it was a `500`; a lift changes nothing. Admin trust writes for one agent (PUT trust,
  DELETE, the reset) are serialized by a per-agent Postgres lock, so two of them on different replicas
  no longer interleave. The lock is held across the store write, and a
  tightening reaches the store before the registry while a loosening reaches it only after its commit;
  every store write is fenced, so a late one cannot land over a newer change. When something fails the
  store is never looser than the registry, except when the store itself cannot take a tightening, which
  the `503` reports as "NOT confirmed live". A freeze that finds another change in progress, or no database, is
  still applied live, not persisted; a change already under way can replace it when it finishes, and the
  `503` says to check the agent. A starting API's write-back of freezes
  and caps takes the same locks in batches, so it no longer restores a cap or freeze another replica
  changed while it ran, and a retried write-back resumes where it stopped. The three routes answer
  `422` for an id without the `spiffe://` prefix, empty or only whitespace after it, or over 512 characters. A change that finds the agent locked by another past the lock timeout (3 s by
  default) is a `503` that applies nothing except a freeze, which goes live unpersisted (`NRVQ-API-7149`).
  The connection an admin change holds the agent's lock on sets `idle_session_timeout`,
  `idle_in_transaction_session_timeout` and TCP keepalives, so a lock left by an API node that vanished is
  released in about 35 s, not hours; the boot write-back's lock-holding transactions run on a connection
  configured the same way. The boot write-back skips an agent whose lock is held, writes every other one,
  names the skipped ones (`NRVQ-API-7160`, ERROR) before retrying them for at most 2 s, and names any still
  unwritten. Freezes applied while the agent's lock was unavailable no longer make the next changes to
  that agent fail; a change the store refused because a newer one owns the agent says so ("refused: a
  newer change owns the agent") instead of reporting that the store did not answer. A Postgres that stops
  answering in the middle of a change no longer holds that request for about a minute: its reads and the
  lock release are bounded (statements at `db_command_timeout`, never under 3 s, and a connection whose
  statement was cut off is given up at once; an ordinary release at 2 s), so a freeze goes live in about
  5 s, also when Postgres stops after the registry read or at the commit: a
  freeze that cannot be persisted is applied live through the fence. A retry within about 30 s of such a
  partition may be answered "in progress" while Postgres still holds the orphaned backend's lock.
  `NRVQ-API-7033` carries the failing stage (`registry`, `pool`, `admin_slots`, `fence_token`, `persist`)
  and the underlying error. `NRVQ-API-7031` names the
  actor.

**Building from source.** `webhook/go.mod` says `go 1.26.10` (was `1.26.0`): on go1.26.0, govulncheck
reports 47 standard-library advisories, 29 of them reachable from the webhook. An older Go fetches
1.26.10 by itself unless `GOTOOLCHAIN=local` is set, and then the build fails with
`go.mod requires go >= 1.26.10`. The official `golang` images set it, so a local `docker build` of the
webhook from a cached `golang:1.26-alpine` older than 1.26.10 needs `--pull`. `golang.org/x/net` moves
to 0.62.0 (GO-2026-6860, GO-2026-6866).

**Security.** 0.2.6 contains security fixes; their advisories publish with the release.
Dependency floors for pyjwt, aiohttp, urllib3, anyio, multidict, certifi and opentelemetry;
DOMPurify 3.4.17 in the console.
The lock moves cryptography from 50.0.0 to 50.0.2 and idna from 3.18 to 3.20; urllib3 stays at 2.8.0.
Image builds now move `-latest` and version tags only after the scan and signature pass. The FOSSA
dependency gate grades Python again: from 2026-08-19 `.fossa.yml` named the Python target `type: pip`,
which is not a fossa-cli type, so no Python package was scanned and the gate passed on the console and
the webhook alone. The target is `setuptools`, the scanned closure is the one the images install
(`.[spiffe]`), and the job fails when a graph is missing from the scan summary or a line of the Python
input is not in a form fossa-cli reads. The report-only dependency audit now covers every optional
extra as well. In SECURITY.md's accepted exceptions, React Router GHSA-qwww-vcr4-c8h2 is removed (the
pinned 7.18.2 is the first patched release), and chromadb CVE-2026-45830, -45831 and -45833 are added
(no fixed release; reachable only through the optional `crewai` and `frameworks` extras, in no
image). OPA moves from 1.19.1 to 1.21.4 in the sidecar image, the api and engine images and CI: 1.19.1's
static binary carries 9 fixable HIGH findings (Go stdlib, x/crypto, x/net, x/text, grpc) that fail the
image scan, and every OPA release that clears them is 1.21.2 or later. The API's TLS terminator moves
from `nginx:1.27-alpine` to `nginx:1.30-alpine`, the console's base from
`nginxinc/nginx-unprivileged:1.27-alpine` to `1.30-alpine`, and the `helm test` pod from
`curlimages/curl:8.10.1` to `8.23.0`. nginx 1.27 and its Alpine 3.21 base are end of life; Trivy
(HIGH/CRITICAL, fixable only) reported 60 findings in the terminator, 58 in the console base before the
build's `apk upgrade`, and 22 in curl. A mirror behind `global.imageRegistry` needs the new tags copied
(digest-preserving) before the upgrade. The first-party bootstrap image (the chart's TLS hooks) moves
from `alpine:3.21` to `alpine:3.24`: Alpine 3.21 left security support on 2026-11-01.
Image hardening: pip is removed from the api and engine runtime images, and the webhook image's base moves
from distroless `static-debian12` to `static-debian13`.

**Fixed.** `global.imageRegistry` relocates the busybox init image. An agent that retries one refused
call no longer loses trust on every attempt. An MCP client that calls tools without listing them
after the proxy restarts (a stateless HTTP client, or one reusing its old tool list) no longer has
every call held for approval by `mcp_definition_never_scanned`: the proxy lists the server itself
and scans the answer through Gate A before deciding the call, so withheld, drifted and quarantined
tools are still refused. If that list fails the call is escalated as before and `NRVQ-MCP-5080` says
why; `NRVQ_MCP_COLD_LIST_TIMEOUT_S` (default 5s, `0` off) bounds it. The MCP HTTP proxy's SSE handling is stricter about
framing; content it cannot parse is not forwarded. The MCP proxy no longer forwards a server response it
cannot match to a well-formed answer to one of the client's requests. The annotations the MCP proxy adds for the client no
longer include excerpts of the server content they describe. The HTTP MCP proxy reads at most
`NRVQ_MCP_HTTP_MAX_MESSAGE_BYTES` (default 8 MiB) of one upstream message on a client-facing path and
fails closed above it (`NRVQ-MCP-5085`); a server that writes one message over several SSE `data:`
lines now reaches the client intact. Behind the HTTP MCP proxy: responses a server sends on a
plain GET stream are dropped (servers must not send them there); SSE event ids reach the client as ids
the proxy issues, which it maps back when the client resumes; and a server's `Mcp-Session-Id` reaches
the client on the response to `initialize`, or when it is the client's own (`NRVQ-MCP-5087` when one is
withheld). The HTTP MCP proxy passes on only the status and headers of the server's answer to a
session `DELETE`, and does not read the server's reply to a refusal it posts back. The MCP proxy refuses a
JSON-RPC message in which an object names a key twice, or names two keys that differ only by case or
compatibility form, in either direction; it also refuses a client message whose key differs from a
protocol field only that way. The HTTP MCP proxy no longer stores cookies an upstream server sets; a client's own
`Cookie` header still reaches the server on that client's requests. Server messages whose structure carries a key that
differs from a protocol field only by case or compatibility form are withheld or refused
(`NRVQ-MCP-5091`), and a tool call whose arguments are too large to inspect for outbound-header
parameters is refused. A message containing `NaN`, `Infinity` or a number too large for a double is refused in
either direction. The MCP proxy refuses a message nested more than 128 levels deep, and the SDK blocks a call
whose evaluate request it cannot encode (`NRVQ-SDK-1016`) instead of applying the outage fallback. An MCP tool
definition, or a resource or prompt list entry, that is too large or too deeply nested for Gate A to
read in full is withheld. Gate A reads every key and every string of a tool definition and of the
other surfaces it scans in full, with no per-field cut-off, and charges its scan budget by the length
text folds to. A notification, handshake result or demand for input too large for Gate A to read in
full is withheld (`NRVQ-MCP-5092`–`5094`), as is a prompt or elicitation, whatever the strip
threshold. Strings without whitespace (property names, enum values, defaults) are checked only for a
dangerous URI scheme followed by code, an instruction-fencing tag such as `<IMPORTANT>`, an
instruction override written as a full directive such as "ignore all previous instructions" (a
property name that only names the setting, such as `ignore_the_system_prompt`, is not one), and the
model's or user's sensitive data (the conversation, earlier messages, the system prompt, the user's
files, keys or messages, file contents, environment variables, tool results) sent to a URL or e-mail
address,
with underscores, dots and camelCase read as word breaks; credential names such as `api_key` or
`.env.example` on their own no longer flag a tool. Text split across fields is matched when the match
spans fields. A line break separates words but ends a sentence. A description that only mentions a
credential (such as the API key a tool takes), the server's own logging, a tool sending anything
else to its destination (a webhook, notification or upload URL), documentation of how to pass an
argument (a page token, an id, the user's locale), a bare Llama `[INST]` token
or a `javascript:` URL it rejects is annotated rather than withheld, and a markdown heading such as
`## Important` is not a marker unless a takeover directive such as "ignore all previous instructions"
follows it. A
`system:`/`assistant:`/`developer:` line is treated as a role takeover only when its text starts with
an instruction word (as listed in the MCP guide), so `system:masters`, `{{system.hostname}}` and most
docstring parameter lists and few-shot templates are not withheld. Known issues: some ordinary descriptions are still withheld — a forwarding tool described as sending
all messages to a webhook, an upload tool described as uploading the file contents to a storage URL
(both graded critical, so only rephrasing the description helps), a description naming a
`javascript:` URL followed by code, a docstring or few-shot line whose role label is followed by an
instruction word, and `<system>` as an XML tag-name example (graded high: rephrase, or raise
`mcp_scan_strip_severity` and `mcp_scan_sanitize_severity` to `critical` for that deployment). Known
detection limits: text split exactly between two words across fields with no whitespace, a
directive wrapped onto a second line within one sentence, the reduced rule set for strings without
whitespace, and paraphrase. The MCP guide lists both.
Two security booleans no longer fall back to off when an
overlay nulls them. The stdio MCP proxy warns when its pin store degrades. The API and the
embedded engine retry Postgres and Redis at startup, 5 attempts with 1, 2, 4 and 8 s between them, and then
fail startup so the pod restarts; a refused Postgres connection used to end the API's startup at once, and the
embedded engine retried neither store. A failed boot warm of agent freezes and trust
caps is retried (3 attempts) and then logged at ERROR, `NRVQ-API-7035`; it was a WARNING, and the count
it returned read like nothing was frozen. The boot warm of namespace posture is retried the same way
before its ERROR, `NRVQ-API-7138`.

**Console.** The console now uses the system font stacks; no web fonts are bundled.

**Project.** SECURITY.md names the response team and sets out the disclosure process, a 90-day
embargo, the security bulletin channel, a supported-versions table and how dependencies are managed.
New: issue and pull request templates (the pull request template asks for a DCO sign-off), an OpenSSF
Security Insights file (`security-insights.yml`) and a CLOMonitor file (`.clomonitor.yml`). The README
gains Scope and SBOM sections, a note on community channels and the Artifact Hub badge. NOTICE now
reproduces the NOTICE files of the console's and the webhook's Apache-2.0 dependencies, and
`scripts/ui_third_party_notices.py` collects the licence files of the console's JavaScript
dependencies.

**Known issues.** Agent freezes, trust caps and namespace posture are persisted in Postgres but
enforced from the store, and the store copy is written only by the admin change and once when an API
process starts. After a loss of store data while the API keeps running (a `FLUSHALL`, a store restart
without persistence or from an older snapshot, a failover) they are absent, and enforced as not frozen,
uncapped and the chart-wide posture, until an API pod restarts. Earlier releases behave the same. After
any such event run `kubectl -n <namespace> rollout restart deployment/norviq-api` and look for
`NRVQ-API-7034` in the new pods' logs. A store restored from an older snapshot can also bring back a
freeze or cap lifted since: the restart adds what Postgres holds and removes nothing, so lift it again
with `norviq agent reset-trust <id> --score 1.0` (which clears a cap too; `--score <cap>` lifts the
freeze and keeps that cap). Details in docs/trust-score-design.md §5.

One MCP listing page is scanned within a fixed budget: about 1235 ordinary entries of ~180 characters
each. Entries past it are withheld, never forwarded unscanned, and logged as `NRVQ-MCP-5067`
(`mcp_a_scan_budget_exhausted`); a server that paginates its listings stays within it per page. The
MCP guide (§3.1) states the limit.

An admin trust change (`PUT /api/v1/agents/{spiffe_id}/trust`) that fails part-way answers `503` saying
which state it left: a tightening may be live without being persisted, a loosening the registry took may not
be live yet, and a tightening the store did not confirm is persisted but NOT confirmed live (the store may then enforce
the previous, looser state until the next successful change to that agent or the next API start). Retry
the change.

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
