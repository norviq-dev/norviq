# Backlog

Open work, carried out of the 0.2.5 cycle. One rule for this file: **every item states how it was
verified, or says plainly that it was not.** An unverified item is a lead. A lead that gets written
down as a finding is how a wrong fix ships — most of this file exists because that nearly happened
several times in the cycle that produced it.

Status vocabulary: **verified** = reproduced against the artefact or source by hand, with a control
where a clean result was possible. **reported** = an agent or a scan claimed it; nobody has
reproduced it. **landed** = fixed on `main`, waiting on a release.

---

## 1. Waiting on the next cut

### 1.1 `deny_shell_execution` caveat — landed, unreleased
**Status:** landed (`f11a6b8`), not in 0.2.5.

The caveat served by `GET /baseline/controls` and rendered beside the console's Enforce toggle said,
in the present tense, that the control "trips roughly 1 in 8 times" on ordinary order ids. That was
fixed in 0.2.1. The control ships `default_effect="deny"`, so the console was warning operators off
enforcing something whose stated cost no longer exists.

Ships with 0.2.6. No cut is needed on its own account: it is a display string, the chart renders
byte-identical to `v0.2.5` (verified — excluding the `randAlphaNum` secrets that differ on every
`helm template` run), and there are no customers reading it today.

**Note the asymmetry while it waits:** `docs.norviq.dev` is already corrected and live, so the site
says the false positive was fixed in 0.2.1 while the shipped console still calls it current.

---

## 1a. Quickstart gate — RUN, and it passes

**Status:** verified 2026-08-24 end to end on a clean cluster. **The documented path takes 88
seconds**, 8/8 pods Running, `helm install` exit 0 on the first attempt.

| stage | elapsed | in the product's path? |
|---|---|---|
| `helm install` from the published chart, pulling 5 digest-pinned + 4 third-party images | **88s** | **yes — this is the quickstart** |
| `kind create cluster` | 53s | no — test-rig scaffolding, see below |

Usability was checked, not assumed: the documented password retrieval
(`kubectl get secret norviq-secrets ... | base64 -d`) returns a 20-character value, the documented
port-forward serves the console at HTTP 200 (`<title>Norviq Security Console</title>`), and the API
answers `/healthz` 200. The README's command was run **verbatim**, including
`--set config.dbSslMode=disable` and `policyQuotaNamespaces={default}` — not the variant known to work.

**Measured on one machine:** macOS arm64, fast network. A fresh kind node has its own empty
containerd, so the image pulls were real. A slower link moves the 88s and nothing else.

### The README's prerequisite is deliberate, not a gap

An earlier draft of this entry recommended adding `kind create cluster` to the README Quick start,
on the reasoning that "a Kubernetes cluster (1.30+)" leaves a newcomer stranded. **That
recommendation was wrong and has been removed.** Norviq targets corporate Kubernetes: an evaluator
arrives with EKS, AKS, GKE or an on-prem cluster already running. Putting `kind` in the Quick start
would position a runtime security product as a laptop toy and invite people to evaluate it on a
single-node cluster where the HA, quota and multi-namespace behaviour it exists to provide cannot be
exercised.

The 53s above is therefore scaffolding for THIS measurement, not a step any target user performs. It
is recorded so nobody re-derives a 141s figure and reports it as the install time.

### One finding stands

**There is no documented "10-minute quickstart" to gate.** The phrase appears exactly once in the
repo — a code comment at `scripts/kind-e2e/00-up.sh:43`, an internal note about where a precondition
check belongs. It is not a user-facing promise anywhere in README, docs/, or the docs site. The
measurement now supports making a claim if one is wanted (88s onto an existing cluster); what should
stop is treating an internal comment as a public commitment.

**Not a gap, checked because one was expected:** login is documented in three independent places —
`README.md:169-177`, `docs/getting-started.md:107`, and the chart's post-install NOTES — including the
sharp edge that the Secret holds only the FIRST password and is stale after the forced change.

---

## 2. Product defects — verified

### 2.1 `busybox:1.36` is not relocatable, and air-gap installs will fail on it
**Status:** verified. **Severity:** first-run blocker on air-gapped clusters.

`helm/norviq/templates/_helpers.tpl:249` hardcodes `image: busybox:1.36` with no
`norviq.thirdPartyImage` wrapper, unlike every other third-party reference. Rendering with
`--set global.imageRegistry=myreg.example.com` relocates opa, redis, postgres, nginx and curl, and
still emits bare `busybox:1.36`.

On a cluster with no path to Docker Hub, api and engine sit in `Init:0/2` on an `ImagePullBackOff`
for busybox while every other image resolves — the failure names an image the operator never chose
and cannot move.

`docs/deployment.md` (and the docs site) list `busybox:1.36` among the images `global.imageRegistry`
covers, which is exactly backwards. Fix the helper; the doc row is then true as written.

Repro:
```
helm template norviq helm/norviq -n norviq --set policyQuotaNamespaces='{a}' \
  --set global.imageRegistry=myreg.example.com | grep busybox
```

### 2.2 External datastores via `existingSecret` render no wait containers
**Status:** verified with a control.

`norviq.waitFor` (`_helpers.tpl:246`) now opens with `{{- if .host -}}`, and the pg/redis wait-host
helpers return `""` when `host` is unset and the bundled store is disabled. With the
`existingSecret`-only external path — the one `docs/configuration.md` recommends, because the
credential should not pass through values — **api and engine get no dependency gate at all** and
retry their own connections instead.

Measured: bundled datastores render 5 busybox references; `--set postgresql.enabled=false
--set postgresql.existingSecret=my-pg --set redis.enabled=false --set redis.existingSecret=my-redis`
renders 1 (the webhook's wait-for-api). The control is what makes this trustworthy — 5-vs-1, not
0-vs-0.

This is *better* than the 0.2.3 behaviour it replaced, where the guard rendered `nc -z` against a
bundled Service name that `enabled: false` never creates, so pods waited forever. But the docs still
describe the old universal guarantee.

**Decide:** is the missing gate intended (the app retries anyway) or should `existingSecret` grow an
optional `host` for the gate? Then make the docs match whichever it is.

---

## 3. Docs drift — verified, not yet fixed

Two claims on `docs.norviq.dev` that the 0.2.5 audit confirmed stale and that were left alone
because both depend on decisions above, not on wording:

| page | claim | why it is wrong |
|---|---|---|
| `deployment.md:370` | `global.imageRegistry` covers `busybox:1.36` | it does not — see 2.1 |
| `deployment.md:502` | "`initContainers` gate api/engine on Postgres **and** Redis … so Helm's apply order never matters" | not on the `existingSecret` path — see 2.2 |
| `configuration.md:410` | the `postgresql.existingSecret` row inherits the same assumption | as above |

Everything else the audit found — 18 confirmed stale claims across 20 pages — was fixed in
`norviq-docs@80ec64c` and is live. 124 claims were checked and found still true; 6 staleness reports
were refuted on inspection.

---

## 4. Debt held by a ratchet

### 4.1 Log codes that name more than one thing
**Status:** measured, frozen, shrinking only.

`tests/test_log_code_uniqueness.py` freezes two lists:

* **40 codes** emitted at both an alertable level (`warning`/`error`/`critical`) and a routine one
  (`debug`/`info`). All 40 were reviewed; none hides a security signal behind routine traffic. Mostly
  a debug trace beside a warning in the same module.
* **52 codes** covering more than one event at the same severity. Untidy in a log reader, harmless in
  an alert.

Both ratchet: adding one fails, and *fixing* one also fails until the entry is deleted, so neither
list can go stale and hide the next real case. Split them opportunistically when touching a module —
there is no value in a renumbering campaign, and 85 of the original 96 were documented identifiers
whose churn buys nothing.

**Known blind spot, stated in the module docstring:** two events at the *same* level, one alertable
and one not, are invisible to the level heuristic. Rarer, because routine events are not logged at
warning.

---

## 5. Operational

### 5.1 Rotate the dev JWT in `ui/.env.local`
**Status:** open, owner: San. Exposed to a terminal during the vitest investigation. Gitignored, so
it was never committed, but it is a live token until rotated.

### 5.2 Cloudflare rewrites the tool-poisoning demo on `norviq.dev`
**Status:** verified, cosmetic.

The live page differs from `norviq-public-ui/test/index.html` by 233 bytes: Cloudflare's email
obfuscator finds `audit@attacker.example` inside the MCP tool-poisoning *payload* illustration,
replaces it with a `/cdn-cgi/l/email-protection` link and injects `email-decode.min.js`. The attack
string a visitor reads is therefore not the one we wrote. Wrap that span in `<!--email_off-->` if the
payload should render verbatim.

Everything else on the public site verified current: no version pins, "twenty-one detectors" matches
the 21 controls in the `strict` preset, and the SDK fail-open wording matches
`norviq/sidecar/remote_evaluator.py` ("a refused credential is not an outage and always blocks").

---

## 6. Carried plan work

Pre-existing, unrelated to the 0.2.5 cycle. Tracked in the session task list.

| id | item |
|---|---|
| #80 | P3 — MCP server registry (model, endpoints, Gate A, UI) + asset-graph node — *in progress* |
| #81 | P4 — MCP baseline controls (static in preset + registry-backed `__mcp__` module) |
| #82 | P5 — MCP server narrowing in the Visual Policy Builder |
| #70 | F-032 — shared normalize+decode stage before every content regex |
| #75 | CB-5 — red/blue through the chatbot UI, cross-mapped in the console |
| #76 | CB-6 — defend each hole with a policy authored in the Policy Builder |
| #66 | Campaign 2 Phase 0 — environment + both UIs in the browser |

Also noted during the MCP registry design and deliberately not fixed inside it:
`_reload_policy` (`policy_loader.py:795`) reads only Redis and returns silently on a miss, with no DB
fallback, so a replica that misses the pubsub message keeps serving a stale in-memory module. It also
drops `enforcement_mode` when rebuilding the entry.
