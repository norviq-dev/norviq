# Backlog

Open work, carried out of the 0.2.5 cycle. One rule for this file: **every item states how it was
verified, or says plainly that it was not.** An unverified item is a lead. A lead that gets written
down as a finding is how a wrong fix ships — most of this file exists because that nearly happened
several times in the cycle that produced it.

Status vocabulary: **verified** = reproduced against the artefact or source by hand, with a control
where a clean result was possible. **reported** = a review or a scan claimed it; nobody has
reproduced it. **landed** = fixed on `main`, waiting on a release. **on prep** = committed on the local
`prep/0.2.6` branch, which is unpushed: not on `main`, not on any remote, reaches nobody until the cut.
A "control" below means the check fails with the fix reverted and passes with it.

Commit ids are those of `prep/0.2.6` after the fold of 2026-11-04 (§7.16). The folded tip `a72bebc` has
the same tree as the tip the kind runs of 2026-11-03 were built from, so results recorded against it hold.

---

## 1. Waiting on the next cut

### 1.1 `deny_shell_execution` caveat — landed, unreleased
**Status:** landed (`f11a6b8`, on `main` and `prep/0.2.6`), not in 0.2.5. Re-verified 2026-10-30 on
`prep/0.2.6`: `GET /baseline/controls` serves the past-tense caveat ("Fixed in 0.2.1"). Control: with
`f11a6b8`'s `baseline.py` hunk reverted, the endpoint serves 0.2.5's present-tense text and both caveat
tests fail (2 failed → 2 passed).

The caveat served by `GET /baseline/controls` and rendered beside the console's Enforce toggle said,
in the present tense, that the control "trips roughly 1 in 8 times" on ordinary order ids. That was
fixed in 0.2.1. The control ships `default_effect="deny"`, so the console was warning operators off
enforcing something whose stated cost no longer exists.

Ships with 0.2.6. No cut is needed on its own account: it is a display string, and there are no
customers reading it today. (The original entry also said the chart renders byte-identical to
`v0.2.5`. That was true when written and is no longer true on `prep/0.2.6`, which carries many chart
changes; nothing depends on it.)

**Note the asymmetry while it waits:** `docs.norviq.dev` is already corrected and live, so the site
says the false positive was fixed in 0.2.1 while the shipped console still calls it current.

---

## 1a. Quickstart gate — RUN, and it passes

**Status:** verified 2026-08-24 end to end on a clean cluster. **The documented path takes 88
seconds**, 8/8 pods Running, `helm install` exit 0 on the first attempt. Not re-run on the 0.2.6 tree
(see §7.16 for what has and has not run on kind since).

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

### 1.1a Also landed on `cncf-readiness`, also unreleased (2026-09-02)

All verified with a control before commit; none reaches a user until 0.2.6 ships. Re-verified
2026-10-30 on `prep/0.2.6`, each with its fix reverted.

* **stdio MCP proxy degraded its pin store in silence** on the path the quickstart recommends
  (`file` with no path → memory, no log). Warning moved into `build_store` (`NRVQ-MCP-5078`) so no
  caller can forget it; tested through the real entrypoint. `9c97470`. Re-verified: 4 passed; with the
  `pins.py`/`http.py` hunks reverted, the unit test and the real-entrypoint test fail (2 failed), and
  the two quiet-path controls stay green.
* **Two security booleans fell back to OFF** — `auth.requireBoundAgentIdentity` and
  `config.requireStrongSecret` used `| default false` while the code defaults True, so an overlay that
  nulled the key rendered `"false"`. Latent (stock pins true). The other four `| default false`
  booleans default False in code and are harmless. `3c2c2ec`.
* **`NOTES.txt` and the refusal message called the audit-mode baseline "fail-closed"**, in the text
  printed on every install. `c9ea106`, wording since rewritten for the block default by `b4c127a`.
  Re-verified: the rendered NOTES has no "fail-closed" (the v0.2.5 chart's does); re-inserting the 0.2.5
  phrase fails `tests/helm/test_baseline_prose_parity.py`.
* **#117's veto excused "silently skip the policy check"** — see §7.1.

### 1.1b PR #109 (Mr-Neutr0n) — on prep with its follow-ups; the PR's own CI still never ran
**Status 2026-11-02:** the contribution is on `prep/0.2.6` as `227a3ba` (cherry-picked, authorship
kept; patch-identical to the PR head `e8b3886` by `git patch-id`, 2026-10-30), and items 2–4 below are
done in `a1e1d89`. Item 1 is still the maintainer's: see §7.14 and decision G in §7.23. `227a3ba`
passes the full CI-equivalent gates on its own (2026-11-02).

Original entry: open, head `e8b3886`, approved by the maintainer's comments on 2026-09-01 and held so
the docs change in it does not describe a fix no released version has. **The only third-party human
contribution the repo has.** Reviewed on the merits in the review: the fix is correct, the
subprocess test is the right shape (`CliRunner` never executes `main()`), and reverting the one-line
fix makes the test fail — it can fail, for the right reason.

Before it merges, in order of consequence:

1. **CI has never run on this commit.** It is a cross-repository PR, and all three workflows on
   `e8b3886` sit at `action_required` with zero check runs — the only green is FOSSA's legacy commit
   status, which is what `gh pr checks` reports as "all passed". Approve the fork workflow runs
   first, or the first execution of the suite on this code is the merge itself. **Still open** (the
   runs have since expired, §7.14).
2. **The test does not guard the half its name promises.** `test_json_payload_reaches_stdout_and_logs_go_to_stderr`
   never asserts anything is *on* stdout: moving the JSON to stderr leaves it green while `-o json |
   jq` reads nothing (probed). Issue #104's own checklist asked for `json.loads(proc.stdout)`. The
   maintainer's comment offered the success-case variant as optional; it is the load-bearing half.
   **Done (`a1e1d89`):** the test now runs `policy list` against a loopback stub API and asserts
   `json.loads(proc.stdout)` equals the payload, and that `nrvq.cli.command_ok` still arrives on
   stderr. Controls: with the stderr fix reverted both tests fail; with the payload moved to stderr the
   old test stays green and the new one fails.
3. **Two copy-paste examples still pipe through the `grep -v` workaround** the PR deletes the
   explanation for (`docs/cli.md:337` and `:483` on main). Harmless post-fix, but the file now
   contradicts the sentence the PR adds. A gap in #104's checklist, not the contributor's.
   **Done (`a1e1d89`):** both examples drop the workaround.
4. Minor: `subprocess.run` inherits the environment, so `HTTP_PROXY`/`ALL_PROXY` routes the
   deliberately-unreachable `127.0.0.1:1` through a proxy and the test fails on `returncode != 0`
   (measured). **Done (`a1e1d89`):** both tests run the CLI with the proxy variables removed, as
   `tests/mcp/test_stdio_transport.py` already did.

**Decided 2026-11-04 (G, revised): `227a3ba` stays on prep.** It is the same patch as the PR head
(`git patch-id --stable` gives one id for `227a3ba` and `e8b3886`, re-checked 2026-11-05), and dropping it
instead would conflict and break `a1e1d89`'s test. At the cut the maintainer re-runs #109's CI, merges
#109 into `main` first, then merges prep, resolving `docs/cli.md` and
`tests/cli/test_main_entrypoint.py` to prep's side. Simulated 2026-11-05 with `git merge-tree` at prep's
tip `cb5f14f`: `main` + #109 + prep and `main` + prep, each with conflicts taken from prep's side, give the
same tree, and it is prep's own tree. (`README.md` also conflicts between `main` and prep, with or without
#109; prep's side is the one to take there too.)

Original closing: "Items 2–4 are for the contributor or a follow-up commit; item 1 is the maintainer's
click. None of this is on `cncf-readiness` — it is the contributor's PR and stays theirs." Superseded
2026-10-30: `227a3ba` keeps the contributor's authorship; `a1e1d89` is a separate follow-up.

### 1.2 E.1 and the 0.2.6 cut are one unit, not two items

**Status 2026-11-03:** the pairing held, but most of the reasoning below is now history. §2.1 is on
`prep/0.2.6` (busybox relocates, verified with controls). Nothing is cut: `pyproject.toml:3` and
`Chart.yaml:6-7` still say `0.2.5` (read 2026-11-03 at `a72bebc`). The "thin release" argument no
longer applies: prep carries the security fixes listed in §7.16, the enforcing baseline with floors,
Valkey, #109, the OPA bump, digest-pinned and bumped third-party images (§7.24), and decisions B–E.
What blocks the cut now is the pending list in §7.16.

**Correction to item 3 below.** "The `docs/error-codes.md` direction corrections" are not something
0.2.6 carries: the commits that made them (`0eb060e`, `8b6ad60`, `b918d05`) are ancestors of `v0.2.5`
and shipped in it (checked 2026-10-30: `git diff v0.2.5 90b9f49 -- docs/error-codes.md` was empty).
**Update 2026-11-03:** the page was recounted on prep in `dad56e3` (410 → 535, adding an MCP area of
49 codes in the registry summary) and last updated to "Total unique codes: 538" in `70d950a` (counted
2026-11-02). Its MCP row indexes part of the 5xxx range and says the rest is described in
`docs/guides/mcp.md` §8 and not yet indexed. **Update 2026-11-05:** recounted and
held by a test. `cb5f14f` indexes every code the source carries (554; the page had 538, missing 16, and
said in a sentence that part of the MCP range was not indexed), with an MCP section of its own, and
`tests/test_error_codes_indexed.py` fails when a code in the source is missing from the index, when the
index lists a code no source file carries, or when the stated total disagrees with the index.

**Decision:** ship the busybox fix (§2.1) and cut 0.2.6 together, or do neither. Not launch-gating.

The dependency runs one way and is easy to miss: **fixing `_helpers.tpl` does nothing on its own.**
Anyone installing gets the published chart, which hardcodes bare `busybox:1.36`. A fix that sits on
`main` while 0.2.5 remains the published chart is indistinguishable, from a user's position, from no
fix at all — while reading in the repo as done. That is this codebase's recurring defect shape applied
to the release process rather than to a control.

So the pair is:

1. §2.1 — wrap `busybox:1.36` in `norviq.thirdPartyImage` so `global.imageRegistry` relocates it
2. correct the docs row that lists busybox among the images that key covers (it becomes true with the
   fix; see §3 for where that row actually lives)
3. cut **0.2.6**, which also carries the already-landed `deny_shell_execution` caveat fix (§1.1) ~~and
   the `docs/error-codes.md` direction corrections~~ (see the correction above)

**Why it is not launch-gating.** busybox only breaks installs with no path to Docker Hub. An
evaluator on EKS/AKS/GKE — the target user — pulls it fine and never sees this. It is an
enterprise/air-gapped evaluation blocker, which matters on a slower clock than a launch.

**Why not cut 0.2.6 sooner** (written 2026-08; superseded). As of that writing 0.2.6 would have carried
one corrected caveat string and some doc rows — thin justification for spending a version and
re-running the irreversible PyPI path.

---

## 2. Product defects — verified

### 2.1 `busybox:1.36` is not relocatable, and air-gap installs will fail on it
**Status:** FIXED on `cncf-readiness` (`557e311`, also on `prep/0.2.6`). Re-verified 2026-10-30 on
`prep/0.2.6`: with
`global.imageRegistry=myreg.example.com` all five wait containers render
`myreg.example.com/busybox:1.36@sha256:…` and none is bare. Controls: without the flag the same five
render bare (so none vanished); the v0.2.5 chart renders five bare `busybox:1.36` with the flag;
reverting the helper makes the relocation test list five bare. Since then busybox is also
digest-pinned (`6725738`, §7.3). Reaches users only with the 0.2.6 cut (§1.2). **Severity:** first-run
blocker on air-gapped clusters.

`helm/norviq/templates/_helpers.tpl:249` hardcoded `image: busybox:1.36` with no
`norviq.thirdPartyImage` wrapper, unlike every other third-party reference. Rendering with
`--set global.imageRegistry=myreg.example.com` relocated opa, redis, postgres, nginx and curl, and
still emitted bare `busybox:1.36`.

On a cluster with no path to Docker Hub, api and engine sit in `Init:0/2` on an `ImagePullBackOff`
for busybox while every other image resolves — the failure names an image the operator never chose
and cannot move.

The docs list `busybox:1.36` among the images `global.imageRegistry` covers, which was exactly
backwards for the published chart. With the helper fixed the row is true as written (in-repo:
`docs/configuration.md:213`; see §3).

Repro:
```
helm template norviq helm/norviq -n norviq --set policyQuotaNamespaces='{a}' \
  --set global.imageRegistry=myreg.example.com | grep busybox
```

### 2.2 External datastores via `existingSecret` render no wait containers
**Status 2026-11-03:** decided and DONE on `prep/0.2.6` (decision B in §7.23): the behaviour stays,
the docs say so and name `host` as the opt-in gate (`9e3ae03`), and the app now retries both stores at
startup instead of failing on the first refusal (`4a1654f`, §7.25). Verified with a control; re-measured
2026-10-30 and again in `9e3ae03` (initContainers per Deployment, api / engine / webhook: bundled 2/2/1;
`existingSecret` alone 0/0/1; `existingSecret` + `host` 2/2/1, waiting on the given host while the URL
is still read from the Secret; the `existingSecret` renders are identical before and after apart from
the generated secrets, since only comments changed in the chart).

`norviq.waitFor` (`_helpers.tpl`, `define "norviq.waitFor"`) now opens with `{{- if .host -}}`, and the
pg/redis wait-host helpers return `""` when `host` is unset and the bundled store is disabled. With the
`existingSecret`-only external path — the one `docs/configuration.md` recommends, because the credential
should not pass through values — **api and engine get no dependency gate at all** and retry their own
connections instead.

Measured: bundled datastores render 5 busybox references; `--set postgresql.enabled=false
--set postgresql.existingSecret=my-pg --set redis.enabled=false --set redis.existingSecret=my-redis`
renders 1 (the webhook's wait-for-api). The control is what makes this trustworthy — 5-vs-1, not
0-vs-0. Re-measured 2026-10-30 per configuration (api / engine / webhook init containers): bundled
2/2/1; `enabled=false` + `host` 2/2/1; `existingSecret` + `host` 2/2/1, waiting on the given host,
with the URL still read from the Secret; `existingSecret` alone **0/0/1**.

This is *better* than the 0.2.3 behaviour it replaced, where the guard rendered `nc -z` against a
bundled Service name that `enabled: false` never creates, so pods waited forever. But the docs still
describe the old universal guarantee (§3). `values.yaml`'s `postgresql` comment does say the gate is
skipped with `existingSecret` alone; the `redis` comment does not.

**Decide:** is the missing gate intended (the app retries anyway) or should `existingSecret` grow an
optional `host` for the gate? Then make the docs match whichever it is. Note that `host` beside
`existingSecret` already restores both waits today (measured above) — it just is not documented.

**Decided 2026-11-02 (B, option 1):** the gate stays absent with `existingSecret` alone, because the
chart cannot read an address out of the operator's Secret at template time. `9e3ae03` rewrites the
`docs/deployment.md` guarantee ("so Helm's apply order never matters") and its dependency-wait section,
the `existingSecret` guidance and both table rows in `docs/configuration.md`, mirrors the Postgres
comment into the Redis block of `values.yaml`, and corrects `_connect_with_backoff`'s docstring. The
same commit measured what ran instead of the gate, against a refused port, and found the docstring
wrong too: the API's Redis connect gave up after 15 s, its first Postgres connection did not retry a
refused connection at all, and the embedded engine retried nothing. That is fixed by `4a1654f`
(§7.25). The one risk is documented: a `host` that disagrees with the Secret's URL makes the gate wait
on the wrong address.

---

## 3. Docs drift — verified; most fixed on `cncf-readiness`, the three held rows fixed on prep

**Fixed (`8522e16`, `c9ea106`)**, each side read before either was changed: six pages claiming five
rule_ids stay hard in audit mode (the code keeps one plus one behind `monitor_exempt_rate_limit`;
the cited symbol `_POSTURE_EXEMPT_RULES` raises ImportError); "fail-closed" on the audit baseline in
getting-started, production-config, prod-deploy-runbook, NOTES.txt and the chart's refusal message;
graphs.md's "fail-closed default" row, unreachable stock (`no_policy_loaded` needs
`noPolicyDecision: deny`; the chart ships allow); security-model.md and `values.yaml:858` calling
`requireBoundAgentIdentity` false-by-default when it has shipped true since 0.2.1; README:114's
unqualified "fail-closed". `tests/test_docs_prose_parity.py` now reads the prose so this cannot
recur silently — anchored on the function name, because "stays hard" also occurs in unrelated text
about pack overlays.

**Correction 2026-10-30: the line numbers in this table are docs-site lines, not repo lines.**
`docs/deployment.md` has been 382–383 lines at every tag from v0.2.3 to v0.2.5 and on `prep/0.2.6`; it
never reached 502 lines and never mentions `global.imageRegistry`, and `configuration.md:410` is fleet
prose. The original numbers most likely point into the `norviq-docs` site source, which was not
checked. The table below gives the in-repo sentences that make the same claims, measured against the
chart on `prep/0.2.6`.

**Held**, because each depended on a decision in §2 rather than on wording. **Update 2026-11-03:** the
busybox row is true on prep (§2.1), and the two `existingSecret` rows were rewritten in `9e3ae03` once
decision B was made (§2.2). The table is kept as the record of what was wrong; the docs site
(`norviq-docs`) still needs the same corrections when 0.2.6 is published.

| page (docs site / in repo) | claim | true on `prep/0.2.6`? (as measured 2026-10-30, before `9e3ae03`) |
|---|---|---|
| site `deployment.md:370` / repo `docs/configuration.md:213` | `global.imageRegistry` covers `busybox:1.36` | **true on prep** (five relocated wait containers, §2.1); false for the published 0.2.5 chart, so it becomes true for users with the cut |
| site `deployment.md:502` / repo `docs/deployment.md:183-185`, and `:213-214` ("used for api/engine → Postgres and Redis") | "`initContainers` gate api/engine on Postgres+Redis … so Helm's apply order never matters" | **false when only `existingSecret` is set** (api and engine render no init containers, §2.2); true for bundled, `host`, and `existingSecret`+`host` |
| site `configuration.md:410` / repo `docs/configuration.md:286`, `:299` and the "Prefer `existingSecret`" block at `:60-75` | the `existingSecret` rows inherit the same assumption | the rows are **true as written** (they make no gate claim, and a render with neither `host` nor `existingSecret` fails); the "Prefer `existingSecret`" block is **incomplete**: it recommends the path and never says the gate disappears |

The two `existingSecret` rows were held on decision 2.2 (B in §7.23) and are now fixed in the repo
(`9e3ae03`); the line numbers above are as of 2026-10-30 and have moved.

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
* **48 codes** covering more than one event at the same severity (52 until `9c97470` gave the pin-store
  warning its own code and `NRVQ-MCP-5067` stopped carrying two events; 51 until `bb2f46e` on
  `prep/0.2.6` gave `nrvq.policy.reloaded` its own code, `NRVQ-REG-5022`, so `NRVQ-REG-5012` and `5013`
  each name one event; 49 until `a7dfcd7` made the boot warm raise instead of logging its own
  WARNING under `NRVQ-API-7035`, so that code names one event (the ERROR) — the ratchet's
  delete-the-entry rule fired each time, as designed). Untidy in a
  log reader, harmless in an alert. Counted 2026-11-03 at `a72bebc` from `KNOWN_DUPLICATES` (48) and
  `MIXED_LEVELS` (40).

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
**Status:** open, owner: the maintainer (F in §7.23). Exposed to a terminal during the vitest investigation.
Gitignored, so it was never committed, but it is a live token until rotated. Note for the re-mint:
`ui/.env.local.example`'s recipe mints a token with no `exp`, which the API refuses, signed with the
placeholder secret `requireStrongSecret` rejects (read 2026-10-30).

### 5.2 Cloudflare rewrites the tool-poisoning demo on `norviq.dev`
**Status:** RESOLVED 2026-08-24 — `norviq-UI#2` removed the literal address rather than escaping it;
the live page now carries no `email-decode.min.js` (measured: 0). Kept for the record. Not re-verified
since (external site).

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

**Correction 2026-10-30: the table below was copied from an old session task list, and every item on
it had already landed** — most of them logged in `docs/design/IMPLEMENTATION-LOG.md` before this file
was opened (`6f0960b`, 2026-08-21). Evidence, read or measured on `prep/0.2.6` on 2026-10-30:

| id | item | status and evidence |
|---|---|---|
| #80 | P3 — MCP server registry (model, endpoints, Gate A, UI) + asset-graph node | **landed** (`92561a8`, 2026-08-17; log "live on kind, chatbot-lab"). `McpServer` model, `/mcp/servers`, `/mcp/servers/decision`, `DELETE /mcp/servers/{ns}/{id}`, `mcp_server` graph node, `McpServers.tsx`. `test_mcp_api.py` + `test_mcp_controls.py` + `test_content_norm.py`: 85 passed |
| #81 | P4 — MCP baseline controls (static in preset + registry-backed `__mcp__` module) | **landed** (`7658cfe`). Five `mcp_*` heads in `strict.rego`; `norviq/api/mcp_controls.py`; the evaluator appends the `__mcp__` floor. Read, not re-run live |
| #82 | P5 — MCP server narrowing in the Visual Policy Builder | **landed**. `BuilderSheet.tsx`, with `BuilderMcpNarrowing.test.tsx` and `BuilderSheet.mcp.test.tsx`. Read; vitest not run for this check |
| #70 | F-032 — shared normalize+decode stage before every content regex | **landed** (`ae86def`, 2026-08-13). `scripts/f032_battery.py` today: 1/22 evaded, 0 false positives; the one miss (a bare nine-digit SSN) is by design |
| #75 | CB-5 — red/blue through the chatbot UI, cross-mapped in the console | **done for 0.2.0** (`980a5ed`, 2026-08-17: 24 prompts, 48 tool calls, 5 blocked at baseline). **Not re-run for 0.2.6** |
| #76 | CB-6 — defend each hole with a policy authored in the Policy Builder | **done for 0.2.0** (same run: the `printenv` credential read, 0→1 blocked by a builder policy). **Not re-run for 0.2.6** |
| #66 | Campaign 2 Phase 0 — environment + both UIs in the browser | **landed** (`18b5179`, 2026-08-02, Phase 0a–0c in the log) |

What was left was re-verification on the 0.2.6 candidate, not feature work. Plan: H in §7.23.

**MCP re-verify — DONE 2026-11-03 on kind, images built from `a72bebc`: 84/84.** Covered:
`docs/design/03-mcp-servers.md` §8 acceptance 1–6; the five MCP controls live (drift and never-scanned
escalate, quarantined and flagged block, healthy and non-MCP allow); and the generated `__mcp__` module
across two API replicas, reloaded through pub/sub (which depends on the reload fix below).

**The risk the plan named was real, and is fixed (cold catalog, `94b2f8c`).** The enforcing baseline
enforces `mcp_definition_never_scanned` (escalate). Measured: a client that does not re-list after a
proxy restart had **every** call escalated as never-scanned, 45/45. Now, when a `tools/call` arrives
before any `tools/list` was scanned, the proxy lists the server itself and scans the answer through
Gate A before deciding the call. The list is single-flight, bounded by `NRVQ_MCP_COLD_LIST_TIMEOUT_S`
(default 5 s; `0` turns it off), and backs off for 30 s after a failure (`NRVQ-MCP-5079`/`5080`/`5081`,
in `docs/error-codes.md` and `docs/guides/mcp.md`). Re-verified on the final tree: 0/45 for those
clients; control, with the self-list off: 45/45. Further MCP proxy changes rode on the same
work (§7.26).

**Still open:** the CB-5/CB-6 re-run on the candidate images (needs kind, an LLM key and a browser);
not run. Three owner calls the log left open: the two non-canonical attack-path endpoints (a public API
break to remove), `egress_allowlist.py` with no router, and how `input.mcp.server` is sourced.

**The `_reload_policy` note — FIXED on `prep/0.2.6` (`bb2f46e`), with follow-ups `0067b51`, `25a028d`,
`94414d6`.** The original note: `_reload_policy` (`policy_loader.py`) read only Redis and returned
silently on a miss, with no DB fallback, so a replica that missed the pubsub message kept serving a stale
in-memory module, and it dropped `enforcement_mode` when rebuilding the entry. Now the embedded engine's
reload reads Postgres through `load_from_db` (mode, priority and `applied_at`, as a cold start does).
Found and fixed alongside it: a policy saved at priority 0 came back as 100 from five Postgres read sites
(`0067b51`), so a reload or restart could reverse which layer wins; a delete never reached the embedded
engine, which kept enforcing it until restart (`25a028d`: `delete()` publishes the invalidation, a reload
that finds no row unloads, and a DB error raises and never unloads); and the sidecar and peer logs said
the opposite of what happened (`94414d6`: `NRVQ-SDC-3024` `policy_unloaded`, `NRVQ-REG-5016`
`operation=upsert`). `tests/engine/test_policy_reload.py` drives the real handler against real Redis and
Postgres and judges the engine's decision. Controls: with `bb2f46e` reverted all six new reload tests
fail (and the log-code ratchet on 5012/5013); with `0067b51`, `25a028d` and `94414d6` reverted, 5, 4 and
3 tests fail respectively. **Still open:** a delete notice that meets a DB error is not retried; there is
no periodic reconcile for missed pub/sub messages; a successful reload does not invalidate cached
decisions (5 s TTL).

---

## 7. Opened during the CNCF readiness pass (2026-09-02)

Every item below was reproduced against the tree or the live API during the review; the audit that
proposed most of them had executed nothing. Where the audit was wrong, §8 says so. Items 7.17 onward
were opened during the 0.2.6 preparation (2026-10-28 to 2026-11-05).

### 7.1 PR #117 narrowed the concealment scanner into a bypass
**Status:** fixed on `cncf-readiness` (`6c4d3b3`, also on `prep/0.2.6`). Re-verified 2026-10-30: the 16
regression cases pass; with `_excused` reverted to the window-only veto, exactly 15 fail and 50 pass.
**"The open PR still has it" looks stale:** the local remote ref `fix/concealment-bare-false-positive`
carries a commit patch-identical to `6c4d3b3` (pushed 2026-10-27). Confirm on GitHub that it is #117's
head; then what remains is merging #117 and rewording #116.

The veto that makes "succeed silently" ordinary matched on the verb alone, and its verb list — skip,
drop, ignore, overwrite, discard, continue, retry — is what a poisoned description uses to suppress a
control. Seven phrasings went STRIP/high → PASS-THROUGH on both the definition and the tool-result
path; the PR's own positive controls sample only exfiltrate/send/copy, which the veto cannot match,
so they stayed green. A second defect in the same function: the veto checked the window, not whether
the ordinary phrase contained *this* adverb, so a decoy "skip silently." twenty characters earlier
excused a following "silently exfiltrate". Fixed by requiring the veto phrase to span the adverb and
by refusing the excuse when the words after the adverb name a control. Sixteen regression cases;
reverting fails exactly fifteen. **#116** documents the false positive "until #117 lands" and should
be reworded once the corrected fix does.

### 7.2 CI is red on `main`, and nothing is a required check
**Status:** FOSSA half resolved (`e4bf1b9`, `bd78e61`); Framework Compat RESOLVED (`024101b`); the
required-check question is a decision owed (G in §7.23). Re-verified 2026-10-30 on `prep/0.2.6`: the
FOSSA exception test passes 11, and removing the three ids fails it; a dry-run joint resolve gives
googleapis 1.75.0 + protobuf 5.29.6, while `.[dev]` alone gives 1.76.0 + 7.36.2, which autogen-core's
`~=5.29.3` would break (the leg's 13 tests were not re-run). **`main` still has the two-step install**
until these branches merge. The "prepared settings script" this entry used to cite is not in the repo.
FOSSA's Python scan had a separate, larger hole: §7.17.

**The Framework Compat diagnosis below ("pin protobuf") was wrong.** The autogen leg installed in two
pip calls: `.[dev]` resolved googleapis-common-protos to 1.75.3 (metadata `protobuf>=6.33.5`), then
autogen-core's `protobuf~=5.29.3` downgraded the runtime and pip carried on with a warning. One joint
resolve backtracks googleapis to 1.75.0 and the leg's 13 tests pass, with the framework still unpinned.
Pinning protobuf was impossible — the framework is what caps it. End users were never affected:
`pip install norviq[autogen]` and `uv sync --extra autogen` both resolve jointly (measured).

The k8s modules are bumped v0.33.0 → v0.37.0 (build/vet/test/image all green). That does **not**
clear FOSSA — read from the advisory database, all three CVEs have fixed versions eight to twenty
minors below v0.33.0 (client-go 0.17.0 / 0.19.6; CVE-2018-1002105 is against `kubernetes/kubernetes`
< 1.12.3, never a library). The matches are spurious and have no upper bound, so they are excepted in
`scripts/check_fossa_issues.py` with the rationale beside them, in SECURITY.md's table, and pinned by
a test. The lesson worth keeping: a bump that "fixes" a scanner finding without reading the advisory
is the recurring defect in a new costume. (An exception is keyed on the CVE id, not on package plus
version, so it has no upper bound of its own either.)

FOSSA fails on the webhook's Go deps at `k8s.io/{apimachinery,client-go}` v0.33.0
(CVE-2018-1002105, CVE-2019-11250, CVE-2020-8565) — the gate working, the dependency old. Framework
Compat's autogen leg fails at collection on `protobuf` gencode 6.33.5 vs runtime 5.29.6. Neither
blocks a merge: `main` has no branch protection and no rulesets, so no workflow is a required check
— while `test.yml:2` calls itself a merge gate. The lint/audit gates added in `dafdcca` report and do
not block for the same reason. GOVERNANCE.md says when that changes.

### 7.3 The default Redis image is RSALv2/SSPLv1, on a floating tag, with no digest
**Status:** licence half RESOLVED on `cncf-readiness` (`a822c7f`) for the single store, and on
`prep/0.2.6` for the HA failover too (`7da3cb8`: its redis and sentinel pods run Valkey; §7.21).
**Digest half FIXED on `prep/0.2.6` (`6725738`, 2026-10-30).** The upgrade path this opened is §7.21.

Digests: reproduced first — the chart stamped with `scripts/release_stamp.py`, rendered, and
release.yml's gate run verbatim said `GATE: PASS` with eleven image lines still on tags (busybox ×5,
opa ×2, nginx, postgres, valkey, curl); postgres and valkey had both been rebuilt upstream that week,
so two installs of one signed chart could run different datastore builds. Now
`global.thirdPartyImageDigests` holds the multi-arch index digest of every third-party image, keyed by
the upstream ref (so an overridden tag never inherits the old digest), and `norviq.thirdPartyImage`
appends it after any `global.imageRegistry` prefix. `scripts/check_image_pins.py` is the release gate:
every rendered `image:`/`imageName:` value and every `*_IMAGE` env literal must end in
`@sha256:<64 hex>`, and an empty render fails; release.yml runs it on the working-tree and the packaged
render, and `verify_release.py` on the stamped chart. Controls: the helper reverted → 11 failed; the
gate reduced to the old semantics → 17 of 30 in `test_image_pins` fail, including all 7
one-pin-missing cases; the new gate on the old render → exit 1, all 11 bare lines named. Mirrors that
re-push images (new digest) drop the pins with `global.thirdPartyImageDigests=null` (documented).
**Residual closed:** the HA failover's sentinels ran the operator's own default image on a bare tag,
because the template set no `spec.sentinel.image`, so the gate could not see it (reported in
`4d9c761`). `7da3cb8` sets both the redis and the sentinel image to the digest-pinned Valkey, held by
`tests/helm/test_bundled_store_upgrade.py` for both pod kinds.

Licence (2026-09-05): ships `valkey/valkey:8.1-alpine` — BSD-3-Clause, LF fork, minor-pinned. Validated
before pinning: the image symlinks `redis-server`/`redis-cli`, sentinel mode starts, and the full suite
(3297) ran green against a live Valkey — the first fully green run this cycle. compose, test.yml's
service and the chart now agree. HA kept Redis 7.4 until `7da3cb8` moved it to Valkey too (§7.21).

Original entry: `redis:7-alpine` resolves today to 7.4.11 (OCI annotation and the image's own
`REDIS_VERSION`), which is past the 7.4 relicense. Unlike every first-party image the redis entry has
no `digest` key, and `release.yml`'s "every image is digest-pinned" gate asserts `@sha256:` only on
`ghcr.io/norviq-dev/` lines — false for six of eight images.

Images (2026-11-02 entry, updated 2026-11-03): `nginx:1.27-alpine` (TLS terminator; EOL; 60 fixable
HIGH/CRITICAL in Trivy 0.69.3) → 1.30 (3); `curlimages/curl:8.10.1` (22) → 8.23.0 (0); the console base
`nginx-unprivileged:1.27-alpine` → 1.30. **Done on prep** (`ff019bb`, with the bootstrap image's Alpine
in `f350332`; §7.24, L in §7.23). **Still open:** `postgres:16-alpine`'s findings, all in `gosu`,
which runs because the chart starts postgres as root (disclose, or run postgres non-root later; M in
§7.23); re-counted in the 2026-11-04 sweep, §7.28. The built Norviq images: api, engine and webhook scan 0 fixable HIGH/CRITICAL (2026-11-03,
images built from `a72bebc`); ui and bootstrap could not be built exactly on the test host and must be
scanned by CI (§7.16).

### 7.4 Four commits are authored by a coding tool's default git identity
**Status 2026-11-03:** decided (C in §7.23); the in-repo half is DONE on `prep/0.2.6` (`1dfc80e`); the
DCO remediation commit is drafted and is the maintainer's to sign.

Decision C chose disclosure over a rewrite: re-attributing the four commits (`e97892d`, `a61b37f`,
`5ae820d`, `92e0e59`, all 2026-07-31, ancestors of `main` and contained in tags v0.2.0 through v0.2.5)
would change every later SHA, including the published v0.2.x tags and the revisions stamped in released
images. `1dfc80e` adds an "AI-assisted commits and provenance" section to `CONTRIBUTING.md` that lists
the four SHAs, says the maintainer committed and is responsible for them and why history is not
rewritten, and states the rule from now on: a commit written with AI assistance has the human who
reviewed it as author and sign-off, and a tool is never an author or co-author. `.mailmap`'s comment now
points at that section instead of at an open decision. Verified in the commit: filtering `origin/main`
on the tool's noreply address as author lists exactly these four. The remediation commit is an
attestation only the maintainer can make; it is not on prep.

Original entry: `.mailmap` (`8ff9a05`) collapses the seven human spellings and deliberately leaves these
four alone — folding them into a human identity by mailmap would hide the question, not answer it. An
AI cannot certify origin under the DCO; a foundation doing IP diligence will ask. Options: re-attribute
to the maintainer with the AI noted in the body; leave and disclose; or a one-off DCO remediation commit
covering prior work. Not a formatting question. Also: 387 commits (73%) carry a co-author trailer naming
the tool; those stopped 2026-08-10 and are disclosure, not authorship.

### 7.5 Repository security toggles are off, and SECURITY.md points at one of them
**Status:** verified live; decision owed (G in §7.23). Not re-checked live since; the repo settings
were not touched.

Private Vulnerability Reporting: `enabled: false` (control: `github/docs` → true). Secret scanning,
push protection, Dependabot security updates: all off. `SECURITY.md:12-13` calls PVR "the preferred
channel" and `:8` forbids a public issue — a researcher following the doc finds no button and is
pushed toward the one route the doc bans. Either flip the toggles or edit the sentence; leaving both
as they are is the defect.

### 7.6 `.gitleaks.toml` allowlists every `.md`, so docs are never scanned
**Status:** FIXED on `cncf-readiness` (`57bcd74`).

Re-verified 2026-10-30 with gitleaks `dir` over the 67 tracked `.md` files: the branch config reads
1.48 MB and finds 0, `main`'s reads 0 bytes; a planted `ghp_` token is found with the branch config
and missed with `main`'s; dropping the log-code regex brings back the one `error-codes.md` hit.
`main` is unchanged until merge.

Measured at the fix: the cost of removing the line across all 67 tracked `.md` was two findings —
`NRVQ-API-7460` (a log-code id, now allowed by shape) and the example one-time password #118 makes fake
(same one-line change made here). Controls: 67 files → 0; a planted `ghp_` token in a `.md` → found;
`gitleaks git` over the PR range → 0. The first attempt scanned 0 bytes twice and reported clean both
times. Original entry: Line 12's `.*\.md$` means the `secrets` job does not read `docs/cli.md` — or any
markdown. #118's premise that "a scanner flagged" the example password is true only of Mr-Neutr0n's
scanner, not this repo's. Two credential-shaped strings have now lived in docs; measuring what
un-allowlisting costs across all 62 tracked `.md` files is the next step.

### 7.7 `docs/cli.md` line citations are systemically stale
**Status:** FIXED on `prep/0.2.6` (`9441e60`, `f8f2cc5`, 2026-10-30). The page's 135 raw line citations
are symbol anchors now: 151 code anchors and 3 TOML anchors (102 distinct, across 32 files).
`tests/test_docs_cli_anchors.py` resolves each one (Python through `ast`; TS/Go/Rego by definition;
YAML/TOML by key path), refuses raw line citations in any text file type (including `Dockerfile*`,
`Makefile` and a wrapped "line N"), reads the page as CommonMark (code spans pair across single newlines,
never across a blank line or a block boundary; agrees with markdown-it-py 3.0.0 on cli.md and on 65 of 67
tracked `.md`), and fails on any `::` in prose that it did not resolve. Re-anchoring found sentences that
were false, now rewritten: `--target-type` decides the key via `resolve_apply_target_key`; the line cap
is 650; the webhook controller is exempt from the namespace write floor; the reserved-scope table gained
`__controls__`/`__egress__`/`__mcp__` and the overlay `--mode audit` refusal; apply does not refuse
`<class>__remediation__`. Controls: the old page fails with 137 raw citations (the 135 `file:line`
citations plus a bare `:1187,1197` and a prose "line 48"; the 2026-09-16 count of 122 predates later
edits to the page); planted typos fail by name; the first review's wrapped-span gap — the old pairing
passed 38 with typos planted, the new parser fails 1 and passes 80, and putting the old pairing back
fails the completeness test on exactly lines 190 and 518.

Original entry (measured 2026-09-16): 122 `file:line` citations; 19 pointed at nothing a sentence
could mean (a blank line, a lone `)`, or a bare basename the page never resolves); 44 more sat 11–349
lines below the symbol they presumably meant. `:14` cited `pyproject.toml:67-68` (actual 82-83);
`:608` cited `config.py:393` (actual 454, and 393 is a comment about body size). Nothing in CI kept a
line number fresh; the anchor test is what does now.

### 7.8 Two of the maintainer's worktrees were deleted during the review
**Status:** recorded. `../tmp/prega-92ceec1` (`release/pre-ga-consolidated`) and
`../tmp/wt-pre-ga-remediation` (`fix/catalog-hierarchy-batch2`) were removed by an over-broad
cleanup filter. Both branches are intact at `92ceec1` on the maintainer's machine, last commit 2026-07-08. Any uncommitted work
in those directories is gone; `git worktree add ../tmp/<name> <branch>` restores the directory.

### 7.9 Steps not yet done from the CNCF audit
* **OpenSSF Best Practices badge** — never registered (`bestpractices.dev` → "Zero Projects";
  control: `kubernetes` → 431). Owner-only web form; criterion answers to be drafted from the repo as
  it stands *after* the items above, so justifications point at real artifacts.
* **Security self-assessment** (CNCF TAG Security abbreviated template) — the highest-value artifact
  and the one where an unverified claim is actively dangerous. To be written from the code at the
  moment of writing; §3's drift list is its raw material.
* ~~**Framework Compat and FOSSA reds** (§7.2) — bump the k8s Go deps; pin protobuf in the autogen
  leg.~~ Done differently: see §7.2 (the k8s matches are excepted, and the autogen leg resolves
  jointly instead of pinning protobuf).

---

### 7.10 A misclassified tool NAME cascades into an agent-wide outage

**Status 2026-10-30: both halves FIXED on `prep/0.2.6`.** The cascade half (`1a199c4`, 2026-10-28):
repeated refusals of the same tool with the same parameters count once toward trust, so a retry loop no
longer reaches the violation cap. The classifier half (`847a021`, which since the fold also
documents why its per-event cache write is a deliberate handler): `run`/`execute`/`invoke` now take the verb they
govern (`run_query` read, `run_update` write, `run_export` send) and keep delete/critical when they
govern nothing known (`run`, `run_report`, `execute_sql`) or code. The rule is fail-closed: a run
qualifier keeps "read" only when the payload is positively a read — no statement or mutation keyword
token in any string, keys and values, at any depth; otherwise it is delete (destructive keyword) or
write. Write-named qualifiers can only raise the verb. The derived input is memoised per event.

Two independent reviews; the first cut was rejected. Verified on the final rule with the reviewer's
own sweep: 204 names × 33 statement kinds × 6 policies give 0 non-read calls allowed that `90b9f49`
blocked (the first cut: 121). Non-SQL writes are refused by `mcp_controls`, read-only-intent and the
guardrail, and the SUPPORT policy now blocks `verb == write` for its read-only class. Controls: `90b9f49`'s classifier → 86 of
the new tests fail; the first cut → 57. Live on kind
(`22c1232`): the chatbot scenario scores **16/16** (was 13/16); 16/16 again on images built from
`a72bebc` (2026-11-03).

**Residuals:** some statement forms are still classified as read; they are not listed here, and
the guardrail and `mcp_controls` still refuse non-SQL writes.

Original entry: found by running `scripts/mcp-chatbot-scenario.sh` on a live kind cluster
(2026-09-07), not by reading. `classify_tool("run_query")` resolves to **delete** — the `run` token is
in the lexicon as delete/critical — and the evaluator consults an admin's promotion ONLY when the name
classifier returns `unknown`; when the name resolves, "the classifier wins outright, whichever
direction the promotion points" (`norviq/engine/evaluator.py`, pinned by
`tests/engine/test_promoted_verb_enforcement.py::test_a_promotion_cannot_demote_a_classified_tool_in_any_direction`).

That rule is right on its own terms — it stops a promotion being used to move a tool into an egress
refinement. The consequence was not:

1. A policy gating on `input.derived.verb == "delete"` blocks `run_query` permanently, and the
   documented remediation (promote the tool) cannot reach it.
2. The scenario retries the blocked call 12 times. Each refusal is a violation.
3. Trust falls 0.8 -> 0.515 -> 0.505 -> **0.30**, the floor. Measured across the audit rows of one run.
4. At the floor, `escalate_low_trust` catches the agent's BENIGN traffic — `post_message` to
   `#support` and `search_issues` on a different MCP server both escalate, on servers and tools that
   no policy rule touches.

So one bad name in the classifier lexicon degraded into an agent-wide, cross-server outage, and the
one admin control that looks like the fix is inert against it. Neither half is visible from either
side alone: the classifier looks correct, the trust control looks correct, the promotion returns 200.

The promotion rule is unchanged: the classifier still wins over a promotion when the name resolves;
the fix is that `run_query` no longer resolves to delete. Of the three candidates the entry listed —
correct the lexicon (narrowest, but the next `run_*` read tool would hit it again, hence the
generalised rule above); let a promotion outrank the classifier when it is strictly de-escalating and
carries evidence (not taken); count repeated refusals of the same tool once (`1a199c4`; the original
entry called it "worth doing regardless", since any agent retrying a blocked call was self-driving
toward an outage an attacker could trigger deliberately).

### 7.11 Two harness checks reported green for something they never observed

Same run, both now fixed on `cncf-readiness` (`5913d72`, `271fe68`). Re-checked 2026-10-30: an offline
run of the scenario with every `run_query` refused reports the promotion as "promoted, but the name
classifier still wins" and PII as "not evaluated"; the same simulation of `main`'s module reports
"promoted"/PASS and "masked". The digest stamp was verified by reading `Dockerfile.api`/`00-up.sh`; its
live control needs a cluster and was not re-run.

* **`scripts/mcp-chatbot-scenario.sh:56` could never pass.** It asserted `/app/.build_tree_digest` in
  the **API** pod, but only `scripts/mcp-demo.Dockerfile` writes that file and nothing builds the API
  from it — `Dockerfile.api` writes `.build_git_sha`, and `00-up.sh` never passed the arg, so the
  value was `unknown`. Copy-pasted from the data-plane check at :133, which is correct because the
  chatbot pod does run that image. Fixed by stamping the digest in `Dockerfile.api` and passing both
  build args from `00-up.sh`; control-tested in both directions (perturb the tree -> guard goes red
  with the real digests; rebuild -> passes).
* **The promotion claim passed on an HTTP 200.** `_promote_verb` returned "the POST succeeded" and
  the claim asserted that, so `an admin can correct a misclassified tool through the existing
  promotion lifecycle` reported PASS while the correction reached nothing (7.10). Its docstring
  asserted "the override outranks the name classifier" — prose contradicting the module it described.
  Now read off enforcement: `promoted, but the name classifier still wins`.
* **The PII-masking check reported `masked` on a refused call.** `"4111111111111111" not in txt` is
  trivially true when `txt` is a block message, so the check was strongest exactly when the model had
  received no customer data at all. Now reports `not evaluated — the query never returned a result`.

### 7.12 The chatbot scenario is not idempotent, and does not say so

**Status 2026-10-30:** FIXED on `prep/0.2.6` (`b1bbd00`, 2026-10-28): each run uses its own
service-account name, so it starts with no history. Re-verified 2026-10-30 by reading: one epoch-stamped
name feeds both the token's `spiffe_id` and the pod's `NRVQ_SERVICE_ACCOUNT` (`main`: `sa/default`). Two
runs started in the same second share an identity, and setting `RUN_SA` reuses one on purpose. Live:
16/16 on kind (`22c1232`, and again on `a72bebc`).

**Decision E — DONE on `prep/0.2.6` (2026-11-02/03; 16 commits, `ba43906` through `ea1e5d8`). All 16
gated green (§7.16).** What
DELETE /agents should do is settled:

* **DELETE /agents answers 409 while the agent is frozen or capped** (`aa107b0`). It no longer lifts an
  admin freeze or trust cap as a side effect; lift it explicitly first.
* **An explicit, audited reset:** `POST /agents/{id}/trust/reset` (CLI `norviq agent reset-history`),
  admin-only, clears the behavioural history and profile in one delete and logs `NRVQ-API-7145` with
  the actor, the score before and what was cleared. It is not a lift: a freeze or cap stays in force,
  and `audit_log` and the cumulative violation count are untouched (`2077368`).
* **`NRVQ-API-7031` carries the actor** (`actor`, `actor_role`) (`c284676`).
* **`PUT …/trust` upserts the registry row** for an agent that has none, and never answers 200 without
  the durable write (`ba43906`); the CHANGELOG says both (`173c04d`).
* **Retention never ages out a frozen or capped row.**
* **All admin trust writes and the boot warm are serialised per agent** (`6051752` onward): a
  session-level Postgres advisory lock, the two writes ordered by direction so the store is never
  looser than the registry, a fenced store write with a monotonic owner token. A freeze always goes
  live, even under lock contention or a database outage, and the response says whether it was
  persisted.
* **One identity rule** (`5fb62be`, `70d950a`, `9c89d98`): a `spiffe://` prefix, non-empty after it,
  at most 512 characters, valid UTF-8 without NUL — for keys, admin routes and the evaluator. An invalid
  identity blocks in every posture as `invalid_spiffe_identity` (`NRVQ-ENG-2006`).

Eight independent review rounds plus two focused verifications; the final verdict PASS. **Known
limitation:** SPIFFE ids over 512 characters (the spec allows 2048 bytes) are refused everywhere;
widening needs a planned migration (an online index rebuild on the `audit_log` partitions), not a
startup `ALTER` (`7064505` keeps the columns at 512). **Follow-ups, not blocking:** a freeze answered
"Persisted but NOT confirmed live", when only the liveness check timed out, does not retry the store;
DELETE's conditional statement is bounded only by the driver timeout.

**Update 2026-09-16 — a reset through the product does not reset.** A step calling
`DELETE /agents/{spiffe_id}` before each run was tried (stashed, not committed: `git stash list`,
"scenario trust reset via DELETE /agents"). Run 1 after it scored 12/16, run 2 still 10/16 on
`escalate_low_trust`. In-pod, authenticated (`DBSIZE` 3 as the control): after the delete,
`agent_profile:<id>` and `agent_history:<id>` survive — the handler drops the registry row, the
freeze key and the trust override, not the behavioural history the score is recomputed from. So a
re-registered identity inherits its violations. That the history drives the score is inferred from
`AgentHistoryStore`/`AgentProfileStore` and the result, not control-tested (2026-10-30: confirmed by
reading `violation_rate`; still not control-tested).

**Correction 2026-10-30 — DELETE /agents removes the freeze and the trust cap durably, and keeps the
history.** Measured against a real Redis with keys seeded through the product's own writers: before
`{history, profile, freeze, trust_cap}` all present; after DELETE, history and profile survive and the
freeze and trust cap are gone. The durable copy of the freeze and cap lives on the `agent_registry`
row (written by `PUT /agents/{id}/trust`), and DELETE removes that row, so a re-registered identity
comes back unfrozen and uncapped while inheriting its violations. That history drives the score is
now confirmed by reading (`violation_rate` scores off `AgentHistoryStore`, a 1-hour rolling set);
`AgentProfileStore` (7 days) holds learned normal behaviour, not violations. Only an admin can call
DELETE, and an admin can lift a freeze directly anyway, so this is about the audit trail and operator
expectation, not privilege — but DELETE's log line does not say a freeze was lifted, and
`PUT …/trust` logs `NRVQ-API-7031` without an actor.

The entry's original framing — "clearing history on delete would make deregister-and-return a way to
launder an agent's record, the same laundering the MCP plan refuses for `forget_server`" — holds for
history, but the behaviour then was the reverse on the strongest admin control: deregister-and-return
lifted the freeze and kept the record. The decision owed was: fix the docstring either way; then either
an explicit, audited "reset history" that also stops DELETE lifting a freeze or cap (refuse with 409
while frozen or capped, or keep a tombstone), or keep DELETE as is and say so. Taken: the reset plus
the 409 (above). The missing actor on `NRVQ-API-7031` is fixed too.

Original entry: re-running it against the same cluster scored lower on identical code: **13/16, then
10/16, then 12/16**. The middle run began with the agent already at trust 0.30 from the previous run's
attacks, so `escalate_low_trust` caught the two benign controls. Nothing in the script reset trust or
warned that the first run poisons the second, and the score was printed as if it were a property of
the code. The 12/16 was the honest clean-baseline number with the 7.11 checks corrected (reset with
`delete from agent_registry where namespace='agents'`, `FLUSHALL`, restart the API), before 7.10.

### 7.13 DCO: the charter requires it on acceptance; 0 of 540 commits carry it

**Status 2026-11-03:** decided (D in §7.23); the in-repo half is DONE on `prep/0.2.6` (`bc628c0`);
enforcement is a GitHub setting the maintainer owns. `CONTRIBUTING.md`'s DCO section now says what a
`Signed-off-by` certifies (origin, not review), how to add it (`git commit -s`, `git rebase --signoff`),
that it must match the author, that the CNCF charter requires it on acceptance, and that the DCO check
applies **from the day it is enabled**, with earlier history left as is and remediation commits, not
rewrites, for anything that got through unsigned. The sentence no longer claims a check that does not
exist (`ls .github`: no `dco.yml`; `grep -ri dco .github` matches only "hardcoded"). `be06ad6` adds
`.github/dco.yml`, which lets the DCO App accept individual remediation commits. Still to do: the
maintainer installs the DCO App and makes it a required check (the file does nothing until then). On prep, 4 of 142 commits carry a
`Signed-off-by` (`9e3ae03`, `1dfc80e`, `bc628c0`, `4a1654f`).

Verified 2026-10-27 (original entry). The CNCF charter (§11, `cncf/foundation/charter.md`) says
inbound code contributions "shall be … accompanied by a Developer Certificate of Origin sign-off".
`CONTRIBUTING.md` on this branch says "every commit in a pull request needs it", while nothing enforces
it (no DCO app; the only workflow hit for "dco" is the substring in "hardcoded") and **0 of 540 commits
on `main` have a `Signed-off-by`**. The sentence is a stated rule that neither CI nor history follows.
Options: start signing off now and add a check once `cncf-readiness` lands (commits before the section
are exempt, as it says), or word it as a request until then. Adding the maintainer's sign-off to commits on
their behalf is the maintainer's certification to make, not the tooling's — not done.

### 7.14 PR #109's CI never ran; the approvals expired

**Status:** verified 2026-10-27; not re-checked since. All three runs on `e8b3886` show `completed / failure` with **zero jobs**
(control: a `main` run has 4). They sat at `action_required` from 2026-08-24 and GitHub expired them on
2026-09-23. The red X is not a test result. Re-running needs the maintainer's account; the contributor's
last activity was 2026-09-01. The same change passes the full CI-equivalent gates as `227a3ba` on
`prep/0.2.6` (§1.1b), which is not a substitute for the PR's own run. Decision G in §7.23: the
maintainer re-runs #109's CI and merges #109 first at the cut (§1.1b).

### 7.15 Sandbox eligibility: 2026-11-28, enforced by an automated pre-review

**Status:** verified 2026-10-27 from `cncf/sandbox`. Since 2026-08-19 a Copilot pre-review
(`scripts/sandbox-application-review-prompt.md`, `.github/workflows/sandbox-application-review.yml`)
labels an application `Postponed` on a "clear violation", including repo `created_at` under 6 months and a
MAINTAINERS link that 404s. `norviq-dev/norviq` was created 2026-05-28. On `main` today
`MAINTAINERS.md`, `ROADMAP.md`, `GOVERNANCE.md`, `ADOPTERS.md`, `NOTICE` and `CHANGELOG.md` do not exist —
they are on this branch only. The form also rejects "will add after acceptance".

**Readiness, 2026-11-05.** Re-checked: on `main` (read 2026-11-05) the six files are still absent; they are on
`prep/0.2.6`, with the governance, conduct, release and review files brought to the CNCF project-template
shape (`282a4f8`), SECURITY.md, issue and pull request templates and supply-chain metadata (`281cd3a`),
and signed release assets, Dependabot and read-only workflow tokens (`be06ad6`). The plan:

* **Filing on or after 2026-11-29**, a day past the six-month mark, because the pre-review reads the repo's
  age once, when the application opens.
* **`MAINTAINERS.md` and `ROADMAP.md` must be on `main` first**, so every link the form gives answers;
  until prep merges, they are not.
* **Naming.** A prior unrelated company uses the name Norviq for software. Before filing, the maintainer
  runs the official trademark searches by hand, and a question to the Linux Foundation on whether the
  name can be assigned is drafted. The application's naming checkbox stays unticked until that is
  answered. Verified so far: a name search found the prior use; the official searches have not been
  run.
* The maintainer signs the contribution agreement as an individual. Filing, the GitHub settings
  (§7.5, §7.13) and the fields that need the maintainer's own words are his.

### 7.16 0.2.6 preparation (2026-10-28) and release (2026-11-05)

**State 2026-11-05 (final):** `prep/0.2.6` is at `7211672`, **159 commits on top of `cncf-readiness`
(`b622399`)**: 26 from the maintainer's machine (through `f375420`), 114 more through the folded tip
`a72bebc` (116 before the fold), `9477a47`, 7 integrated on 2026-11-04/05 (`58f04ad` through
`cb5f14f`: the Gate A test and ceiling, exit-state G1, HA on Valkey, the governance and security-policy
files, release signing and Dependabot, the error-code index), and 11 more through `7211672`: the UI
licence work (the bundled web font and the d3 umbrella's dependency removed, `192d731`, `231d3be`,
`8787b59`, and the allowlist test, `06f5863`), the third-party notices file and its place in the
console image (`6044c04`, `43f090b`), the lint-tooling advisory bumps (`c8d9245`), the image hardening
(pip removed from the api and engine runtime images, `c678e68`; the webhook on distroless
static-debian13, `7211672`), and the docs commits (`a121993`, `259b138`). **All 12 gates are green on `7211672`** (pytest 4770 passed) and on the final prep tip `b5e42d0`
(pytest 4778 passed; `96ec8a5` plus one test fix, the UI font check pruning installed trees at any
depth). On kind, images built from `96ec8a5`: the full validate passed (L3 integration 68/4/0, attacks
209/209, L4 190 passed, injection 18/18, probes 13/13, default deny 19/19, MCP re-verify 84/84), the
upgrade from v0.2.5 and rollback passed 27/27, and a live chatbot run decided every case as expected.
**Released as 0.2.6 (2026-11-05):** the release commit bumps `pyproject.toml`, `Chart.yaml` and the
install and upgrade docs to 0.2.6 together, so `scripts/check_release_versions.py` agrees.

* **Security fixes whose advisories publish with the release.** Nothing more about them is in this
  file until then.
* **The namespace baseline enforces by default** (`b4c127a`), and the baselines are now tighten-only
  floors (`b9d414b`). Without the floor, the enforcing baseline would have switched off for every agent
  class with a policy of its own, because the chart stores it at priority 1. The per-control switch
  that makes this operable is §7.19.
* **The false-positive measurement now uses the engine's own input builder** (`ca57189`). Its hand-built
  input omitted `derived` and the normalised params. Over 51 benign cases, no decision changed: 0 false
  positives at all-deny, 4 refused by design. Re-run 2026-10-30 with the same result.
* **`test_priority_enforcement.py` could not fail.** Every call in it blocked as `trust_frozen`, and the
  tests asserted only `block`. They now run as a healthy agent and assert the deciding rule.
* **`llm05_supply_chain`'s console copy said "from untrusted sources".** The rule matches tool names.
  The copy is corrected; the control stays at deny.
* By 2026-11-02: §7.7, §7.10, the §6 reload note, §7.3's digests and §1.1b were done, and §7.17–§7.22
  were new.
* Since 2026-11-02 (`4d9c761`): the third-party image bumps and `pyasn1` (§7.24); decisions B, C and D
  in the repo (§2.2, §7.4, §7.13, §7.27) and the datastore startup retry (§7.25); the Valkey upgrade
  review fixes, with the follow-up branch kept out (§7.21); decision E (§7.12); the MCP re-verify and
  cold catalog (§6) with the other MCP proxy changes (§7.26); two more test fixes (§7.22).

**Gates.** The full CI-equivalent suite (pytest, ruff, `opa test`, gofmt, go vet, go test, helm
lint/template, `npm ci`, tsc, vitest, eslint, the UI build), each commit with the CI venv synced from
its own `uv.lock`. The 26 commits from the maintainer's machine (`b622399`…`f375420`) were not gated
here.

* **`f375420`…`4d9c761` (48 commits after the maintainer's; 50 before the fold):** all gated. The ones
  gated on 2026-11-02 (`227a3ba`, `4d84c2f`, `34a8c10`, `4d9c761`, the fix-up now folded into
  `2667908`, and `29af7e8` re-run on a quiet host) are green. Before the fold two ranges failed
  deterministically on a test a later fix-up fixed (`test_failures_are_loud` over 6 commits from the
  classifier commit; four `fleet_bundle` cases in `tests/engine/test_legacy_empty_literals.py` over 5
  commits from the legacy-literal rewrite). The fold put each fix-up into the commit that needed it, and
  the rewritten commits (`847a021`…`15826be`) were re-gated: all green (below). Earlier reds were tests that later
  commits rewrote to assert what they mean (§7.22): `7fd40d5` (a test asserting the rule `1a199c4`
  reversed, fixed by `03d365c`, and Gate A wall-clock timing, `d0dc922`), `03d365c` (Gate A timing),
  `c243307` (header debounce after unmount, `4d84c2f`), `995a429` and `6725738` (console scroll timer,
  `5f32c2b`). `6725738` also failed a 5 ms trust-calculator timing check under load, which is
  environmental and was not rewritten.
* **`ff019bb` through `386323a` (13 commits):** all gated; green except three reds that a later commit
  fixes in the test or the component (§7.22): `f350332` (vitest: 1254 passed, then an unhandled error
  from the login screen's redirect timer after teardown; fixed by `44d0d93`), `9e3ae03` and `26932ba`
  (Gate A's bare-string scaling test on a loaded host; fixed by `386323a`).
* **The 16 decision-E commits (`ba43906`…`ea1e5d8`) and the first 17 MCP commits (`94b2f8c`…`7a052e6`):**
  all green.
* **The last gate run (2026-11-04): 32 commits** — the remaining 20 MCP commits (`c717904`…`a72bebc`)
  and the 12 the fold changed (the 11 rewritten commits `847a021`…`15826be` and the tip `9477a47`).
  **26 green, 6 red**, and every red is the same single test, nothing else failing anywhere:
  `tests/mcp/test_gate_a_bounds.py::test_a_realistic_large_catalogue_is_not_withheld`, a 0.300 s
  wall-clock budget on a 1200-entry listing through Gate A (`4ff9d37`, `344a3f4`, `d3ba849`, `72b7358`,
  `a72bebc`, `9477a47`; 0.302–0.379 s). Measured on a quiet host (3 rounds × 10, median CPU ms): the
  listing costs 271–350 ms at every commit from `72b7358`, where the guide's "~165 ms" figure was
  written, to the tip, with CPU equal to wall time, so the budget was host-dependent rather than
  regressed: it failed about half the runs on a 4-vCPU 2.1 GHz host. `58f04ad` makes the test
  host-independent: it asserts the scan units spent against the budget (763,560 of 786,432), keeps a
  coarse 1.0 s wall-clock guard, and adds a test pinning the listing ceiling (§7.26). Not re-gated per
  commit since; the full suite passes at prep's tip.
* **The fold (2026-11-04):** the two fix-ups were folded into the commits they fix, the tree is
  identical (the folded tip `a72bebc` and the pre-fold tip have one tree id, re-checked 2026-11-05), and
  the pre-fold history is kept locally.

**Live on kind, images built from `a72bebc` (2026-11-03):** seed PASS; L3 integration 68 passed /
4 skipped / 0 failed, attacks 209/209; chatbot scenario 16/16; injection e2e 18/18; L4 (Playwright) 188
passed / 7 skipped / 1 flaky (passed on retry), and 190 passed / 0 failed in the exit-state check's own
browser run; live probes 13/13; default deny and its three off-switches 19/19, each with a control; MCP
re-verify 84/84 (§6). (The previous run, on `22c1232`, predated the OPA bump and the later commits.)

**Exit-state (`scripts/kind-e2e/exit-state.sh`) on `a72bebc`:** not all met.
* G1: pytest 4745 passed when run with the database environment CI provides. The script ran pytest
  without `NRVQ_PG_URL`/`NRVQ_REDIS_URL`, so the repo's fail-loud database tests errored there (16 failed,
  272 errors). **Fixed (`09c6b4c`):** G1 passes the caller's values, or else the ones `test.yml`'s pytest
  job uses, and never echoes the URL. Verified by reading the script; exit-state has not been re-run
  since.
* G2, G3, G7: met.
* G4 latency: p95 535–592 ms against a 500 ms target at concurrency 8 on a 4-CPU host (p50 307 ms).
  Not met on this host; needs a quiet, larger host before it says anything about the product.
* G5 chaos: refused, because the API answered 502 right after G4's load — the same environmental cause
  as the previous run.
* G6: needs an LLM key; not run.

**Upgrade v0.2.5 → `a72bebc`, then rollback: 27/27**, including the session and logout checks. Because
the bundled store starts empty on upgrade (§7.21), a token logged out under 0.2.5 is accepted again
after the upgrade until it expires; the CHANGELOG says so and gives the way to end every session
(rotate `api.secretKey`).

**Trivy** (HIGH/CRITICAL, fixable, as `build.yml` gates): api 0, engine 0, webhook 0. The ui and
bootstrap images could not be built exactly on the test host (no Alpine package mirror reachable), so
those two were not scanned here; CI's build must scan them.

**Pending before the cut, for the maintainer, in order.** Done since 2026-11-03: the gate result
(above), the fold and the SHA re-map, G1's database environment (`09c6b4c`), the strict-preset defaults
confirmed as shipped (A), and the `docs/error-codes.md` recount (§1.2, now held by a test).
1. CI builds and Trivy-scans the ui and bootstrap images (Alpine 3.24 base, §7.24); the other three are
   clean. The third-party images with findings upstream has not rebuilt are §7.28.
2. Exit-state G4/G5 on a quiet host with more CPU, G6 with an LLM key.
3. The CB-5/CB-6 re-run on the candidate (H; needs an LLM key and a browser).
4. The HA path on kind with the failover on Valkey (§7.21); and the full kind validate and upgrade test
   on the exact final SHA, run alone, after the last code change.
5. Sign the DCO remediation commit (C), install the DCO App as a required check (D), rotate the dev JWT
   (F), the repository toggles and #109's CI and merge order (G, §1.1b).
6. The maintainer's review of the branch.
7. Enable GitHub private vulnerability reporting on the repository: `SECURITY.md` names it as the
   preferred reporting channel, so it must be on before the branch is public.
8. Publish the security advisories.
9. Then push, version bump (squashed with `prep/0.2.6-version-docs`) and cut — each only on the
   maintainer's explicit go-ahead.

### 7.17 FOSSA had not scanned Python since 2026-08-19; dependency advisories cleared except three low

**Status:** FIXED on `prep/0.2.6` (`df2ee22`, `7e09c66`, `0350773`, `8d41c5f`, `cc6c21c`, follow-ups
`d105561`, `4cfb7ce`, `d078b8a`, and `a07c088`).

* **FOSSA's Python target was never read.** `type: pip` is not a fossa-cli target type, so every run
  since 2026-08-19 graded Go and npm only (`cc6c21c`). It is `setuptools` now, and `fossa.yml` fails
  unless the scan summary lists setuptools, npm and gomod. The scanned closure is the one the images
  install, `.[spiffe]` (60 → 64 packages), and a pre-scan check fails on an empty or unparseable
  requirements file (`d105561`).
* **Optional extras:** 69 advisories in the lock closed by bumps — crewai ≥1.15.29, langgraph ≥1.2.14,
  mcp ≥1.30.0 (`0350773`). Installs pinned to older versions of those no longer resolve; the CHANGELOG
  and CONTRIBUTING say so (`d078b8a`). The report-only `deps-audit` job now audits every extra, which
  SECURITY.md claimed and no job did (`4cfb7ce`).
* **Webhook:** go 1.26.10 and `x/net` 0.62.0 (`df2ee22`). **Console dev tree:** 20 of the 23 packages
  `npm audit` flagged clear inside the declared ranges (`7e09c66`).
* **PyJWT** floor 2.15.0 (PYSEC-2026-4141, PYSEC-2026-4183; 2.14.x carried both) (`a07c088`).
* **The accepted-exception table** argued three rows from stale facts and missed three chromadb CVEs
  (CVE-2026-45830/-45831/-45833); corrected (react-router removed) and tied to the gate by a test
  (`8d41c5f`).

**Open:** the per-extra audit evaluates environment markers for Python 3.11 and reads only the PyPI
advisory feed. `npm audit` on the console dev tree reported 3 low when `7e09c66` landed (deepmerge 4.3.1,
no fixed version; no JS from it reaches the bundle); the 2026-11-04 sweep finds 14 in dev tooling, all
to be bumped (§7.28).

### 7.18 Red-team scoring: the console and the CLI disagreed with their own scorecard

**Status:** FIXED on `prep/0.2.6` (`c243307`, `ac3d88a`, `3252111`, `29af7e8`, `0fba535`).

The console's Red Team table decided "got through" on its own and disagreed with the scorecard; rows
carry the server's verdict now (`c243307`), and a reset that ran after a run appeared no longer undoes
the got-through filter (`ac3d88a`). `norviq redteam run` scored a throttled or faulted block as a pass
and replayed RL-001 61 times, which could throttle every attack after it (`3252111`); the console's
"Suite pass-rate" made the same mistake (`29af7e8`). One rule now decides `passed` for both runners.
The CLI also sent no `call_depth` and no MCP context, so CE-001 was allowed through the CLI and blocked
in the console and MCP-01..03 never made their attack; both runners build the call from one function
now (`0fba535`).

**Open:** the CLI reports packs that are not loaded as FAIL where the console says "not enabled"; an
escalate on a block-expected attack shows on the scorecard but counts as a pass in neither runner.

### 7.19 Per-control precedence: the console's switch could not relax what the chart baseline enforced

**Status:** FIXED on `prep/0.2.6` (`f12e627`, `a34e3c2`, `5fe9157`, `664f832`, `22c1232`); verified live
on kind (`22c1232`, and 19/19 again on `a72bebc`, 2026-11-03). The defaults ship as recommended, 20/1,
and the maintainer confirmed them as shipped on 2026-11-04 (A in §7.23).

With the baseline enforcing by default (§7.16), the console's per-control Off/Monitor did nothing for
a control the chart baseline enforced. Saved effects (`<ns>:__controls__`) now supersede the chart
copy, but only when `covers()` proves the saved module is an exact re-render: the placeholder is
matched by equality, and each head must have a single balanced body. Defaults follow the strict preset
as authored — 20 controls act (17 refuse; `llm06_excessive_agency` refuses destructive tools and
escalates elevated ones; two MCP definition controls escalate) and 1 records
(`scope_violation_dangerous_tool`) — because a save sends the full map and the console's old default
table had three of the preset's blocks at Monitor, so a no-op save relaxed controls nobody touched
(`a34e3c2`). The fleet hub and spoke refuse the reserved scopes. A save writes the stricter of the old
and new module, then the rows, then the final module, under an advisory lock; startup re-renders the
modules and compiles saved rows that have no module (`22c1232`). `verify_release.py` expects 20/1, and
the docs name the three ways off (`664f832`).

This also resolves an inconsistency the 2026-10-30 re-check found: `values.yaml`, the CHANGELOG and the
README said four controls "ship at monitor and only record", while the chart baseline (the preset as
authored) blocked `execute_sql` as `strict_default_block` and the release gate expected `audit` there,
so 0.2.6 would have failed its own gate.

Three independent reviews; the final one passed: `covers()` was not fooled by 476 hand-made and 3000
random variants (0 fail-opens); fault injection at 6 points and process kills at 4 points never left
the engine looser than GET reports; the Off/Monitor/Enforce matrix came out 462/462; `verify_release`
fails five deliberately broken artifacts. Live on kind, each with a control, 19/19: on by default; a
class with its own allow-all policy is still floored; namespace Monitor records while an untouched
namespace still blocks; per-control Off allows and Monitor records while another control still blocks;
install-time `--set baselineClusterPolicy.enforcementMode=audit` records.

**Open:** a namespace whose controls panel was saved under 0.2.5 sees three controls move Monitor →
Enforce (tightening only; the CHANGELOG says how to keep Monitor) — decision A, confirmed: no change. The "All namespaces"
view reads saved controls from memory only (display only, and stricter). `values-dev`'s global audit
makes Target Settings read Monitor while the baseline enforces (documented).

### 7.20 OPA 1.19.1 → 1.21.4, and the bare empty literals 1.21 rejects

**Status:** FIXED on `prep/0.2.6` (`34a98c3`, `2667908`, `79d3570`, `902bb09`, `2baca33`, `15826be`,
`2667908`). Release blocker.

Trivy 0.69.3, run the way `build.yml` runs it (HIGH,CRITICAL, ignore-unfixed, exit-code 1), finds 9
fixable HIGH in the OPA 1.19.1 binary (Go stdlib, x/crypto, x/net, x/text, grpc), so the api and engine
images would fail the gate — the same thing that stopped v0.2.0. 1.21.4 and 1.22.0 both scan clean;
1.21.4 was chosen. Every release that clears them is ≥ 1.21.2, whose type checker rejects reads from a
bare `{}`, `set()` or `[]`, and Norviq's generators emitted them. So:

* generators emit typed empty forms of the same kind and value (`34a98c3`);
* rows stored by ≤0.2.5 are rewritten in memory at the OPA boundary — only exact generated code lines,
  never anything inside a raw string, and the stored rows stay untouched, so a rollback is safe
  (`2667908`, `902bb09`; `NRVQ-ENG-2070`/`2071`);
* every pin moves together — Dockerfiles with both arch checksums, the chart image and digest,
  workflows, capabilities files — held by `tests/release/test_opa_pin_lockstep.py` (`79d3570`);
* the CHANGELOG's upgrade note gives operators the `opa check` command for hand-written Rego (`15826be`).

Two independent reviews; both passed, and the second's raw-string cases now decide as the policy text
on both binaries. pytest and vitest give identical results on the release 1.19.1 asset and on 1.21.4;
`opa test` counts are identical. **On kind since 2026-11-03:** the run on images built from `a72bebc`
carries 1.21.4 (§7.16).

**Open:** hand-written Rego is not rewritten (the CHANGELOG gives the check command); how long the
in-memory rewrite stays, and whether a pre-upgrade checker or a one-time regenerate migration replaces
it, is decision K. The webhook links the OPA Go library 1.18.2, for parsing only.

### 7.21 Valkey 8.1 could not read 0.2.5's store, and HA would have rolled into it

**Status 2026-11-03:** FIXED on `prep/0.2.6` (`995a429`, `8cb4aed`, `4d9c761`), with the first review's
fixes (`44da03e`, `a7dfcd7`, `e4ddbcc`, `26932ba`). The follow-up branch that re-seeds durable state is
**kept out of 0.2.6** (decision I); the gap it would close is a documented known issue instead (below).
Upgrade v0.2.5 → `a72bebc` and rollback on kind: 27/27 (§7.16).

* **The upgrade from 0.2.5 crash-looped the bundled store** (`995a429`). Measured live on kind
  (2026-10-30): 0.2.5's `redis:7-alpine` had floated to Redis 7.4, which writes RDB format 12 on the
  persistent volume; Valkey 8.1 reads format 11 at most and exits, so `helm upgrade` timed out with the
  new api and engine in `Init:1/2`. Valkey now mounts the claim with `subPath: valkey` and starts
  empty; 0.2.5's dump stays at the volume root, untouched, so `helm rollback` finds it. The CHANGELOG
  states what an empty store resets and what Postgres restores.
* **The release gate's upgrade job had never upgraded** (`8cb4aed`): a shallow checkout fetched no
  tags, so `--upgrade-from auto` silently ran the fresh-install path under the upgrade job's name. It
  now asks the chart registry for the newest published release ≤ the candidate or fails, writes to the
  store before upgrading, and checks the store's restart count after.
* **HA would have rolled Valkey into a running Redis 7.4 failover** (`4d9c761`): `templates/redis-ha.yaml`
  took `images.redis`. The failover keeps its own `redis.ha.image`, `redis:7.4-alpine`, pinned by
  digest; moving HA to Valkey is a separate, deliberate change. Rendered before: the failover image was
  Valkey; after: Redis 7.4, with the single-instance store still Valkey. Not run live on an HA cluster.
  Superseded by the next item.
* **HA moved to Valkey** (`7da3cb8`, 2026-11-04; the licence decision). The failover's redis and
  sentinel pods run `valkey/valkey:8.1-alpine`, pinned by the same digest as the single store (the
  sentinels used to run the operator's own default image on a bare tag, §7.3). Valkey 8.1 cannot take
  over 0.2.5's Redis 7.4 failover in place: a Valkey replica pointed at the pinned Redis 7.4 master logged
  "Can't handle RDB format version 12" and never linked. So the failover has **a new name**,
  `norviq-valkey-ha` (was `norviq-redis-ha`), which gives a new StatefulSet and new claims; the master
  Service keeps its name, so `NRVQ_REDIS_URL` does not change. **The store starts empty on upgrade**,
  with the same resets and the same API restart as the bundled store, and 0.2.5's failover claims are not
  kept for a rollback (they carry an owner reference to the deleted failover); the CHANGELOG says both.
  Verified: rendered and held by tests for both pod kinds, the name, the claims and the Service and egress
  selectors; the operator's replication, readiness, shutdown and sentinel-failover steps were re-run
  against the pinned Valkey image outside Kubernetes. **Not verified: the HA path on kind** — still to
  re-test on a cluster before the cut (§7.16).
* **Review fixes, carried without the re-seed** (2026-11-02). `44da03e`: `verify_release`'s store
  check now sees a replaced pod and its API check no longer passes early; an empty `--upgrade-from` is
  refused; the CHANGELOG says how long freezes are absent and what to do (it had understated the gap).
  `a7dfcd7`: a failed boot warm of freezes and caps used to log a WARNING and return 0, which reads like
  "nothing is frozen"; both boot warms (freezes/caps, and namespace posture) are now retried 3 times,
  each attempt cut off at 10 s (`NRVQ-API-7158`/`7159`), then logged at ERROR (`NRVQ-API-7035`/`7138`),
  and the API starts anyway — refusing to start would not put the state back. `e4ddbcc`, `26932ba`: the
  docs no longer say a store flush can never lift a freeze, the reset-trust advice no longer clears caps
  by accident, and three `verify_release` mutants that survived are now caught.

**Known issue (documented in the CHANGELOG, `docs/trust-score-design.md` and `docs/error-codes.md`).**
Agent freezes, trust caps and namespace posture are persisted in Postgres but enforced from the store,
and an API process writes them into the store only on an admin change and once when it starts. After a
store data loss while the API runs (a flush, a restart from an older snapshot, a failover), they are
absent — a freeze or cap is enforced as none, and posture falls back to the chart-wide setting — until
an API pod restarts. This is 0.2.5's behaviour, not new. **Mitigation:** after any such event, and
once after `helm upgrade` to 0.2.6, run `kubectl -n <namespace> rollout restart deployment/norviq-api`
and look for `NRVQ-API-7034` (freezes and caps) and `NRVQ-API-7063` (namespace posture);
`NRVQ-API-7035`/`7138` mean that pod did not restore them.

**The follow-up branch is not in 0.2.6.** It re-seeds that state into the store
when it loses data while the API runs. Its fifth independent review **failed** with five confirmed
blockers — failover and restore edge cases, and a race in its repair queue that could clear a freeze
set moments earlier. Four earlier rounds had each failed and been repaired. Decision I (2026-11-03):
keep it out and ship the known issue above; any later attempt starts from a fresh review. Decision J
(how a freeze behaves during a Postgres outage on that branch) no longer applies to 0.2.6.

### 7.22 Harness, CI and flaky tests

**Status:** FIXED on `prep/0.2.6`.

* **CI's kind-e2e tested the published images, not the pull request's** (`90b9f49`): only `00-up.sh`
  passed `images.registry=norviq/`, so CI ran `ghcr.io/norviq-dev/…-latest` while the PR's build sat
  unused on the node. The registry and pull policy moved into the shared `values-e2e.yaml`, and a step
  asserts on the live cluster that every deployment runs the local build. Controls: drop the registry
  from `values-e2e` → the parity test fails; drop the verification step → it fails.
* **`verify-release`'s upgrade job was vacuous** — §7.21 (`8cb4aed`).
* **`00-up.sh` ran only on macOS**, judged the NodePort on its first instant, and stamped one image;
  it is portable now and stamps the git SHA on all five (`7fd40d5`).
* **Tests that failed on load or passed by accident now assert what they mean:**
  `test_cached_block_still_applies_post_decision` asserted the rule `1a199c4` reversed (`03d365c`);
  Gate A's budget tests timed the scan on the wall clock and failed at 529 ms on a loaded host — they
  assert the characters scanned now (`d0dc922`, `34a8c10`); a debounced header search fired after
  unmount (`4d84c2f`); a console scroll timer threw in jsdom (`5f32c2b`). None was weakened.
* **The 7.10 per-event cache write was a silent handler** on the security surface;
  `test_failures_are_loud` caught it at the gate, and it is justified in place now (`847a021`).
* **bandit's B608 would have failed the 0.2.6 pull request** on the chatbot policies; their modules are
  joined by a helper now, byte-identical (`abec18f`).
* **Two more tests that failed for the wrong reason** (2026-11-02). The console's post-sign-in redirect
  timer outlived the login screen and threw after vitest's teardown, failing a green run on a
  Dockerfile-only commit (`f350332`); the timer is held and cleared on unmount (`44d0d93`; control: the
  new test fails with `Login.tsx` reverted). Gate A's bare-string scaling test timed the whole delivery,
  which is legitimately linear in the entry count, and failed at 230 → 590 ms of CPU on a loaded host
  while the scan read the same characters; it times only the scanner calls now, with the slack tightened
  from 100 ms to 50 ms (`386323a`; controls: an unbounded scan fails the character assertion, and with that
  assertion disabled the CPU assertion fails on its own). Neither was weakened.
* **Exit-state G1** ran pytest without `NRVQ_PG_URL`/`NRVQ_REDIS_URL`, so the repo's fail-loud
  database tests errored there while CI's run passed; fixed in `09c6b4c` (§7.16).
* **Gate A's large-catalogue counter-test was host-dependent** (a 0.300 s wall-clock budget; the only
  red in the last gate run, §7.16). `58f04ad` asserts scan units instead, keeps a coarse 1.0 s guard,
  and adds a test that pins the listing ceiling. Not weakened: every other assertion is kept.

### 7.23 Decisions owed to the maintainer

Each had options and a recommendation prepared. Status as of 2026-11-03; "in-repo DONE" means the part
that lives in the repository is on `prep/0.2.6`, and what remains is the maintainer's own action.

| | decision | options in brief | recommended | status 2026-11-03 |
|---|---|---|---|---|
| A | strict-preset defaults (§7.19) | ship the preset as authored (20 act / 1 records), or author three heads as records | keep 20/1 | **CONFIRMED** as shipped (2026-11-04): 20 act / 1 records, no change |
| B | §2.2 `existingSecret` renders no wait containers | keep app retries and document `host`; or make `host` required beside it | keep retries, document `host` | **DONE** (`9e3ae03` docs; `4a1654f` startup retry, §7.25) |
| C | §7.4 four commits authored by a coding tool's identity on published history | rewrite; re-attribute with a note; leave and disclose; DCO remediation commit | don't rewrite `main`; provenance paragraph + DCO remediation commit | **in-repo DONE** (`1dfc80e`); the remediation commit is drafted, the maintainer signs it |
| D | §7.13 DCO | sign off from now and add a check; or word it as a request | install the DCO app, make it a required check | **in-repo DONE** (`bc628c0`); the App and the required check are a GitHub setting (maintainer) |
| E | §7.12 DELETE /agents | fix the docstring only; DELETE also clears history; explicit audited reset | audited reset; DELETE preserves or refuses over a freeze or cap | **DONE** (`ba43906`…`ea1e5d8`; 409 + audited reset; gated green, §7.16) |
| F | §5.1 dev JWT | — | rotate | open — the maintainer rotates |
| G | §7.5 repository toggles and required checks; §7.14 PR #109 CI | flip toggles or edit SECURITY.md; re-run #109 or ship through prep | turn them on; re-run #109's CI and merge it at the cut | **#109 DECIDED** (2026-11-04): `227a3ba` stays on prep (same patch as the PR head); at the cut re-run #109's CI, merge #109 first, then prep, resolving `docs/cli.md` and `tests/cli/test_main_entrypoint.py` to prep's side (§1.1b). Toggles: open — the maintainer, on GitHub |
| H | §6 plan | — | close the landed items; re-verify MCP and re-run CB-5/CB-6 on the candidate | **step 3 DONE** (MCP re-verify 84/84, cold catalog, §6); the CB-5/CB-6 re-run needs an LLM key |
| I | §7.21 follow-up branch in 0.2.6? | fifth review then integrate; or ship without and document | fifth review, then integrate | **DECIDED: kept out** — the fifth review failed with five confirmed blockers; the known issue is documented (§7.21) |
| J | freeze during a Postgres outage on that branch (enforced, reported "not saved") | keep; or refuse | keep | n/a for 0.2.6 (the branch is out) |
| K | lifetime of the OPA legacy-literal rewrite (§7.20) | keep; one-time regenerate migration; pre-upgrade checker | keep until a regenerate migration exists | keep (unchanged) |
| L | nginx / curl / console-base bumps (§7.3) | — | the maintainer's call; the Trivy numbers are in §7.3 | **DONE and KEPT** in 0.2.6 (`ff019bb`, `f350332`; §7.24; kept 2026-11-04). CI must build and Trivy-scan the ui and bootstrap images before the cut |
| M | run postgres non-root, taking `gosu` off the path | — | later; it changes volume permissions | later (unchanged); until then the `gosu` findings are documented and the image re-pinned when upstream rebuilds (§7.28) |

### 7.24 Third-party images off end of life, and `pyasn1`

**Status:** DONE on `prep/0.2.6` (2026-11-02; `ff019bb`, `f350332`, `7c748c7`). Decision L.

* **nginx and curl** (`ff019bb`). The chart's internal-TLS terminator ran `nginx:1.27-alpine`, the
  console image was built from `nginxinc/nginx-unprivileged:1.27-alpine`, and the helm test pod ran
  `curlimages/curl:8.10.1`. nginx 1.27 is end of life and both nginx images sat on Alpine 3.21, also end
  of life. Trivy 0.69.3 (HIGH/CRITICAL, fixable): 60, 58 (before the console build's `apk upgrade`) and
  22. They move to `nginx:1.30-alpine` (3), `nginx-unprivileged:1.30-alpine` (3) and
  `curlimages/curl:8.23.0` (0). `global.thirdPartyImageDigests` is re-keyed in lockstep, the old entries
  removed; each pin is the multi-arch index digest, and for nginx and curl a second registry returned
  the same digests. Validated: the console base runs the real `ui/nginx.conf` and entrypoint as uid 101
  and `nginx -t` passes; Trivy on the new bases. A registry mirror needs the new tags (CHANGELOG).
* **The bootstrap image** (`f350332`, the chart's TLS hook jobs) built on Alpine 3.21, which left
  security support on 2026-11-01; it builds on 3.24, the branch the console base now uses too. **Not
  verified here:** the build itself — no Alpine package mirror was reachable from the test host, so
  CI's image build and Trivy gate must exercise it (§7.16).
* **`pyasn1` 0.6.4 → 0.6.5** in the lock (`7c748c7`). It comes in through the `spiffe` extra, the
  closure the api and engine images install; `pip-audit` reported four advisories against 0.6.4, all
  fixed in 0.6.5. Only `pyasn1` moves. Control: the same audit on the previous lock reports the four;
  on this lock, none.

**Still open:** `postgres:16-alpine`'s `gosu` findings (§7.3, decision M), and the pinned
third-party images whose findings upstream has not rebuilt yet (§7.28).

### 7.25 The API and the embedded engine gave up on a datastore at the first refusal

**Status:** FIXED on `prep/0.2.6` (`4a1654f`, 2026-11-02). Found while deciding §2.2 (B).

With `existingSecret` and no `host`, nothing waits for the datastores but the app (§2.2), and the app
barely waited: measured against a refused port, the API's first Postgres connection did not retry a
refused connection at all (it failed in 0.28 s), the API's Redis connect gave up after about 15 s, and
the embedded engine retried nothing (0.01 s). Each ended in a pod restart, so a store that was slow to
come up showed as a CrashLoopBackOff. Both now retry each store 5 times, sleeping 1, 2, 4 and 8 s
(about 15 s), then fail startup: `NRVQ-DB-9035` per retry and `NRVQ-DB-9034` when exhausted for the
API's Postgres; `NRVQ-SDC-3045` per retry and `NRVQ-SDC-3046` when exhausted for the embedded engine.
The engine's Postgres warm retries only an unreachable store (refused, unresolvable, timed out, or
starting up), so an authentication failure or a bad row still surfaces at once. Tests:
`tests/api/test_startup_connect_retry.py`, `tests/engine/test_embedded_startup_connect_retry.py`.

### 7.26 MCP proxy: cold catalog, operator-visible changes, and the listing ceiling

**Status:** on `prep/0.2.6` (2026-11-02/03; 37 commits, `94b2f8c` through `a72bebc`). Gated: 32 green, 5
red on one host-dependent timing test, since made host-independent (§7.16).

* **Cold catalog** (`94b2f8c`; §6): a client that calls tools without listing them after the proxy
  restarts no longer has every call escalated as never-scanned; measured 45/45 → 0/45 on the final tree,
  45/45 with the self-list off.
* **Security fixes whose advisories publish with the release.** Eighteen independent review rounds.
* **Operator-visible changes:** a new setting, `NRVQ_MCP_HTTP_MAX_MESSAGE_BYTES` (default 8 MiB). The
  cold-catalog codes are `NRVQ-MCP-5079`/`5080`/`5081` (§6); other new MCP log codes are listed in
  `docs/error-codes.md`.
* **Known false positives and detection limits of Gate A are documented** in `docs/guides/mcp.md` §3.1
  (`a72bebc`), and the CHANGELOG matches the guide.
* **The listing ceiling (open, for 0.2.7).** One listing page is scanned within a fixed budget: on the
  shipped budget about **1235 ordinary entries** (uri, name and a description, ~180 characters each)
  are forwarded whole; past that the rest of the page is withheld, never forwarded unscanned, and logged
  as `NRVQ-MCP-5067` (`mcp_a_scan_budget_exhausted`). A server that paginates stays within it per page.
  Measured on the folded history by the largest realistic catalogue forwarded in full: 3311 entries
  before the scan read every string in full, 1373 after, 1235 once the folded length was charged, so the
  test's "realistic 1200" sat at 97% of the budget. `58f04ad` documents it in `docs/guides/mcp.md` §3.1
  and the CHANGELOG, and `test_the_documented_catalogue_ceiling_holds` pins it (1235 forwarded whole; of
  1300 the 65-entry tail withheld and logged), so a change to the budget or to the cost per entry fails a
  test. **To do in 0.2.7:** raise the headroom.

### 7.27 Decisions B, C and D in the repository

**Status:** DONE on `prep/0.2.6` (2026-11-02). Each commit changes only docs and comments, and each
claim in it was checked against the code or the repository before it was written.

* **B** (§2.2): `9e3ae03` — the datastore wait gate is documented as it renders; `host` is the opt-in
  gate. With the startup retry in §7.25.
* **C** (§7.4): `1dfc80e` — the provenance section in `CONTRIBUTING.md`; history is not rewritten. The
  DCO remediation commit is the maintainer's to sign.
* **D** (§7.13): `bc628c0` — `CONTRIBUTING.md`'s DCO section says what the sign-off certifies and that
  the check applies from the day the maintainer enables it.

### 7.28 Vulnerability sweep (2026-11-04): what is left is upstream's

**Status:** swept on `prep/0.2.6` at `9477a47`, all severities, with Trivy 0.69.3 (checksum-verified
binary), pip-audit, `npm audit`, govulncheck and osv-scanner. CNCF has no vulnerability-scan requirement
for Sandbox; the sweep was done anyway. The rule applied: Norviq-built images must have 0 fixable
findings; a digest-pinned third-party image with findings upstream has not rebuilt is documented here
with the reason and re-pinned when upstream rebuilds.

* **Clean:** the Python runtime closure (`.[spiffe]`) and every extra, 0; the webhook's Go modules
  (govulncheck), 0; the console's runtime npm tree (`--omit=dev`), 0; busybox, curl and Valkey 8.1, 0.
* **`nginx:1.30-alpine`** (the TLS terminator): 1 critical, 5 high, 2 medium, 44 low, 1 unknown, all in
  Alpine packages (curl/libcurl, brotli-libs, libexpat) that Alpine has fixed, but upstream's current
  `nginx:1.30-alpine` is still the pinned digest, so there is no rebuilt image to pin. **Re-pin when
  upstream rebuilds.** `nginx-unprivileged:1.30-alpine`, the console base, shows the same class; the
  console build runs `apk upgrade`, which is to be verified on the exact ui build in CI (§7.16).
* **`postgres:16-alpine`:** 1 critical, 25 high, 31 medium, 3 low, 1 unknown, all in `gosu` (the Go
  standard library and two Go modules it links); upstream's current image is not rebuilt, and
  `16.11-alpine3.23` scans worse. **Re-pin when upstream rebuilds**; taking `gosu` off the path by
  running postgres non-root is decision M (§7.23).
* **`openpolicyagent/opa:1.21.4-static`:** 3 of unknown severity (`x/crypto`, `x/net`); the latest
  static image scans the same.
* **npm dev tooling:** 14 advisories (2 low, 12 moderate) in the console's dev tree — the eslint family
  (`@eslint/config-array`, `minimatch`), the typescript-eslint family, and the shadcn CLI's dependencies
  (`@shadcn/registry`, `deepmerge`, `ts-morph`). None of these advisory packages ships in the bundle
  (shadcn's own CSS and tailwindcss do, and are licence-checked and in the notices file). **Bumped
  (`c8d9245`):** 3 low remain, in `deepmerge` through the shadcn CLI, which has no fixed release.

### 7.29 Concurrent full-suite runs on one host interfere through OPA's fixed port

**Status:** open, owner: the maintainer. Not fixed. Found while gating several worktrees on one host; the
cause read in the code, not control-tested. The OPA address the tests use defaults to `127.0.0.1:8181`
(`opa_addr` in `norviq/config.py`), and the OPA-backed tests spawn a managed OPA there
(`norviq/engine/opa_client.py`). A second full-suite run on the same host cannot bind the port, so its
tests either fail to start OPA or pass the health probe against the first run's server and push their
policies into it. Workaround until it is fixed: give each run its own `NRVQ_OPA_ADDR` (and its own
database and Redis db). Fix: have the test session pick a free port, or refuse to start when the port
is held by another run.

## 8. Audit claims that did not reproduce

Recorded so the next reader of the CNCF audit knows which numbers to distrust.

* "PR #109 has been open and unanswered" — answered twice by the maintainer on 2026-09-01, approved,
  held on the release cut. The audit predates the reply.
* "The only open PR" — four were open.
* "Three shipped dependencies carry non-allowlisted licences" — one (`certifi`, MPL-2.0) in the
  58-distribution `norviq[spiffe]` closure; the other copyleft-flagged packages are dev-only.
* "Posture may vary by preset / namespace list / prod overlay" — one behaviour, `audit`, on every
  path constructible. (True of the 0.2.5 chart; from 0.2.6 that one behaviour is `block`, §7.16.)
* "Nine dependencies carry NOTICE files" — five shipped; four are in the venv but not the images.
* "`git shortlog -sne` shows 7 identities" — the count is right; the command as written reads stdin
  when non-interactive and prints nothing. Use `-sne HEAD`.
* "0 reviews across 96 PRs" — 100 PRs; 96 is the closed count. The zero holds across all 100.
* "`README.md:244` is where Community goes" — stale citation; the section went before `## Security`
  at what was line 276.
* "`ruff` shows 5 errors on main" — exact for main; this branch had added three more before the gate
  existed, which is the gate's own argument.

