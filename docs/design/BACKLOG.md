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

### 1.1a Also landed on `cncf-readiness`, also unreleased (2026-09-02)

All verified with a control before commit; none reaches a user until 0.2.6 ships.

* **stdio MCP proxy degraded its pin store in silence** on the path the quickstart recommends
  (`file` with no path → memory, no log). Warning moved into `build_store` (`NRVQ-MCP-5078`) so no
  caller can forget it; tested through the real entrypoint. `9c97470`.
* **Two security booleans fell back to OFF** — `auth.requireBoundAgentIdentity` and
  `config.requireStrongSecret` used `| default false` while the code defaults True, so an overlay that
  nulled the key rendered `"false"`. Latent (stock pins true). The other four `| default false`
  booleans default False in code and are harmless. `3c2c2ec`.
* **`NOTES.txt` and the refusal message called the audit-mode baseline "fail-closed"**, in the text
  printed on every install. `c9ea106`.
* **#117's veto excused "silently skip the policy check"** — see §7.1; the fix is on the branch, the
  open PR still carries the bypass.

### 1.1b PR #109 (Mr-Neutr0n) — approved, held on the cut; three things to do before merging
**Status:** open, head `e8b3886`, approved by the maintainer's comments on 2026-09-01 and held so
the docs change in it does not describe a fix no released version has. **The only third-party human
contribution the repo has.** Reviewed by this session on the merits: the fix is correct, the
subprocess test is the right shape (`CliRunner` never executes `main()`), and reverting the one-line
fix makes the test fail — it can fail, for the right reason.

Before it merges, in order of consequence:

1. **CI has never run on this commit.** It is a cross-repository PR, and all three workflows on
   `e8b3886` sit at `action_required` with zero check runs — the only green is FOSSA's legacy commit
   status, which is what `gh pr checks` reports as "all passed". Approve the fork workflow runs
   first, or the first execution of the suite on this code is the merge itself.
2. **The test does not guard the half its name promises.** `test_json_payload_reaches_stdout_and_logs_go_to_stderr`
   never asserts anything is *on* stdout: moving the JSON to stderr leaves it green while `-o json |
   jq` reads nothing (probed). Issue #104's own checklist asked for `json.loads(proc.stdout)`. The
   maintainer's comment offered the success-case variant as optional; it is the load-bearing half.
3. **Two copy-paste examples still pipe through the `grep -v` workaround** the PR deletes the
   explanation for (`docs/cli.md:337` and `:483` on main). Harmless post-fix, but the file now
   contradicts the sentence the PR adds. A gap in #104's checklist, not the contributor's.
4. Minor: `subprocess.run` inherits the environment, so `HTTP_PROXY`/`ALL_PROXY` routes the
   deliberately-unreachable `127.0.0.1:1` through a proxy and the test fails on `returncode != 0`
   (measured). `tests/mcp/test_stdio_transport.py:62-68` already passes an explicit env.

Items 2–4 are for the contributor or a follow-up commit; item 1 is the maintainer's click. None of
this is on `cncf-readiness` — it is the contributor's PR and stays theirs.

### 1.2 E.1 and the 0.2.6 cut are one unit, not two items

**Decision:** ship the busybox fix (§2.1) and cut 0.2.6 together, or do neither. Not launch-gating.

The dependency runs one way and is easy to miss: **fixing `_helpers.tpl` does nothing on its own.**
Anyone installing gets the published chart, which hardcodes bare `busybox:1.36`. A fix that sits on
`main` while 0.2.5 remains the published chart is indistinguishable, from a user's position, from no
fix at all — while reading in the repo as done. That is this codebase's recurring defect shape applied
to the release process rather than to a control.

So the pair is:

1. §2.1 — wrap `busybox:1.36` in `norviq.thirdPartyImage` so `global.imageRegistry` relocates it
2. correct `docs/deployment.md:370`, which currently lists busybox among the images that key covers
3. cut **0.2.6**, which also carries the already-landed `deny_shell_execution` caveat fix (§1.1) and
   the `docs/error-codes.md` direction corrections

**Why it is not launch-gating.** busybox only breaks installs with no path to Docker Hub. An
evaluator on EKS/AKS/GKE — the target user — pulls it fine and never sees this. It is an
enterprise/air-gapped evaluation blocker, which matters on a slower clock than a launch.

**Why not cut 0.2.6 sooner.** As of this writing 0.2.6 would carry one corrected caveat string and
some doc rows. That is thin justification for spending a version and re-running the irreversible PyPI
path. §2.1 gives the release a reason to exist, and the docs corrections ride along.

---

## 2. Product defects — verified

### 2.1 `busybox:1.36` is not relocatable, and air-gap installs will fail on it
**Status:** FIXED on `cncf-readiness` (`0e51ea7`, control-tested: helper reverted → the relocation test lists five bare `busybox:1.36`). Still reaches nobody until a cut — see §1.2. **Severity:** first-run blocker on air-gapped clusters.
**Sequencing:** paired with the 0.2.6 cut — see §1.2. Fixing this without releasing changes nothing for users.

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

## 3. Docs drift — verified; most fixed on `cncf-readiness`, three held on purpose

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

**Held**, because each depends on a decision in §2 rather than on wording:

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
* **51 codes** covering more than one event at the same severity (52 until `9c97470` gave the pin-store
  warning its own code and `NRVQ-MCP-5067` stopped carrying two events — the ratchet's delete-the-entry
  rule fired, as designed). Untidy in a log reader, harmless in
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
**Status:** RESOLVED 2026-08-24 — `norviq-UI#2` removed the literal address rather than escaping it;
the live page now carries no `email-decode.min.js` (measured: 0). Kept for the record.

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

---

## 7. Opened during the CNCF readiness pass (2026-09-02)

Every item below was reproduced against the tree or the live API by this session; the audit that
proposed most of them had executed nothing. Where the audit was wrong, §8 says so.

### 7.1 PR #117 narrowed the concealment scanner into a bypass
**Status:** fixed on `cncf-readiness` (`6c4d3b3`); **the open PR still has it.** Decision: push the fix
onto the PR branch, or the maintainer takes it.

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
**Status:** FOSSA half resolved (`9aede34`, `111ccc0`); Framework Compat RESOLVED (`69f0010`); the
required-check question has a prepared, unrun settings script (§7.5).

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
is the recurring defect in a new costume.

FOSSA fails on the webhook's Go deps at `k8s.io/{apimachinery,client-go}` v0.33.0
(CVE-2018-1002105, CVE-2019-11250, CVE-2020-8565) — the gate working, the dependency old. Framework
Compat's autogen leg fails at collection on `protobuf` gencode 6.33.5 vs runtime 5.29.6. Neither
blocks a merge: `main` has no branch protection and no rulesets, so no workflow is a required check
— while `test.yml:2` calls itself a merge gate. The lint/audit gates added in `dafdcca` report and do
not block for the same reason. GOVERNANCE.md says when that changes.

### 7.3 The default Redis image is RSALv2/SSPLv1, on a floating tag, with no digest
**Status:** licence half RESOLVED on `cncf-readiness` (`50cfb18`); the digest half open.

Ships `valkey/valkey:8.1-alpine` — BSD-3-Clause, LF fork, minor-pinned. Validated before pinning:
the image symlinks `redis-server`/`redis-cli`, sentinel mode starts, and the full suite (3297) ran
green against a live Valkey — the first fully green run this cycle. compose, test.yml's service and
the chart now agree. Still open: no `digest` key on the redis entry, and release.yml's "every image
is digest-pinned" gate asserts `@sha256:` only on first-party lines. Widening it needs a rehearsal
run, which needs a push.

`redis:7-alpine` resolves today to 7.4.11 (OCI annotation and the image's own `REDIS_VERSION`),
which is past the 7.4 relicense. Unlike every first-party image the redis entry has no `digest` key,
and `release.yml`'s "every image is digest-pinned" gate asserts `@sha256:` only on `ghcr.io/norviq-dev/`
lines — false for six of eight images. Options: pin `7.2-alpine` (BSD-3-Clause, verified against
upstream `COPYING` at tag 7.2.16), or `valkey/valkey:8-alpine` (BSD, LF fork, drop-in for the
`redis://` client), then run kind-e2e against the Sentinel/HA paths. Either way the floating major
tag goes, and the release gate should assert digests on *all* `image:` lines.

### 7.4 Four commits are authored as `Claude <noreply@anthropic.com>`
**Status:** decision owed. `.mailmap` (`1855de8`) collapses the seven human spellings and deliberately
leaves these four alone — folding them into a human identity by mailmap would hide the question, not
answer it. An AI cannot certify origin under the DCO; a foundation doing IP diligence will ask.
Options: re-attribute to the maintainer with the AI noted in the body; leave and disclose; or a
one-off DCO remediation commit covering prior work. Not a formatting question. Also: 387 commits
(73%) carry a `Co-Authored-By: Claude` trailer; those stopped 2026-08-10 and are disclosure, not
authorship.

### 7.5 Repository security toggles are off, and SECURITY.md points at one of them
**Status:** verified live; decision owed.

Private Vulnerability Reporting: `enabled: false` (control: `github/docs` → true). Secret scanning,
push protection, Dependabot security updates: all off. `SECURITY.md:12-13` calls PVR "the preferred
channel" and `:8` forbids a public issue — a researcher following the doc finds no button and is
pushed toward the one route the doc bans. Either flip the toggles or edit the sentence; leaving both
as they are is the defect.

### 7.6 `.gitleaks.toml` allowlists every `.md`, so docs are never scanned
**Status:** FIXED on `cncf-readiness` (`d81e1ea`). Measured cost of removing the line across all 67
tracked `.md`: two findings — `NRVQ-API-7460` (a log-code id, now allowed by shape) and the example
one-time password #118 makes fake (same one-line change made here). Controls: 67 files → 0; a planted
`ghp_` token in a `.md` → found; `gitleaks git` over the PR range → 0. The first attempt scanned 0 bytes
twice and reported clean both times. Original entry: Line 12's `.*\.md$` means the `secrets` job does not
read `docs/cli.md` — or any markdown. #118's premise that "a scanner flagged" the example password is
true only of Mr-Neutr0n's scanner, not this repo's. Two credential-shaped strings have now lived in
docs; measuring what un-allowlisting costs across all 62 tracked `.md` files is the next step.

### 7.7 `docs/cli.md` line citations are systemically stale
**Status:** measured 2026-09-16, open. 122 `file:line` citations; 19 point at nothing a sentence could
mean (a blank line, a lone `)`, or a bare basename the page never resolves); 44 more sit 11–349 lines
below the symbol they presumably mean. The fix is symbol anchors, not renumbering. Original entry: `:14` cites `pyproject.toml:67-68`
(actual 82-83); `:608` cites `config.py:393` (actual 454, and 393 is a comment about body size).
Prefer function names and YAML key paths over raw line numbers; nothing in CI keeps a line number
fresh.

### 7.8 Two of the maintainer's worktrees were deleted by this session
**Status:** recorded. `../tmp/prega-92ceec1` (`release/pre-ga-consolidated`) and
`../tmp/wt-pre-ga-remediation` (`fix/catalog-hierarchy-batch2`) were removed by an over-broad
cleanup filter. Both branches are intact at `92ceec1`, last commit 2026-07-08. Any uncommitted work
in those directories is gone; `git worktree add ../tmp/<name> <branch>` restores the directory.

### 7.9 Steps not yet done from the CNCF audit
* **OpenSSF Best Practices badge** — never registered (`bestpractices.dev` → "Zero Projects";
  control: `kubernetes` → 431). Owner-only web form; criterion answers to be drafted from the repo as
  it stands *after* the items above, so justifications point at real artifacts.
* **Security self-assessment** (CNCF TAG Security abbreviated template) — the highest-value artifact
  and the one where an unverified claim is actively dangerous. To be written from the code at the
  moment of writing; §3's drift list is its raw material.
* **Framework Compat and FOSSA reds** (§7.2) — bump the k8s Go deps; pin protobuf in the autogen leg.

---

### 7.10 A misclassified tool NAME cascades into an agent-wide outage

Found by running `scripts/mcp-chatbot-scenario.sh` on a live kind cluster (2026-09-07), not by
reading. `classify_tool("run_query")` resolves to **delete** — the `run` token is in the lexicon as
delete/critical — and the evaluator consults an admin's promotion ONLY when the name classifier
returns `unknown`; when the name resolves, "the classifier wins outright, whichever direction the
promotion points" (`norviq/engine/evaluator.py`, pinned by
`tests/engine/test_promoted_verb_enforcement.py::test_a_promotion_cannot_demote_a_classified_tool_in_any_direction`).

That rule is right on its own terms — it stops a promotion being used to move a tool into an egress
refinement. The consequence is not:

1. A policy gating on `input.derived.verb == "delete"` blocks `run_query` permanently, and the
   documented remediation (promote the tool) cannot reach it.
2. The scenario retries the blocked call 12 times. Each refusal is a violation.
3. Trust falls 0.8 -> 0.515 -> 0.505 -> **0.30**, the floor. Measured across the audit rows of one run.
4. At the floor, `escalate_low_trust` catches the agent's BENIGN traffic — `post_message` to
   `#support` and `search_issues` on a different MCP server both escalate, on servers and tools that
   no policy rule touches.

So one bad name in the classifier lexicon degrades into an agent-wide, cross-server outage, and the
one admin control that looks like the fix is inert against it. Neither half is visible from either
side alone: the classifier looks correct, the trust control looks correct, the promotion returns 200.

Fix candidates, none applied yet — this needs a product decision:
* correct the lexicon so `run_query` does not tokenise to `delete` (narrowest, but the next
  `run_*` read tool hits it again);
* let a promotion outrank a name-classifier result when it is strictly DE-escalating and carries
  evidence, keeping the existing refusal for escalating promotions;
* have repeated refusals of the SAME tool+rule count once toward trust, so a policy loop cannot
  drive an agent to the floor.

The third is worth doing regardless: as it stands, any agent that retries a blocked call is
self-driving toward an outage, which is a denial-of-service an attacker can trigger deliberately.

### 7.11 Two harness checks reported green for something they never observed

Same run, both now fixed on `cncf-readiness`.

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

**Update 2026-09-16 — a reset through the product does not reset.** A step calling
`DELETE /agents/{spiffe_id}` before each run was tried (stashed, not committed: `git stash list`,
"scenario trust reset via DELETE /agents"). Run 1 after it scored 12/16, run 2 still 10/16 on
`escalate_low_trust`. In-pod, authenticated (`DBSIZE` 3 as the control): after the delete,
`agent_profile:<id>` and `agent_history:<id>` survive — the handler drops the registry row, the
freeze key and the trust override, not the behavioural history the score is recomputed from. So a
re-registered identity inherits its violations. That the history drives the score is inferred from
`AgentHistoryStore`/`AgentProfileStore` and the result, not control-tested.

Not obviously a bug: clearing history on delete would make deregister-and-return a way to launder an
agent's record, the same laundering the MCP plan refuses for `forget_server`. Decision owed — either
the docstring stops implying a fresh start, or an explicit admin "reset history" exists and is audited.


Re-running it against the same cluster scores lower on identical code: **13/16, then 10/16, then
12/16**. The middle run began with the agent already at trust 0.30 from the previous run's attacks, so
`escalate_low_trust` caught the two benign controls. Nothing in the script resets trust or warns that
the first run poisons the second, and the score is printed as if it were a property of the code.

The 12/16 is the honest clean-baseline number with the 7.11 checks corrected: reset with
`delete from agent_registry where namespace='agents'`, `FLUSHALL`, restart the API. Either the script
should do that itself or it should refuse to run twice without it.

### 7.13 DCO: the charter requires it on acceptance; 0 of 540 commits carry it

**Status:** verified 2026-10-27; decision owed. The CNCF charter (§11, `cncf/foundation/charter.md`) says
inbound code contributions "shall be … accompanied by a Developer Certificate of Origin sign-off".
`CONTRIBUTING.md` on this branch says "every commit in a pull request needs it", while nothing enforces
it (no DCO app; the only workflow hit for "dco" is the substring in "hardcoded") and **0 of 540 commits
on `main` have a `Signed-off-by`**. The sentence is a stated rule that neither CI nor history follows.
Options: start signing off now and add a check once `cncf-readiness` lands (commits before the section
are exempt, as it says), or word it as a request until then. Adding San's sign-off to commits on his
behalf is his certification to make, not the tooling's — not done.

### 7.14 PR #109's CI never ran; the approvals expired

**Status:** verified 2026-10-27. All three runs on `e8b3886` show `completed / failure` with **zero jobs**
(control: a `main` run has 4). They sat at `action_required` from 2026-08-24 and GitHub expired them on
2026-09-23. The red X is not a test result. Re-running needs the maintainer's account; the contributor's
last activity was 2026-09-01.

### 7.15 Sandbox eligibility: 2026-11-28, enforced by an automated pre-review

**Status:** verified 2026-10-27 from `cncf/sandbox`. Since 2026-08-19 a Copilot pre-review
(`scripts/sandbox-application-review-prompt.md`, `.github/workflows/sandbox-application-review.yml`)
labels an application `Postponed` on a "clear violation", including repo `created_at` under 6 months and a
MAINTAINERS link that 404s. `norviq-dev/norviq` was created 2026-05-28. On `main` today
`MAINTAINERS.md`, `ROADMAP.md`, `GOVERNANCE.md`, `ADOPTERS.md`, `NOTICE` and `CHANGELOG.md` do not exist —
they are on this branch only. The form also rejects "will add after acceptance".

## 8. Audit claims that did not reproduce

Recorded so the next reader of the CNCF audit knows which numbers to distrust.

* "PR #109 has been open and unanswered" — answered twice by the maintainer on 2026-09-01, approved,
  held on the release cut. The audit predates the reply.
* "The only open PR" — four were open.
* "Three shipped dependencies carry non-allowlisted licences" — one (`certifi`, MPL-2.0) in the
  58-distribution `norviq[spiffe]` closure; the other copyleft-flagged packages are dev-only.
* "Posture may vary by preset / namespace list / prod overlay" — one behaviour, `audit`, on every
  path constructible.
* "Nine dependencies carry NOTICE files" — five shipped; four are in the venv but not the images.
* "`git shortlog -sne` shows 7 identities" — the count is right; the command as written reads stdin
  when non-interactive and prints nothing. Use `-sne HEAD`.
* "0 reviews across 96 PRs" — 100 PRs; 96 is the closed count. The zero holds across all 100.
* "`README.md:244` is where Community goes" — stale citation; the section went before `## Security`
  at what was line 276.
* "`ruff` shows 5 errors on main" — exact for main; this branch had added three more before the gate
  existed, which is the gate's own argument.

