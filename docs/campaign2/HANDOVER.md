# Campaign 2 — handover

**Purpose:** a new session should be able to resume from this file alone. Keep it current — update
the "Work queue" and "Session log" sections every time something lands. Do not let it go stale.

Last updated: 2026-08-11 — PR #97 open. **verify (fresh) + verify (upgrade) PASS** — the
release-artifact gate is green. Three checks still red; see "CI state" below.

### CI state on PR #97 (2026-08-11)

**GREEN:** verify (fresh), verify (upgrade), fossa, python-sast, ts-sast, secrets, iac, deps-audit,
pytest, all five framework-compat.

**RED, and what each actually is:**

1. **`Security Analysis`** — the FOSSA **GitHub App**, which reads the project's **UI ignore list**,
   NOT `ACCEPTED_CVES` in fossa.yml. Needs CVE-2024-6825 marked *Ignored* in the FOSSA console.
   **San's action — a console change, not a repo one.** The `fossa` JOB is green.
2. **`vitest`** — one test of 1155 (`Dashboard.test.tsx`, the Monitor-mechanism one). Known harness
   debt with a 90s timeout and four ruled-out theories recorded in the test. Not a product defect.
3. **`L3 + L4`** — **RESOLVED: a SEEDER defect, not a product bug.** Settled by querying the RUNNING
   branch API rather than probing an imported `app` object:

   ```
   GET /api/v1/mcp/pins/observe -> 405   (route EXISTS; GET is the wrong method — it is a POST)
   GET /api/v1/mcp/servers      -> 200
   GET /api/v1/tools            -> 200
   ```

   The MCP surface is fully served. `scripts/kind-e2e/seed.py` is calling paths/methods that do not
   match, so its 404s are its own. Fix the seeder, not the API.

   **Three probing mistakes to avoid repeating** — all of mine, in order:
   (a) `git show "$t:helm/..."` in zsh applies the `:h` history modifier and mangles the ref (braces
       required); (b) importing `norviq.api.main` picked up a STALE COPY at `/private/tmp/norviq`
       until PYTHONPATH was pinned; (c) even from the right package, module-level `app` has only 7
       routes — the routers are registered in a factory, so a bare import can never answer "is this
       route served". **Ask the running API.**

   Also learned in passing, and worth keeping: the app REFUSES TO START on a weak
   `NRVQ_API_SECRET_KEY` or a default admin password when `NRVQ_REQUIRE_STRONG_SECRET` is on. Both
   fail-closed checks behaved correctly.

   ~~ROOT CAUSE UNRESOLVED~~ The seeder gets 404 on its declared-tools endpoints
   (`/api/v1/mcp/pins/observe` among them). My first hypothesis (main-built images) is WRONG: this job
   BUILDS the five images from source, so it runs branch code. My second probe suggested the mcp
   router was unmounted — that probe was ALSO INVALID, because `include_router` runs inside a factory
   function, so module-level `app.routes` is empty before startup. `main.py:299` does include it.
   **Start here:** run the app through `TestClient` (which triggers startup) and list the real routes,
   then compare against what `scripts/kind-e2e/seed.py` posts to. Do not trust a bare-import probe.

### Dependency work done here (both were MY regressions, both resolved)

* aiohttp/cryptography/pyopenssl bumped to close 4 CVEs — and note **pyproject alone was inert**:
  FOSSA resolves from `uv.lock`, pip from pyproject, and neither implies the other. Both must move.
* The relock pulled **litellm** into the graph and broke `fossa`. Bump attempted first per the project
  rule; litellm 1.96.1 ships **no cp311 wheel**, so uv refuses it. Accepted in BOTH `ACCEPTED_CVES`
  and the SECURITY.md table (they must stay in lockstep), on the same reachability grounds as the
  existing three: optional `norviq[crewai]` extra, in no shipped image.

### The release gate got STRICTER, and is validated

`verify_release.py` expected `execute_sql -> block`, which was the pre-allow-by-default contract; a
stock install now RECORDS (`audit` + `strict_default_block`). It asserts both halves: the stock
install records (rule_id checked, since `audit`+`default_allow` means nothing fired), and the call
BLOCKS once the control is promoted to deny. A 404 on the promote endpoint reports **[SKIP]** only
when a `GET` probe shows the whole router is absent — `GET` ok + `PUT` 404 still FAILS.
Validated live against the branch API on AKS: promote produced `block / strict_default_block`, then
was restored to monitor.
Remaining: C2-013, C2-016, Tier 4 triage, the three deliverables, and resuming the attack campaign.

---

## Where things stand

**Branch:** `integrate/mcp-and-builder` — **PUSHED 2026-08-10** (`76cc477..095be99`, 59 commits).
Version 0.2.0, **no tag at HEAD**. **Still NOT merged to main and NO version cut** — both need San.

### Pre-release gate, run before the push — 8/8 CLEAR

| gate | result |
|---|---|
| gitleaks over the push range (`@{u}..HEAD`) | **no leaks** in the 59 commits |
| pytest (ex integration/attacks) | 2754 passed |
| ruff | clean |
| `opa test --v0-compatible` | 29/29 |
| helm | 176 passed |
| version consistency | 0.2.0, 3 manifests + 17 docs agree |
| go build / vet / test | clean |
| ui vitest / tsc / eslint / build | 1155 passed, clean (see flake below) |

> **A SECRET LIVES ON THREE OTHER LOCAL BRANCHES — `backup/pre-public-cleanup-20260712`,
> `fix/catalog-hierarchy-batch2`, `release/pre-ga-consolidated`.** gitleaks over ALL refs flags
> `b465b13:scripts/test-campaign/seed_campaign.py:21` — a 54-char mixed-charset value on a variable
> named `SECRET`, no placeholder marker. It is **NOT an ancestor of HEAD**, so the push did not carry
> it and CI (which scans the PR range only) will not see it. **Pushing `release/pre-ga-consolidated`
> WOULD publish it.** The branch names suggest it was cleaned off the main line and left on backups.
> San's call — do not push those branches, and consider rotating the value regardless.

> **KNOWN DEBT — `Dashboard.test.tsx` "does NOT assert the Monitor mechanism…" needs a 90s per-test
> timeout in CI.** NOT root-caused, and not a product defect. It needs >30s on a 2-core GitHub runner
> while the whole 25-test file finishes in ~2s locally on 10 cores. Testing-library's failure dump
> CONTAINED the element it said was missing, so the render happens — just far too slowly there.
> **Four theories ruled out** (all written into the test itself): a sync/async race between the two
> feeds; state leaking between tests (`timeRange` is not persisted, and the file already clears
> `nrvq_namespace` + the api cache); worker starvation (the workflow ALREADY passes
> `--no-file-parallelism`, and its comment records that raising the async budget "moved the symptom
> rather than removing it"); and useApi's bounded empty-retry (only `/audit/stats` is configured for
> it, and this test mocks it non-empty). Next thing to try: split this one test into its own file, on
> the theory that 25 full Dashboard renders in one jsdom accumulate. The timeout does not weaken the
> assertion — the element still has to appear.

> **Earlier note, superseded by the above:** UI test flake, ~1 in 5. One vitest FILE failed on the first gate run and passed on the next
> four. The failing run never printed which file, and the jsdom `Not implemented: navigation` noise
> appears in GREEN runs too, so it is ambient rather than the cause. Not a regression (tsc, eslint and
> build were clean, and 4/5 runs are green) — but a flake that hides its own name will be painful to
> chase. Worth a `--retry` or a reporter change to surface the filename.

**Latest commits:**
- `2bfd0d0` C2-012: a homoglyph or zero-width name must not defeat a name-keyed control
- `4d309d3` C2-020: forewarn the 30-day sidecar credential cliff
- `6354bf3` C2-019: deliver sidecar credentials via Secret, not literal pod env
- `6dfd55d` C2-022: a destructive tool must not escape by being renamed
- `b3501c6` C2-023: the decoded arm must not match bare shell metacharacters
- `e741d6e` tier 1: monitor must never interrupt, on every plane that decides
- `236a1c3` campaign2: a throttle is not a detection (C2-021), + rate-abuse findings

**Gates last run at `2bfd0d0` — ALL GREEN:**
- `.venv/bin/python -m pytest tests --ignore=tests/integration --ignore=tests/attacks -q` → **2727 passed**
- `.venv/bin/python -m ruff check norviq tests` → clean
- `opa test --v0-compatible comprehensive.rego webhook/presets/strict.rego webhook/presets/strict_parity_test.rego` → **26/26**
  (NOTE: bare `opa test` FAILS on this repo — OPA 1.x defaults to Rego v1, these presets are v0.
   The `--v0-compatible` flag is not optional. Without it you get parse errors on every rule.)
- `cd ui && npx vitest run && npx tsc --noEmit && npx eslint src --max-warnings=0` → **1155 passed**, clean
- `.venv/bin/python -m pytest tests/helm -q` → **176 passed**
- `cd webhook && go test ./...` → ok  (NOTE: the go module is at `webhook/go.mod`, NOT the repo root —
  `go build` from the root fails with "cannot find main module")
- Pre-existing `gofmt` drift in `webhook/controller_retry_test.go` and
  `handler_injection_integrity_test.go` — NOT mine, left alone deliberately.

### Deployed state (2026-08-10)

**AKS is running the fixed build.** helm release `norviq` **revision 36, status `deployed`**, all
components at `50ebb70e4c07f54baaea286f8f42bbcd231ae0f4` except `ui`, which is intentionally left at
`ui-daa7532…` (the only UI change was a TypeScript type, erased at build time — no runtime delta).

Images are in the DEV package `ghcr.io/norviq-dev/norviq-engine-dev` via `scripts/push_dev_image.sh`.

> **TRAP — server-side-apply field-manager conflict.** `helm upgrade` FAILED twice with
> `conflict with "kubectl-set" using apps/v1: .spec.template.spec.containers[...].image`. An earlier
> out-of-band `kubectl set image` made `kubectl-set` the owner of `.image`, and helm will not take a
> field back from another manager. The webhook was never set that way, so it rolled cleanly — which
> is the only reason C2-019 could be verified while the others could not.
> **Fix that worked:** `kubectl set image` the deployments to the SAME tag helm wants (values then
> match, so SSA co-owns instead of conflicting), then re-run `helm upgrade`. For `ui`, the reverse —
> point helm at the tag that is actually running.
> **Rule: deploy through helm OR kubectl, not both.** This has now bitten twice.

### The four fixes, VERIFIED LIVE (2026-08-10, after the rollout)

| finding | before | after |
|---|---|---|
| **C2-023** base64 FP on prose | 2 of 80 tripped `deny_shell_execution` (n=18, n=58) | **0 of 80** |
| **C2-022** rename evasion | `get_delete_all_records` allowed 75/75 | **flagged** `strict_default_block` |
| **C2-022** camelCase | (not previously reachable) | **flagged** |
| **C2-012** Cyrillic-е | `allow / default_allow` | **flagged** |
| **C2-012** zero-width | `allow / default_allow` | **flagged** |
| benign `get_customer` / `run_query` | allow | **still allow** — no over-block |
| **C2-019** pod-spec credentials | token + cert + key were literal values | **all `secretKeyRef`**; 0 private keys in the spec |
| **C2-020** `/system-health` | n/a | serves the new path, `status=ok`, no band |

Note on the controls' shape: they ship on **monitor**, so a detection reads as
`audit / policy_audit_would_block:strict_default_block`, not `block`. What changed is that the rule
FIRES at all — pre-fix it did not fire on any of the four evasions.

**C2-020's band is confirmed reachable but NOT exercised:** a freshly rolled fleet has ~30 days of
credential left, so no band is the CORRECT result. The live run proves the endpoint serves the new
code without erroring; only the unit tests cover the populated case. Do not record it as more.

Verification script (re-runnable): `scratchpad/verify_live.py` — but it lives in a session-scoped
temp dir, so copy it somewhere durable before relying on it.

### Decision in force (2026-08-10)

**Stop attack testing; fix the backlog first.** The reasoning, so it is not re-litigated:

1. Four findings share ONE root cause (controls key on a caller-supplied *name* or a hand-written
   allowlist instead of the semantic fact the product already computes): C2-012, C2-013, C2-016,
   C2-022. More attack rounds keep re-finding it.
2. Two open bugs contaminate the measuring instrument — C2-023 puts a measured 2.5–4% false-positive
   rate on any prose payload, and C2-022 makes name-keyed controls evadable. Any FP or evasion number
   collected before those land is partly measuring the bug.
3. The fix batch is still reviewable. Another attack round makes it not, which for a security product
   is itself a risk.
4. The backlog reconciliation found two defects **in code already reported as fixed**, by reading
   rather than by attacking. Marginal value of verification now exceeds marginal value of more attacks.

Resume the attack campaign after tier 2 lands (see Work queue).

---

## Work queue

Tiers are ordered. Do not reorder without a reason recorded here.

### Tier 1 — safety invariants — ✅ DONE, commit `e741d6e`

All three were the same shape: a surface deciding on the literal decision string instead of on
whether the call proceeds. **2713 passed, ruff clean, UI tsc+eslint clean.**

- [x] **`_gate_answer`** (`norviq/mcp/firewall.py`) now uses `is_allowed()`. It was the one gate of
      four in that file comparing the string by hand. There were **no answer-plane tests at all**,
      which is how it survived; added four, and verified the two `audit` ones FAIL against the old
      line while the two enforcement ones pass either way.
- [x] **`_evaluate_step`** (`norviq/engine/attack_graph.py`) now maps `block|escalate → would_block`
      and `allow|audit → would_allow`. `audit` used to fall into the `no_policy` tail — the least
      alarming bucket — which under the all-monitor shipped default meant a control that fired on a
      dangerous call was reported as "nothing evaluated this", and silently disarmed the
      dangerous-tool risk check at `:416`. Verified the new tests fail against the old mapping.
- [x] **C2-002 completed** (`norviq/api/routers/compliance_view.py`): new `_own_policy_control_for`
      bucket, so a customer's own monitor-mode rule is reported. The existing filter was NOT loosened
      — the blast-radius number stays honest. The response now carries **`origin: "baseline"|"custom"`**
      (also added to `ComplianceControl` in `ui/src/api/client.ts`, optional for back-compat).
- [x] **Sweep done.** Four hand-comparisons to `"allow"` exist in `norviq/`. Two were bugs (above).
      The other two are DELIBERATE — do not "fix" them:
      - `evaluator.py:788` `_maybe_rate_limit` — must gate on a genuine resource grant; the docstring
        says never to flip block/escalate/audit into a throttle.
      - `evaluator.py:1009` trust override — deliberately does not escalate a call a control already
        flagged, which would turn a monitor-mode observation into an interruption.

**Follow-up worth doing (not blocking):** `BaselineControls.tsx:104` still derives custom rows via
`!baseline.has(c.control_id)`. That is correct and still works, but it could now read `origin`
directly.

### Tier 2 — the instrument (must land before any further attack testing)

- [x] **C2-023 — base64 false-positive root cause — ✅ DONE, commit `b3501c6`.**
      The decoded arm of `shell_injection_detected` now uses `decoded_shell_patterns` (multi-byte
      indicators only) instead of the raw list containing `|`, backtick and `$(`.
      **Fixed in BOTH copies** — `comprehensive.rego` had the identical construct and lives at the
      REPO ROOT, so a `webhook/presets/*.rego` sweep misses it (my first one did). The parity test
      only compares DECISIONS, so a divergence that happens not to flip a decision on the fixtures
      would pass. Five rego tests pin both directions; verified the two prose tests FAIL against the
      old list. `opa test --v0-compatible` 17/17.
      > **STILL OWED — re-measure the FP baseline LIVE.** The AKS cluster runs the pre-fix image, so
      > the 2.5%-on-prose figure has not been re-taken. Needs a rebuild+deploy → **ask San first**.
      > Expected: the base64 FP curve collapses to ~0 and `deny_shell_execution` stops firing on
      > prose. Repro: 80 `/evaluate` calls with `{"note": "benign call N"}`; previously tripped at
      > n=18 and n=58 (see the `/evaluate` request shape below — `agent_identity.namespace` is
      > required or you get 422, not a decision).
- [x] **C2-022 — name-keyed controls — ✅ DONE, commit `6dfd55d`.**
      Rate limiter: the name still gates but must AGREE with `classify_tool`, called with **no params**
      (passing them would let an unknown name + `{"query": "select 1"}` classify as `read` and earn the
      exemption — a caller-controlled payload is worse than a caller-controlled name).
      Presets: destructive verbs matched as whole TOKENS anywhere in the name, in BOTH strict.rego and
      comprehensive.rego. `getDeleteAllRecords` is caught too, since `name_split_map` splits camelCase.

      Re-measured against the compiled baseline: `delete_all_records`, `get_delete_all_records`,
      `getDeleteAllRecords`, `search_and_destroy` → all **block**; `run_query`, `get_customer` → allow;
      `get_customer` still rate-exempt, `get_delete_all_records` no longer is.

      **Two traps hit while doing this — recorded so nobody re-walks them:**
      1. Keying the BLOCK on `derived.verb` is WRONG and I tried it first. `classify_tool` takes the
         worst verb over all name tokens and over-classifies: `run_query` and `execute_sql` both come
         back `delete`, so a verb-keyed block refuses ordinary read tools.
         `tests/engine/test_capability.py::test_reads_are_not_swept_up_by_the_wider_lexicon` catches it.
         **Over-classification is safe where it NARROWS, unsafe where it BLOCKS.**
      2. A helper `x = {...}` defined inside the `>>> CONTROLS-BEGIN/END` markers breaks the baseline
         compiler outright (`ValueError: unparsable line in CONTROLS region`) and took 38 tests down.
         That region is rule HEADS only. Put helpers outside the markers.

      > **SCOPE CORRECTION — this did NOT close C2-012, contrary to what this file previously said.**
      > Verified against the compiled baseline: `dеlete_records` (Cyrillic е) and a zero-width-space
      > variant both still return `allow / default_allow`. Uppercase IS covered (`lower()`).
      > C2-012 needs the tool **NAME** folded to an ASCII confusable skeleton — the engine already does
      > exactly that for `tool_params` ("Confusable skeleton (homoglyph/zero-width)" note in
      > strict.rego) but not for the name. **That is the fix shape; C2-012 stays OPEN.**
      > C2-013 (destination-keyed) and C2-016 (supply-chain) are also untouched by this — both still
      > open, and neither was ever really the same fix, only the same root cause.

### Tier 2b — still open, same root cause as C2-022

- [x] **C2-012 — homoglyph / zero-width tool name — ✅ DONE, commit `2bfd0d0`.**
      The fix was small because the fact already existed and nobody read it: the engine publishes
      `input.tool_name_normalized = skeleton(name)` at `evaluator.py:1107`, consumed only by the
      intent compiler's generated rego — the shipped presets never looked at it. Both presets now
      tokenise the normalized name alongside the raw one. Additive; `object.get` falls back to the raw
      name for an engine predating the fact. Verified end to end against the compiled all-deny
      baseline: Cyrillic-е, zero-width-space and camelCase renames all block; `get_customer` and
      `run_query` still allow. Four rego tests; the two homoglyph ones fail without the arm.

- [ ] **C2-013 — no destination-keyed control for tools outside a hand-written allowlist.** The
      campaign's headline design finding, proven three times on three surfaces.
- [ ] **C2-016 — supply-chain phrasing in a query param does not trip `llm05_supply_chain`** (it is
      tool-name keyed).

### Tier 3 — high-severity infrastructure

- [x] **C2-019 — credentials out of the pod spec — ✅ DONE, commit `6354bf3`.**
      New `webhook/sidecar_secret.go`: the injector writes a Secret and emits `valueFrom.secretKeyRef`
      for `NRVQ_API_TOKEN` / `NRVQ_CLIENT_CERT_PEM` / `NRVQ_CLIENT_KEY_PEM`. `NRVQ_API_CA_PEM` stays
      literal (a CA cert is public by construction). Sidecar unchanged — same env vars either way.
      Namespaced Role+RoleBinding per configured namespace (`webhook-secret-rbac.yaml`),
      `get/create/update` only — deliberately NOT a ClusterRole, reasoning in the file.
      Values: `webhook.injection.credentialSecret.{enabled,required,namespaces}`.
      Six tests; the three behavioural ones verified to FAIL when the transform is reverted.

      **Design points that must not be casually "simplified":**
      - **Fail SOFT.** `failurePolicy: Fail` means this webhook gates ALL pod creation in labelled
        namespaces. A Secret-write failure falls back to literal env + `NRVQ-WHK-4049` at ERROR.
        `NRVQ_SIDECAR_SECRET_REQUIRED=true` inverts it. 3s timeout on the write.
      - **Dry-run must not write** but must preview the same shape. `req.DryRun` used to only log;
        that was fine until injection had a side effect. `PatchOptions{DryRun}` is threaded through.
      - **Rotation survives** because the Secret is rewritten every admission and its name is
        deterministic (hash suffix guards collisions). Created-if-absent would have broken rotation.

      > **✅ VERIFIED LIVE on AKS, 2026-08-10** (webhook `webhook-50ebb70e`, pod
      > `analytics/finance-agent-8458567cbf-287q6`):
      > - `NRVQ_API_TOKEN`, `NRVQ_CLIENT_CERT_PEM`, `NRVQ_CLIENT_KEY_PEM` → all `secretKeyRef` ->
      >   `norviq-sidecar-finance-agent`. `NRVQ_API_CA_PEM` correctly still a literal.
      > - Secret created by the webhook with exactly those 3 keys + a `norviq.io/minted-at` annotation.
      > - **`grep -c "BEGIN RSA PRIVATE KEY"` on the pod spec = 0** (it was 1 that morning — I printed
      >   a full key out of that same spec).
      > - Credential WORKS, not just present: sidecar logged `remote_evaluator.mtls_enabled` then
      >   `remote_evaluator.ready`, 0 restarts. The cert+key were read from the Secret and built a
      >   live TLS context.
      > - `view` ClusterRole on this cluster: pods=True, secrets=False -> the exposure is closed.
      > - RBAC Roles present in `analytics`, `chatbot-prod`, `default` with `[get create update]`.

- [ ] **Revocation is still missing (part of C2-019, NOT fixed).** `norviq/api/session_revocation.py`
      exists but its only caller is `auth_login.py:174` (interactive logout). No admin revoke endpoint,
      no CRL for the client certs. So a leaked sidecar credential stays valid for its full 30 days and
      the only lever is rotating `NRVQ_API_SECRET`, which invalidates every token at once.

- [x] **C2-020 — day-30 cliff forewarned — ✅ DONE, commit `4d309d3`.**
      New `norviq/api/sidecar_expiry.py`; `/system-health` gains a `warning` band. Observed where the
      API already decodes the token (`auth._authenticate`), AFTER the revocation check.
      **Behaviour that must be preserved:** SERVICE tokens only; nothing written until inside the
      7-day window (zero writes on the hot path in steady state); `nx=True` bounds it to one key per
      (namespace, workload); TTL is the credential's own remaining lifetime; every function is
      best-effort — `observe()` runs in the AUTH path and must never fail a login, `expiring_soon()`
      degrades to `[]` so /system-health cannot 500 over its least important band. The band is
      `warning` and appended AFTER live incidents so "will break Tuesday" never outranks "is broken".
      UI needed no component change (the banner already renders non-critical); `SystemIssue.window_minutes`
      is now nullable + an optional `expiring` list.
      **The expiry behaviour itself is CORRECT and must not be "fixed":** at expiry the API answers
      401, a 4xx overrides `sdk_fallback_mode`, and the sidecar fails CLOSED. Auto-rolling pods was
      considered and NOT done — evicting customer workloads from a controller is a much riskier change.

### Tier 4 — triage the reconciled backlog, then fix

A 13-agent reconciliation of `docs/campaign/BUG-TRACKER.md` (28 rows) + open C2 items ran on
2026-08-10. Raw result: `total 35, fixed 2, open 28, partial 5, overturned 5`.

**DO NOT treat those counts as a measurement.** The agents were instructed to default to OPEN when
uncertain and the refuters to default to "not upheld", so it is a deliberately conservative floor.
Two overturns were independently verified and promoted to Tier 1 above; the rest needs a human-quality
triage pass before it becomes a work list.

Full per-item output with file:line evidence:
`/private/tmp/claude-501/-Users-san-Documents-Development-norviq/967b9f75-7055-4cd9-943f-e62e2fd530fb/tasks/w15v6f76h.output`
Per-agent journal:
`~/.claude/projects/-Users-san-Documents-Development-norviq/967b9f75-7055-4cd9-943f-e62e2fd530fb/subagents/workflows/wf_59a6697e-dfc/journal.jsonl`

> **`docs/campaign/BUG-TRACKER.md` is STALE** — it lists 24 OPEN including many fixed during Campaign 2.
> Reconcile it as part of this tier so the next session is not misled the way this one nearly was.

### Also outstanding

- [ ] Three plan deliverables never written: `WALKTHROUGH.md`, `FRAMEWORK-MATRIX.md`, `UNMEASURED.md`.
      Write them while the evidence is fresh — much of it currently lives only in session transcripts.
- [ ] Raise declared dependency floors to the GA majors actually tested (`langchain-core>=0.2`
      currently permits two majors below what is exercised).

---

## SECURITY — outstanding, San's action

- **Postgres/Redis rotation is NOT a release blocker.** Corrected 2026-08-10 after reading
  `helm/norviq/templates/secret.yaml`: with `postgresql.password`/`redis.password` empty (the default)
  a FRESH install gets `randAlphaNum 32`. The literal `norviq-pg-password` is reachable only on the
  MIGRATION path (an existing secret that predates the `NRVQ_PG_PASSWORD` key), never on install. So
  the values two Campaign 1 subagents exposed belong to THIS dev cluster only — nothing ships with
  them and no customer inherits them. Rotate as hygiene whenever convenient; it gates nothing.

- [x] **RESOLVED, not a finding — the pg/redis self-heal asymmetry.** Traced 2026-08-10: the
  legacy-literal branch fires only when an existing secret LACKS `NRVQ_PG_PASSWORD`, and **every
  released tag v0.1.0–v0.1.10 already ships that key** (counted per tag). So no released chart can
  produce a secret that reaches it — dead code for any real install. The asymmetry with
  `api.secretKey` (which does self-heal off a weak value) is real but unreachable. Closed.
  > zsh trap worth knowing: `git show "$t:helm/..."` applies the `:h` history modifier and silently
  > mangles the ref, so the first per-tag count came back 0 for EVERY tag including HEAD. Use
  > `"${t}:helm/..."`. `scripts/push_dev_image.sh` documents the same trap — "braces are load-bearing".
- One sidecar mTLS **client key** (namespace `analytics`, pod `finance-agent-…-xd6k5`, expires
  2026-09-09) was printed in full in a session transcript on 2026-08-10 while reading a pod spec.
  Low impact — mTLS is defence-in-depth alongside the JWT and authenticates nothing on its own — and
  the pod has since been replaced, which rotated it. No action needed; recorded for completeness.

---

## Environment

- **Local kind is STOPPED** (`docker stop norviq-local-control-plane`, 2026-08-10) — everything is on
  AKS now. Restart with `docker start norviq-local-control-plane`; the cluster and its seeded state
  are intact, NOT deleted. `kubectl config current-context` is unset, so ALWAYS pass `--context norviq`.
- **Cluster:** AKS, kubectl context `norviq`. Namespaces with `norviq-injection=enabled`:
  `analytics`, `chatbot-prod`, `default`.
- **Port-forwards** (re-establish if dropped):
  `kubectl -n norviq port-forward svc/norviq-api 8080:8080` and `svc/norviq-ui 3400:80`.
- **Admin token:** `/tmp/nrvq-signin-token.txt`. Re-mint:
  `kubectl -n norviq exec <api-pod> -c api -- python -m norviq.api.token_mint --ttl 7200`.
  Mirror it into `examples/chatbot/.env` (`NRVQ_API_TOKEN`) — a stale one there produced four fake
  "block" results earlier in this campaign.
- **Console auth:** seed `localStorage.nrvq_token` rather than typing into the login form.
- **Secrets:** `GROQ_API_KEY` in `.secrets/groq.env` (gitignored, chmod 600). `examples/chatbot/.env`
  holds a real Groq key + NRVQ token; gitignored (`.gitignore:26`) and dockerignored.
- **Test images:** use the `norviq-engine-dev` package. Ask before any build/push/deploy — San often
  has uncommitted changes in flight; a clean tree is not proof he is done.

## `/evaluate` request shape (cost an hour to rediscover)

`agent_identity` requires `namespace`; without it the API returns **422**, not a decision:

```json
{"agent_id":"x","agent_class":"c","namespace":"analytics","tool_name":"send_message",
 "tool_params":{},"framework":"campaign2",
 "agent_identity":{"spiffe_id":"spiffe://norviq/ns/analytics/sa/x","namespace":"analytics",
                   "agent_class":"c","workload":"x"}}
```

## Standing rules learned the hard way

- **A block with no audit row is not a defence** — it is a degraded proxy or a schema refusal.
  **A block with an empty `rule_id` is a gate refusal**, not a policy decision. Check both before
  scoring anything as caught.
- **A model refusal is not an enforcement win.** Groq refuses some payloads before Norviq sees them.
  Every adversarial prompt needs a paired direct-MCP call that bypasses the model.
- **Measurement defects stop the line; coverage gaps batch.** Applied to BUG-011, BUG-026, SEED-05,
  C2-021.
- **The rate limiter contaminates unpaced sweeps** — 60 non-read calls/60s per SPIFFE id, shared
  across replicas. `get_`/`list_`/`search_` exempt. Pace every sweep.
- Never claim a policy works because it compiled and dry-ran `valid`. **Measure it.** A dry-run that
  replayed 0 calls proves nothing; a Visual Builder policy once compiled exactly inverted.
- Campaign identity prefix is `r2-`. Campaign 1's `cmp-*` rows are NOT hidden by `synthetic.py` and
  pollute KPIs. Nothing is deleted.

---

## Session log

Append one line per landed change. Newest last.

- 2026-08-10 `e1030dd` — Phase 6 read-out: filed C2-019 (creds as literal pod env), C2-020 (30-day
  hard stop), resolved SEED-06 (caBundle scenario is handled by design; rotation forward proven by
  live pod replacement with fingerprints).
- 2026-08-10 `236a1c3` — C2-021 FIXED (throttle scored as a detection on three surfaces; added
  `non_policy_rule_for`). Filed C2-022, C2-023. Rate-abuse family measured live.
- 2026-08-10 — backlog reconciliation run; two overturns verified and promoted to Tier 1. Decision
  taken: stop attack testing, fix first.
- 2026-08-10 `e741d6e` — **Tier 1 DONE.** `_gate_answer` uses `is_allowed()`; attack-graph step
  verdict maps on whether the call proceeds; `_own_policy_control_for` bucket + `origin` field.
  Each fix verified to fail its own test when reverted. 2713 passed, all gates clean.
- 2026-08-10 `b3501c6` — **C2-023 DONE** (Tier 2, first half). Decoded arm narrowed to multi-byte
  indicators, in BOTH strict.rego and comprehensive.rego. One existing test used the now-fixed shell
  misfire as its vehicle for "monitor records a false positive rather than dropping it"; retargeted
  to the date→SSN misfire (BUG-005, still open, 100% deterministic) rather than weakened.
- 2026-08-10 `6dfd55d` — **C2-022 DONE** (Tier 2 complete). Rename bypass closed on both halves.
  Two traps hit and recorded in the work-queue entry: a verb-keyed BLOCK over-blocks reads because
  the classifier takes the worst verb over all tokens; and a helper definition inside the
  CONTROLS markers breaks the baseline compiler. Also **corrected an earlier claim in this file** —
  C2-012 is NOT closed by this fix; homoglyph and zero-width names still evade.
- 2026-08-10 `6354bf3` — **C2-019 DONE.** Credentials moved to a Secret; namespaced RBAC; fail-soft;
  dry-run side-effect free; rotation preserved. A `fail`-on-missing-namespaces guard was reverted
  after 11 chart tests showed that configuration is mainstream — reasoning kept in the template.
- 2026-08-10 `4d309d3` — **C2-020 DONE.** Expiry forewarning band on /system-health.
- 2026-08-10 `2bfd0d0` — **C2-012 DONE.** Presets now read `input.tool_name_normalized`, a fact the
  engine had been publishing all along.
- 2026-08-10 — **BUILT, DEPLOYED AND VERIFIED LIVE.** api/engine/webhook at `50ebb70e`, helm rev 36
  `deployed`. All four fixes confirmed on the cluster (table above). Local kind stopped.
- 2026-08-10 `42229d3` — **ROUND 2 run against the deployed fixes, to break them.** 19 of 22
  spellings of `delete_records` caught; `delete records` (SPACE) evaded -> **C2-024, fixed** by
  widening `name_split_map`. Two others evade by design and are recorded not fixed: `d3lete_records`
  (skeleton folds letters, not digits) and `remove_records` (`remove` not in the verb list).
  Collateral clean 9/10 — the one flag is BUG-005, still open.
  Reusable probes now live in `scripts/campaign2_round2.py` and `scripts/campaign2_verify_live.py`.

  > **C2-024 IS NOT LIVE.** The presets ship inside the api/engine images, so it needs the next
  > build+deploy. Everything else in the queue below is code-only until then.

- 2026-08-10 — **C2-013 DESIGNED, NOT BUILT** -> `docs/campaign2/C2-013-DESIGN.md`. Stopped
  deliberately at a decision that is not mine: **there is no migration tooling** (`create_all` creates
  missing TABLES, never adds a column to an existing one), so a new `NamespaceSettings` column would
  work on a fresh DB and silently not exist on the live Postgres. Three options costed in the doc;
  recommendation is to carry the allowlist as POLICY data rather than a settings column for now, and
  introduce migration tooling before GA.
  Also measured and recorded there: the cheap config-free version (`data_classes` + egress sink)
  **provably does not work** — `data_classes` returns `[]` for a customer name and address, because
  its `pii` means SSN-shaped only. Building it would look like a fix and miss the exact payload.

- 2026-08-10 — **C2-013 storage question ANSWERED and the compiler BUILT**:
  `norviq/api/egress_allowlist.py` + 22 tests, all through real OPA (`--v0-compatible` — bare
  `opa eval` fails on this repo's v0 rego). The allowlist is compiled INTO a policy module and
  round-trips via an embedded `# nrvq-egress-allowlist/v1:` header, the same trick the Visual Builder
  uses — **so no schema change and no manual DDL against the live Postgres.**
  Empty allowlist = DISCOVERY (flags every destination, always `audit`, never `block`), because
  "empty = inert" is the same false assurance C2-001 is about.

- 2026-08-10 — **C2-013 PRECEDENCE DONE.** `__egress__` is now collected as a tighten-only overlay in
  BOTH `_collect_candidates` and `_collect_candidates_union`. The appender was PARAMETERISED by scope
  rather than copied — this codebase has shipped a fix into one of two copies repeatedly (shell
  pattern lists, the MCP allow-check, the preset pair). It lands in the HARD partition for free:
  `_resolve_overlay` partitions the pack family by suffix and treats everything else as hard.
  5 new precedence tests; verified 3 FAIL if the scope is collected without `overlay: True`.
  One brittle pre-existing test (`test_the_controls_scope_is_collected_as_a_tighten_only_floor`)
  regexed the SOURCE TEXT and broke on the refactor; rewritten to assert the PROPERTY instead, which
  is stronger and survives future refactors — not weakened, and the reason is in its docstring.

  **NEXT for C2-013: only the endpoint + console remain (see the design doc's "What is left").**
- 2026-08-10 — **`__egress__` RESERVED from the generic policy API** (`policies.py`, all three lists).
  It was in none of them, so a direct create would bypass the compiler while still being collected as
  a HARD tighten-only overlay, and a direct delete could remove it. Same reasoning already documented
  for `__controls__`, plus one more: the console's allowlist view reads the embedded header, so a
  hand-written module at that scope could not be described at all.
- 2026-08-10 — **CUT READINESS EVALUATED -> `docs/campaign2/RELEASE-READINESS.md`.**
  **Exactly ONE blocker: nothing has been through CI.** Everything else ships as a documented known
  issue. Correction recorded there: "C2-024/egress not live on AKS" was NEVER a cut blocker —
  `release.yml` builds images FROM THE TAG, so every committed fix ships automatically; absence from
  the dev cluster only constrains further testing. Round 2's real lesson is
  that C2-012/C2-022/C2-024 are ENUMERATION, not generalisation: each fixed the evasions in front of
  it and the next round found one more separator. Keying on a semantic fact instead of the spelling of
  a caller-supplied string is the only thing that ends that loop. Then C2-016, the Tier 4 triage, and
  the three missing deliverables.

---

## 2026-08-13 — Independent v0.2.0 evaluation (`~/norviq-v020-eval/backlog.md`)

Working the eval's fix-ready backlog. Ground rule from the brief and worth keeping: **the cards are
reported issues, not conclusions.** Confirm the mechanism against current source, run the Repro, fix,
run the Verify — and where a check disagrees with the card, trust the check and say so.

Branched from `main` @ `22e9da6` (= tag `v0.2.0`), which is exactly what the eval targeted. One
focused branch per finding; **nothing pushed** (standing rule: ask before pushing).

### Done

- **`fix/f-032-content-normalizer`** (`ae86def`) — the umbrella. New `norviq/engine/content_norm.py`:
  one normalize+decode stage in front of every content detector. Repro'd first with
  `scripts/f032_battery.py` — **68% evasion (15/22), 0 false positives** — then **4% (1/22), still 0
  false positives**. The eval said 66%; same shape, and its per-family split reproduced.
  - *Disagreement with the card, recorded:* the fullwidth SSN it lists as evading was **caught** in my
    fixture, because Python's `\d` matches Unicode digits. My fixture used an ASCII hyphen, so it was a
    weaker test than theirs, not a refutation of it.
  - Three limits are deliberate and each is pinned by a test so removing one is a decision:
    separators are canonicalised and **never deleted** on the general path (strip them from any nine
    digits and every order number becomes an SSN); **bare nine digits stays uncaught**; PCI is
    Luhn-gated. `desep()` exists for credential shapes only.
  - `normalize()` does **not** case-fold — `AKIA[0-9A-Z]{16}` is case-sensitive and folding is how an
    earlier attempt lost the key it was looking for.

- **`fix/f-046-egress-and-confusable-verb`** (`1f71b20`) — three things.
  1. *Egress from params, not the name.* Measured: same AWS key, same attacker URL, `fetch_data`
     blocked (only because `fetch_` is in the prefix list) while `lookup_customer`,
     `retrieve_records`, `view_report`, `describe_asset` all **allowed**. New `value_pattern_sink`
     reads `derived.destinations`.
     **Deliberately NOT folded into `egress_verb_tool`** — that would widen the KEY-NAME gate, and
     `sensitive_keys` holds the bare key `token`, which is the over-block that once turned 39 of 53
     vendor tools into sinks. Paired only with the VALUE-pattern gates. A pagination cursor beside a
     URL still allows, and a test says so.
     **The card's own fix (c) was rejected**: "always run the params egress recovery" would make
     `fetch_data` report `send` and render its `read` *unsayable* — the failure `source_registry.py`
     documents twice.
  2. *Verb from the confusable skeleton.* `dеlete_records` (Cyrillic е) classified UNKNOWN.
     **Order is load-bearing**: `skeleton()` casefolds, `_CAMEL_RE` needs uppercase, so folding before
     splitting silently dropped the verb from `aws_s3_DeleteObject`, `chat.postMessage`,
     `SES:SendRawEmail`, `getMail`, `sendEmail`. Caught by a 36-name vendor corpus, now a test.
     Leetspeak (`de1ete_records`) left uncaught on purpose — folding digits rewrites `s3_get_object`
     and `md5_hash`, which are names, not attacks. Pinned.
  3. *The baseline could not grow.* `strict.rego` sat at **exactly 500 of the validator's 500-line
     cap**, so a three-line security rule was unshippable — and the symptom is not a clean rejection:
     the controller retries every 60s while the DB keeps enforcing the **old** policy. Raised to 650
     and added `test_shipped_rego_keeps_line_headroom` mirroring the regex-op guard.

- **`fix/f-012-preset-reads-engine-classes`** (`3fa4992`) — the presets read `derived.data_classes`
  rather than re-deriving detection in Rego. base64 / hex / lowercase / spaced AKIA, spaced + dotted
  SSN, spaced PAN and grouped Amex all went from **allow to block**. Costs **no regex ops**, which
  mattered at 24 of 25. Rego detectors kept alongside as the floor for an older engine; `object.get`
  defaults make that path degrade rather than error.

**F-045 needs no separate change** — verified closed by F-032, including `access_token` /
`client_secret` / `refresh_token` / `aws_secret_access_key` / `api-key` / `pwd` / `bearer_token`,
Diners-14 and Discover-16, with `shipping` / `pinned` / `tokenizer` staying clean.
F-045's item (4) — a high-entropy heuristic for `_SECRET_VALUE_RE` — was **not** done: the key-name
path already catches every repro in the card, and a generic entropy test is exactly what destroys the
0-FP property (UUIDs, SHA digests and JWT-shaped ids are all high entropy).

### Found while verifying, not yet fixed

- **BUG-005 is now attributable.** The benign ISO date `2026-08-11` still blocks as `pii_detection`
  while the engine reports **no** data class for it. So the false positive is the **Rego** SSN regex,
  not the engine's detector — the duplicate copy is both less sensitive *and* less precise than the
  thing it duplicates. Deleting it is a **loosening**, so it needs its own change and its own
  evidence; do not fold it into a recall fix.

### Next, in order

F-001 (v0.2.0 never published — Trivy failed on `oras.land/oras-go/v2` CVE-2026-50163), F-003
(`agent_class` not attested for namespace-scoped keys), F-025 (`chain_depth_limit` live on 1 of 5
adapters), then §4's secure-by-default items, then MEDIUM.
**Skip** F-026 (needs-live). **Do not touch** F-011, F-029, F-015, F-017, F-019/21/22, F-035, F-036.

### Gates as of this entry

`2844 passed`, `ruff` clean, `opa test --v0-compatible` **45/45**, f032 battery **1/22 evaded, 0 FP**.

### 2026-08-13, continued — F-025, F-003, F-001

- **`fix/f-025-depth-scope-all-adapters`** (`aa8e43e`) — `depth_scope()` was held by LangChain only, so
  `_CALL_DEPTH` never left 0 on CrewAI / AutoGen / LangGraph / Semantic Kernel and `chain_depth_limit`
  could not fire at any depth — while the Compliance view counted it as enforced. Each adapter now
  holds it around its own tool body (wrapped `_run`/`run`; the node invocation for LangGraph;
  `next(context)` for SK).
  Tests assert the depth seen **inside the tool body**, not the presence of the string `depth_scope`,
  because a source scan cannot tell a scope held around the *interceptor* from one held around the
  *tool*. **Verified by reverting the four adapters: those four fail, LangChain passes.**
  A product-honesty test then caught the stale shipped caveat ("Only LangChain reports call depth
  today") — it exists because that copy shipped self-contradictory once before, and it is written to
  fail exactly when someone adds depth without updating the prose. The remaining honest caveat is not
  about frameworks: the SDK measurement is **authoritative** (it wraps execution), while a sidecar or
  MCP proxy can only forward a **caller-reported** depth.

- **`fix/f-003-attest-agent-class`** (`45c1871`) — `scoped_identity` skips a claim whose credential
  value is empty, so a namespace-scoped key let the request BODY choose `agent_class` — and that
  selects the Rego program. The profitable move was not impersonating a real class but naming one with
  **no** policy, which falls to `no_policy_decision='allow'`.
  `auth_require_bound_agent_identity` now defaults **True** (the ratchet already existed and was only
  ever waiting on migration cost), and issuing a `service` key without an `agent_class` is refused at
  **creation** (422) rather than at evaluation, because the issuing admin is the only person who knows
  which class it is for.
  13 tests in `test_evaluate_scope.py` were written against the old default — one is literally
  `test_the_existing_hot_path_is_unchanged_when_nothing_is_attestable`. Not deleted: `False` stays a
  supported downgrade path, so an autouse fixture states that precondition explicitly and
  `test_the_shipped_default_is_the_strict_one` guards the default (verified: reverting `config.py`
  fails exactly that one test).

- **F-001 — the card's fix is wrong for this repo, and the corrected one is staged but NOT committed.**
  `oras.land/oras-go/v2` is **not** a Norviq dependency: it is absent from `webhook/go.mod` and
  `go.sum`. It reaches the engine and api images inside the **pinned OPA static binary** — confirmed
  directly with `go version -m $(which opa)`: `dep oras.land/oras-go/v2 v2.6.1`, the vulnerable
  version exactly. So `go mod tidy` would change nothing; the fix is an **OPA bump**.
  OPA **v1.19.0** ships `oras-go v2.6.2` (v1.18.2 still ships 2.6.1 — the patch line does not fix it).
  Verified before editing anything: the full Python suite (**2857 passed**) and `opa test
  --v0-compatible` (**45/45**) both run clean against a real 1.19.0 binary, and regenerating
  `opa-capabilities.json` is **purely additive** — nothing removed, one new builtin
  (`strings.split_n`). The `policies/templates/` "multiple default rules" error is **pre-existing** and
  identical on 1.18.0 (those templates all declare `package norviq.custom` and are alternatives, not
  meant to load together).
  Staged: `Dockerfile.api`, `Dockerfile.engine` (URL + both SHA256 digests, recomputed from the real
  downloads), `helm/norviq/values.yaml`, four workflows, `scripts/mcp-demo.Dockerfile`,
  `scripts/kind-e2e/chaos.py`, `scripts/gen-opa-capabilities.py`, and both regenerated capability
  files. **Still to do: `.trivyignore.yaml` names `opa 1.18.0-static` in three entries** — those
  suppressions must be re-checked against 1.19.0 before this is committed, or a stale ignore could
  silence a finding that no longer applies to the shipped binary.

> **BLOCKER, environmental: the host disk is full** (`/` at 98%, ~330 MB free; the Data volume at
> 100%). `docker system df` hangs and the full pytest run times out from thrashing — targeted runs
> still pass in under a second, so this is the machine, not the changes. Freeing real space means
> removing Docker images (which include the kind cluster and the locally loaded `norviq/norviq-engine`
> images), so that is San's call, not something to do unilaterally.

### Gates as of this entry

`opa test --v0-compatible` **45/45** (on 1.18.0 and 1.19.0), targeted suites green.
Last clean FULL run: **2857 passed** — taken *before* the OPA-bump file edits, which are therefore the
one thing in this handover not yet covered by a full-suite pass.

### F-001 — resolved, and it cleared more than expected (`f6d4342`, branch `fix/f-001-bump-opa-1.19.0`)

The backlog's fix does not apply to this repo, and following it would have failed the release a second
time. `oras.land/oras-go/v2` is **not** a Norviq dependency — absent from `webhook/go.mod` and
`go.sum`. It reaches the images inside the **pinned OPA static binary**. Confirmed, not inferred:

```
$ go version -m $(which opa)
  dep  oras.land/oras-go/v2  v2.6.1        <- exactly the vulnerable version
```

`go mod tidy` would have changed nothing. **OPA 1.18.2 is not the fix either** — the patch line still
ships oras-go 2.6.1. **1.19.0** ships 2.6.2.

Verified against a real 1.19.0 binary **before** editing anything, because OPA is the enforcement
engine and this repo's Rego is v0: full Python suite **2857 passed**, `opa test --v0-compatible`
**45/45**, and the regenerated `opa-capabilities.json` is **purely additive** (nothing removed, one
new builtin `strings.split_n`). That regeneration is not optional — the pin is coupled to that file
through `_check_capabilities`, and moving one without the other is how the sidecar starts refusing
builtins the engine expects.

Nine pin sites moved together so CI tests what ships: both Dockerfiles (URL **and** both SHA256
digests, recomputed from the real downloads — the build verifies them and a stale digest fails
closed), `helm/norviq/values.yaml`, four workflows, `scripts/mcp-demo.Dockerfile`, and a comment in
`scripts/kind-e2e/chaos.py`.

**The whole `.trivyignore.yaml` baseline went with it.** All three accepted HIGH findings were in this
same third-party binary, each with an explicit exit condition; 1.19.0 met all three at once —
go1.26.5 (was 1.26.4), grpc-go v1.82.1 (was v1.81.1), x/text v0.40.0 (was v0.38.0). The webhook half
of the first was already covered (`golang:1.26-alpine` resolves ≥1.26.5; `webhook/go.mod` pins x/text
v0.39.0). The list is now empty and the three rows are removed from
`docs/engineering/security-baseline.md`, per that file's own rule.
Removed rather than version-bumped **on purpose**: if a finding survives, the fail-closed gate goes
red and names it, whereas a stale entry silently disarms the gate for a CVE the binary no longer has.

**Not verified here: Trivy itself.** Docker is unresponsive on this machine, so CI's scanner run is
the confirming check. Every dependency-version claim above comes from the released artifacts
(`go version -m`, the published `go.mod`), not from the scanner.

### Environment note for whoever picks this up

The host disk filled mid-session (`/` hit 100%). I reclaimed ~2 GB from **regenerable package caches
only** (`pip cache purge`; the 11 GB `~/.cache/uv` was lock-held and left alone) — no Docker images,
no user data. Docker never recovered and is still hung, which means **Redis is down**, which means
`tests/sidecar/` and other Redis-backed tests error on connection refused.
**Triaged, not assumed:** those same tests fail identically on a **clean tree with every change
stashed**, so they are environmental. Restarting Docker (and with it the kind cluster) is San's call.

### Correction — one post-bump failure was mine, not the environment (`c237232`)

I reported the post-OPA-bump failures as environmental after checking `tests/sidecar` alone. That
generalisation was wrong. Running the full suite with output captured showed 12 affected files, and
one was a **real regression from the bump**:
`test_global_registry_mirrors_third_party_not_norviq` pinned
`mirror.example.com/openpolicyagent/opa:1.18.0-static` as a literal. Its subject is the mirror
**prefix**, so the tag now comes from `values.yaml`; the image itself is still guarded by
`test_default_third_party_images_are_upstream` immediately above. `tests/helm/` → **176 passed**.

The rest of the account does hold, and was checked rather than assumed:
- the errors are `asyncpg` / `redis` **connection** failures (Postgres and Redis are Docker-provided,
  and Docker is hung);
- `tests/engine/test_priority_enforcement.py` fails **identically on a clean checkout of `main`**.

**Lesson worth keeping:** triaging one file and generalising to the rest is how a real regression gets
filed as environmental. Capture the whole run and group by file before making the claim.

---

## 2026-08-13 (cont.) — MEDIUM findings, all on `fix/v020-eval-backlog`

San asked for one branch. The six HIGH branches were stacked, so `fix/v020-eval-backlog` branches off
`fix/f-001-bump-opa-1.19.0` and therefore contains **everything**.

- **F-027** (`48e0336`) — one concept, **four** homes, and they disagreed: values.yaml / config.py /
  the Deployment template all said `allow`, `webhook/config.go` said `block`. **Declined the flip to
  fail-closed**; aligned the Go default to `allow` instead. The chart always wins, so `block` was dead
  on every real install — which is exactly what made it dangerous: it is the branch that runs when the
  chart value is ABSENT (slimmed values, hand-written manifest, a harness building `Config{}`), and
  there it would silently fail CLOSED and stop the customer's agents. Failing open here is **not
  silent** — `NRVQ-SDK-1013` plus `rule_id=engine_unavailable_fallback` in both modes — which is what
  separates a documented trade-off from a governance hole. `test_chart_defaults_track_code.py` now
  compares all four and names which drifted.

- **F-008** (`1b411f7`) — `PYPI-README.md` claimed deny-by-default; the product ships allow. Fixed the
  **docs**, not the default. Kept the bullet's purpose: the truth is equally surprising, just in the
  other direction (a typo'd `agent_class` reads as a clean pass), so it says that, says what to check,
  and gives the knob. Every other deny-by-default mention describes a *policy template* and is
  correct — only the README conflated the two.

- **F-006** (`eb199d7`) — SSRF floor. Seven variants went allow → block (IMDS, ECS creds, GCP,
  loopback, decimal, hex, `localhost`). New `norviq/engine/ssrf.py` classifies with `ipaddress`
  because **the encodings are the attack** and the preset had no regex-op budget left.
  **RFC1918 is classified and deliberately NOT blocked** — an agent in k8s talks to 10.x all day, and
  refusing that is the 39-of-53 over-block again. `metadata.acme.com` and `localhost.acme.com` stay
  clean (exact host or parent suffix, never substring).
  *Got `127.1` wrong first* — an early draft returned before trying the short dotted form. Rule: match
  what the HTTP **client** resolves, not what the address spec calls well-formed.

- **F-014** (`2b1d4a8`) — `?namespace=` was silently dropped, so the suite scored `default` and
  reported 5.9% for a scope that was 82.4%. Unknown query params are now 422 **naming the ones that
  work**, and the report carries the scope it measured (`scope_empty`, `targets_are_fallback`,
  `policy_rules_loaded`). **Deliberately did not 404 an unknown namespace** — a fresh install has no
  seeded classes anywhere, and refusing there breaks the first thing an operator does.

- **F-013** (`2a1abd4`) — concealment by intent, not a verb list. 6 of 9 probes evaded; 12 of 12 now
  caught. Two new rules (`mcp_a_line_jumping`, `mcp_a_side_channel`) are **gated** so
  "Logs each call for audit purposes." and "Include the request id in every response" stay clean —
  a description scanner that fires on those gets switched off and then catches nothing.
  *Disagreement with the card:* `do not reveal` was **already caught**; `reveal` was in the
  alternation. The other five held up.
  **NOT done:** cross-server description shadowing needs a shared cross-instance registry — an
  architectural change, left open rather than half-done.

- **F-033** (`e3b7cfa`) — a sustained violation rate now **caps** trust instead of subtracting from
  it. The band was unreachable *by construction*: weight 0.25 means a constantly-blocked agent floors
  at **0.75**, and no bucket-steepening reaches 0.4 because the weight is the ceiling. A test pins the
  old 0.75 so nobody folds it back into a weight. Compliant agents are numerically unchanged (§4.4).

### Triage discipline that paid off

Every remaining suite failure was proven environmental by capturing the full run and diffing the
failing set against `main` — **byte-identical**. That is the check I skipped earlier and got wrong.

---

## 2026-08-13 (cont.) — LOW findings; the v0.2.0 backlog is now closed

All on `fix/v020-eval-backlog` (26 commits off `main`), which contains the HIGH work too.

- **F-034** (`f4f5e00`) — the authored `reason` was computed, REQUIRED at author time (422 without
  it), carried through `PolicyDecision`, written to the audit record — and `EvaluateResponse` was
  three fields that did not include it. The operator wrote the sentence, the product insisted on it,
  the caller never saw it.
- **F-005** (`f4f5e00`) — `sql_query {query:"SELECT * FROM t -- bypass"}` was ALLOWED. Requires a
  leading SQL keyword **and** a terminator; adding `--` to the destructive set would have failed twice
  (the gate wants the value to LEAD with the pattern, and `--` in prose is punctuation).
- **F-007** (`f4f5e00`) — `file://` blocked as `deny_shell_execution`, a shell attempt that never
  happened. New `dangerous_scheme` **wins the sorted-rule_id tie-break** (checked, not assumed).
  **Did NOT narrow the shell rule to exec-class tools** as the card suggests — that trades an
  attribution bug for a detection gap on a renamed tool carrying a real payload.
- **F-004** (`689686b`) — bare credential VALUES, as `secret_suspected`, a **separate advisory class**
  that blocks nothing. Merging into `secret` was one line and would fire `llm02_data_leakage` on every
  commit hash. Precision comes from excluding known-benign SHAPES — a digest and a secret have the
  same entropy, so no threshold separates them. *This is why I declined the same heuristic under
  F-045: there it widened a BLOCKING class.*
- **F-009** (`689686b`) — `tenant_id` was compared against the k8s NAMESPACE. `agent.home_tenant` when
  configured, namespace as fallback. Tested that a configured home tenant still **blocks** another
  tenant — widening a comparison must not turn a containment control off.
- **F-018 / F-020 / F-023** (`4442420`) — dry-run now separates `no_replayable_traffic` from
  `params_captured` (masked capture is off by default, so content rules cannot fire) and returns an
  `advisory` sentence so every consumer gets the caveat, not just the console; observed-tools panel
  shows the namespace; the Overview gauge says "85% proven-blocking **of 20 evaluate-reachable
  red-team attacks**" instead of a bare percentage that reads as total coverage.
- **F-028 / F-016** (`959bbaf`) — MCP injection is stdio-only; an HTTP server is injected but
  **ungoverned**, and now logs `NRVQ-WHK-4051`. **Warned, not refused** — a stdio server may
  legitimately expose a health port, and failing admission would trade a visibility gap for an outage.
  F-016 documents that content DLP is not the control for shapeless data; **the destination is**.

### Disagreements recorded (checks trusted over the cards)

- **F-027** — declined the flip to fail-closed. The three-way disagreement was the defect; failing
  open is already loud (`NRVQ-SDK-1013` + `engine_unavailable_fallback`).
- **F-026** — the card's premise inverts: LangGraph/SK guard the **execution path**, which is stronger
  than per-tool wrapping. Unifying would have *introduced* the gap it worried about.
- **F-013** — `do not reveal` was already caught.
- **F-044** — fail-closed revocation would turn a Redis blip into a total auth outage; time-boxed it
  instead (30s, cleared on success).
- **F-043** — namespace posture not threaded (needs a query this route does not make); `proven` gives
  the monitor-mode signal that motivated it.

### Final gates

`opa test --v0-compatible` **59/59** · `ruff` clean · UI **1155 passed**, `tsc` + `eslint` clean ·
`go build` + `go test ./webhook` ok · f032 battery **1/22 evaded, 0 FP**.
Python suite **2922 passed, 6 failed, 56 errors** — and the failing set is **byte-identical to `main`**
(all `redis`/`asyncpg` connection errors from Docker still being down). Verified by diffing the
failing set against a clean `main` checkout after every batch, which is how the one real regression in
this session was caught rather than assumed away.

### Still open (unchanged, deliberately)

Cross-server MCP description shadowing (needs a shared cross-instance registry); an audit signal for a
tool invoked without passing the guard (F-026, needs-live — detecting the ABSENCE of a call);
namespace posture in the MITRE pack (F-043); HTTP MCP proxy wiring (F-028 — a feature, not a fix).
