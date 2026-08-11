# Campaign 2 — handover

**Purpose:** a new session should be able to resume from this file alone. Keep it current — update
the "Work queue" and "Session log" sections every time something lands. Do not let it go stale.

Last updated: 2026-08-10 — Tiers 1/2/2b/3 DONE and VERIFIED LIVE. Round 2 run; C2-024 found and fixed (NOT yet live).
Remaining: C2-013, C2-016, Tier 4 triage, the three deliverables, and resuming the attack campaign.

---

## Where things stand

**Branch:** `integrate/mcp-and-builder`. ~38 unpushed commits. Version 0.2.0, no tag at HEAD.
**NOT merged to main, NOT pushed, NO new version cut** — all three need San's explicit approval.

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

- **Postgres and Redis credentials must be rotated.** Two separate Campaign 1 subagents exposed them.
  Still not done. An assistant must not rotate live credentials — this is San's.
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

  **NEXT: C2-013 needs San's call on storage (see the doc), then it is 4 layers of work.** Round 2's real lesson is
  that C2-012/C2-022/C2-024 are ENUMERATION, not generalisation: each fixed the evasions in front of
  it and the next round found one more separator. Keying on a semantic fact instead of the spelling of
  a caller-supplied string is the only thing that ends that loop. Then C2-016, the Tier 4 triage, and
  the three missing deliverables.
