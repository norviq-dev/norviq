# Campaign 2 — handover

**Purpose:** a new session should be able to resume from this file alone. Keep it current — update
the "Work queue" and "Session log" sections every time something lands. Do not let it go stale.

Last updated: 2026-08-10 — Tier 1 done, Tier 2 done (C2-023 + C2-022). Tier 2b / Tier 3 next.

---

## Where things stand

**Branch:** `integrate/mcp-and-builder`. ~38 unpushed commits. Version 0.2.0, no tag at HEAD.
**NOT merged to main, NOT pushed, NO new version cut** — all three need San's explicit approval.

**Latest commits:**
- `6dfd55d` C2-022: a destructive tool must not escape by being renamed
- `b3501c6` C2-023: the decoded arm must not match bare shell metacharacters
- `e741d6e` tier 1: monitor must never interrupt, on every plane that decides
- `236a1c3` campaign2: a throttle is not a detection (C2-021), + rate-abuse findings

**Gates last run at `6dfd55d` — ALL GREEN:**
- `.venv/bin/python -m pytest tests --ignore=tests/integration --ignore=tests/attacks -q` → **2717 passed**
- `.venv/bin/python -m ruff check norviq tests` → clean
- `opa test --v0-compatible comprehensive.rego webhook/presets/strict.rego webhook/presets/strict_parity_test.rego` → **22/22**
  (NOTE: bare `opa test` FAILS on this repo — OPA 1.x defaults to Rego v1, these presets are v0.
   The `--v0-compatible` flag is not optional. Without it you get parse errors on every rule.)
- `cd ui && npx tsc --noEmit && npx eslint src --max-warnings=0` → clean

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

- [ ] **C2-012 — homoglyph / zero-width tool name evades every name-keyed control.** Fold
      `input.tool_name` to an ASCII confusable skeleton before matching, mirroring what the engine
      already does for `tool_params`. Verify with `dеlete_records` (Cyrillic е) and a zero-width-space
      variant; both currently return `allow / default_allow` against an all-deny baseline.
- [ ] **C2-013 — no destination-keyed control for tools outside a hand-written allowlist.** The
      campaign's headline design finding, proven three times on three surfaces.
- [ ] **C2-016 — supply-chain phrasing in a query param does not trip `llm05_supply_chain`** (it is
      tool-name keyed).

### Tier 3 — high-severity infrastructure

- [ ] **C2-019 — injected credentials are literal pod env.** `webhook/injector.go:515` (and `:393` for
      the token) emit `{"name": …, "value": …}`. Kubernetes deliberately excludes Secrets from the
      built-in `view` ClusterRole (verified on this cluster: `view` grants `get pods`, not
      `get secrets`), so a read-only grant yields a working 30-day workload JWT.
      **Fix:** webhook creates/patches a per-pod or per-namespace Secret and injects
      `valueFrom.secretKeyRef`. No sidecar change needed — same env var either way.
      Also: nothing **revokes**. `norviq/api/session_revocation.py` exists but its only caller is
      `auth_login.py:174` (interactive logout). No admin revoke endpoint, no CRL.
- [ ] **C2-020 — every injected pod hard-stops at day 30.** Token TTL measured 720h exactly; client
      cert `webhook/injector.go:553` `now.Add(30*24*time.Hour)`. No renewal loop in `webhook/`, no
      refresh in `norviq/sidecar/`. At expiry the API answers 401 (verified live) → `remote_evaluator.py:215`
      sets `refused=True`, overriding `sdk_fallback_mode` → fails closed. **That behaviour is correct**
      (a refused credential must not become a bypass) — the defect is that nothing renews and nothing
      forewarns. `/system-health` diagnoses it only once the outage starts.
      **Fix:** surface days-to-expiry as a warning band well before the cliff; consider having the
      controller roll pods approaching expiry (rotation IS pod replacement, already proven to work).

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
  **NEXT: Tier 2b (C2-012 name skeleton) or Tier 3 (C2-019 secretKeyRef). Both are open;
  C2-019 is the higher severity.**
