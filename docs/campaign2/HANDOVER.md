# Campaign 2 — handover

**Purpose:** a new session should be able to resume from this file alone. Keep it current — update
the "Work queue" and "Session log" sections every time something lands. Do not let it go stale.

Last updated: 2026-08-10, after the backlog reconciliation.

---

## Where things stand

**Branch:** `integrate/mcp-and-builder`. ~35 unpushed commits. Version 0.2.0, no tag at HEAD.
**NOT merged to main, NOT pushed, NO new version cut** — all three need San's explicit approval.

**Latest commits:**
- `236a1c3` campaign2: a throttle is not a detection (C2-021), + rate-abuse findings
- `e1030dd` campaign2: file C2-019/C2-020, resolve SEED-06 from live evidence
- `3ad6c8c` C2-018 resolved — all five frameworks verified enforcing on current GA
- `00a674c` crewai[litellm] dependency fix

**Gates last run:** `.venv/bin/python -m pytest tests --ignore=tests/integration --ignore=tests/attacks -q`
→ **2705 passed** at `236a1c3`. Ruff clean on touched files.

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

### Tier 1 — safety invariants (small, unambiguous)

- [ ] **`_gate_answer` breaks "monitor never interrupts".** `norviq/mcp/firewall.py:1477` tests
      `decision.decision == "allow"`. Its three siblings (`:821`, `:881`, `:921`) use
      `decision.is_allowed()`, which admits `("allow", "audit")` —
      `norviq/sdk/core/decisions.py:35-37`. `tests/mcp/test_firewall.py:127-132` states the doctrine:
      "`audit` is an ALLOW that is recorded. Treating it as a block would break visibility-only mode."
      So on the MCP **answer plane** an `audit` decision is refused: monitor mode interrupts customer
      traffic, and a monitor-softened engine fault (`monitor_would_block:evaluator_timeout`, decision
      `audit`) is refused with text blaming "policy". Reached unconditionally from `firewall.py:409-413`
      on any client message carrying `inputResponses`.
      **Fix:** use `is_allowed()`, add a test covering an `audit` decision on the answer plane, and
      **sweep the repo for other forked allow-checks** — this is the copy-only-one-copy pattern.
- [ ] **C2-002 is incomplete.** `norviq/api/routers/compliance_view.py:120` honours a bare audit
      rule_id only when it is one of the 14 shipped controls. Verified: `pii_detection`/audit →
      counted; `refund_over_limit`/audit → **dropped**. The Visual Builder ships `audit` as a
      first-class rule decision (`ui/src/components/policies/BuilderSheet.tsx:603`,
      `ui/src/lib/builderCompile.ts:264`), so a customer trialling their OWN policy in monitor mode
      emits exactly that shape — and the "Your own policies" section added for C2-002
      (`ui/src/components/policies/BaselineControls.tsx`) renders zero for the case it exists to serve.
      **Fix:** the exclusion is correct for the blast-radius question the docstring describes; the
      mistake is one filter serving two opposite questions. Add a **second bucket** (same shape as
      `_enforced_violation_for`), do not change the existing filter.

### Tier 2 — the instrument (must land before any further attack testing)

- [ ] **C2-023 — base64 false-positive root cause.** `webhook/presets/strict.rego` has two
      near-anagram lists differing by exactly the three bare metacharacters:
      `shell_patterns_decoded = ["|", "$(", "`", "rm -rf", …]` vs
      `decoded_shell_patterns = ["rm -rf", "/etc/passwd", "/etc/shadow", "wget ", "curl ", "nc -e"]`.
      `base64_decoded_threat` uses the correct one; the decoded arm of `shell_injection_detected`
      (`strict.rego:198-202`) uses the other, matching `|` against random decoded bytes.
      Traced to the byte: `"benign call 18"` → whitespace-stripped candidate `benigncall12chars` →
      decodes to bytes ending `0x7C`. Predicted ~3.5%, observed 2.5% here, 4.0% @8 in Campaign 1.
      **Fix:** decoded arm uses `decoded_shell_patterns`. Expect the FP curve to collapse to ~0 while
      real encoded payloads still match. **Re-run the FP baseline afterwards to confirm it moved.**
- [ ] **C2-022 — name-keyed controls.** `_is_rate_limit_exempt` (evaluator.py:911) is a name-prefix
      test; `strict_default_block` (strict.rego:740-745) is `startswith`. Both decided by a
      caller-supplied string. Proven live: `delete_all_records` caught 75/75;
      `get_delete_all_records` allowed 75/75 and never throttled. `classify_tool` says `delete` for
      both.
      **THE TRAP — do not skip.** The obvious fix (exempt on `derived.verb == "read"`) is *worse*:
      `classify_tool` falls back to inspecting **agent-supplied `tool_params`** when the name resolves
      to nothing, so an unknown name + `{"query": "select 1"}` classifies as `read` and earns the
      exemption. The evaluator already warns about this in a neighbouring comment. Use
      **name-resolved read only** — `classify_tool(tool_name)` with NO params, requiring a confident
      `read` — which is strictly narrower than today's prefix list.
      Landing this should also close **C2-012** (homoglyph tool name), **C2-013** (destination-keyed
      control), **C2-016** (supply-chain phrasing) — all the same root cause. Confirm each.

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
