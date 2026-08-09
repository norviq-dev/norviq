# CAMPAIGN LEDGER — rev 30 (allow-by-default)

Every experiment run by the eight agents, with its claim, status and the evidence that decided it.
`PASS` = the claim held. `FAIL` = the claim did not hold (i.e. a defect, or a design expectation
that was wrong). `NOT_MEASURED` = not executed, with the reason.

Target: live AKS (`kube context norviq`), API on `127.0.0.1:8080`, namespaces `chatbot-prod`,
`analytics`, `default`. ~7,000 real `/evaluate` calls, all under `cmp-*` agent classes with real
framework names so nothing was hidden by `norviq/api/synthetic.py`.

Totals: **102 experiments — 72 PASS, 22 FAIL, 8 NOT_MEASURED.**

---

## 1. Non-interference (benign corpus)

6,115 `/evaluate` calls in `ns/chatbot-prod` as `cmp-support` / `langchain`, including a 200-call
realistic support-desk corpus and state-correlated rate sweeps behind a token-bucket governor.

| # | claim | status | evidence |
|---|-------|--------|----------|
| 1.1 | **BLOCKER CHECK:** `deny_shell_execution` returns `audit`, not `block`, under the shipped monitor default | **PASS** | `sweep2.py` — 2,850 calls with a 1s background poller over `GET /baseline/controls`; 304 control-state samples, all `monitor`; 0 excluded; **0 block decisions**. Independently `correlate.py` (400 calls, state-stamped): monitor → `{allow:219, audit:43}`, off → `{allow:138}` |
| 1.2 | Realistic 200-call corpus: 20% flagged as would-block, 0 hard blocks | **PASS** | `final.py` PART A: `TOTAL 200 {'audit':40,'allow':160}`, hard blocks `{}`; 152 poller samples, no churn |
| 1.3 | Base64 fan-out rate table by identifier shape/length (n=150 each) | **PASS** | 4.0% @8 → 8.7% @16 → 12.0% @24 → 19.3% @32 → 32.0% @64; hex_64 20.0%, b64_44 22.0%, uuid_v4 14.7%; digits_12 **0%**, licence_5x5 **0%**; ALL 362/2850 = **12.7%** |
| 1.4 | A `;` in ordinary prose triggers `deny_shell_execution` 100% of the time | **PASS** | `quantify.py`: semicolon 60/60, pipe 30/30, backtick 30/30; fullstop 0/60, comma 0/30. Minimal pair from `isolate.py` differs by one character |
| 1.5 | A bare ISO-8601 date parameter is classified as PII/SSN 100% of the time | **PASS** | 60/60 across 10 key names; `...T00:00:00Z` 0/30; date-in-prose 0/30. Source confirmed `strict.rego:529` |
| 1.6 | `[A-Z]{2}\d{7}` business refs classified as PII/SSN 100% of the time | **PASS** | 60/60 across GB/SO/IN/PO/RM/AC/CS/WO; hyphenated 0/30; 6-digit 3/30 (unrelated base64 fan-out) |
| 1.7 | `strict_default_block` matches on tool NAME alone | **PASS** | `final.py` PART B, identical params `{'id':'T-4471'}`: name-matching 31/31 flagged, name-safe 0/49. Rule source `strict.rego:740-750`, eight `startswith` tests, no `input.tool_params` reference |
| 1.8 | A monitor `audit` really is a would-DROP: promoting to deny converts the identical call to a hard block | **PASS** | `promote_proof.py` in `ns/default`: ISO-date and semicolon calls `audit` → `block` after PUT; `get_order` control still `allow`; **RESTORED: True, counts {'monitor':14}** |
| 1.9 | Flagged traffic is visible on `/policy-compliance` (naming convention worked) | **PASS** | scanned 6428, excluded_synthetic 0; `deny_shell_execution 460`, `pii_detection 128`, `strict_default_block 58` — the board's three largest rows are all false positives |
| 1.10 | The 25 block decisions in the first uncorrelated sweep are NOT monitor-mode failures | **PASS** | `__baseline__` `current_version` moved v67 → v101 during a single sweep and the control read `off` immediately after; two state-correlated re-runs (400 + 2,850 calls) recorded 0 blocks |
| 1.11 | Per-identity rate limiting contaminates naive corpus runs and is not softened by monitor | **PASS** | First unpaced run: `{'allow':112,'audit':1,'block':87}`, all 87 `rate_limit_exceeded` (**43.5%**). `config.py:169`, `evaluator.py:350` |
| 1.12 | Monitor-mode would-blocks are emitted in two rule_id shapes | **PASS** | bare (`baseline.py:336` compile path) vs prefixed (`evaluator.py:826`); `/policy-compliance` does group both correctly, so latent labelling inconsistency, not observed data loss *(but see §6 — the compiled-monitor case does lose them)* |
| 1.13 | Trust score decays under ordinary high-entropy traffic toward the escalate threshold | **NOT_MEASURED** | Observed `cmp-support` trust 0.445-0.955 and `param_entropy=1.0`, but could not separate decay from legitimate traffic vs the harness's own 96 rate-limit violations. Needs a clean-identity longitudinal run |

---

## 2. Drop inventory (13 rule_ids audited)

| # | claim | status | evidence |
|---|-------|--------|----------|
| 2.1 | `_BASE_POSTURE_EXEMPT_RULES` contains only `trust_frozen`; the four operational rules were removed | **PASS** | executed: `['trust_frozen']`; `_posture_exempt_rules()` = `['rate_limit_exceeded','trust_frozen']` |
| 2.2 | `_apply_posture` with monitor=True softens every operational rule_id to `audit` | **PASS** | 12 rule_ids executed; only `rate_limit_exceeded` and `trust_frozen` stay `block` |
| 2.3 | `evaluator_timeout`, `evaluator_fallback`, `invalid_spiffe_identity` still hard-block in an audit namespace because they bypass `_apply_posture` | **PASS** (defect) | full `evaluate()` with `enforcement_mode=audit`: all three `block`; the four routed rules soften to `monitor_would_block:*` |
| 2.4 | `rate_limit_exceeded` drops real traffic with no policy loaded, at 60/60s | **PASS** | 75 sequential calls: 1-60 allow, 61-75 block. `Counter({'allow':60,'block':15})`. Namespace-wide 108 rows in 1h |
| 2.5 | The read-tool carve-out works | **PASS** | over-limit identity: write #65 blocked, `get_record`/`list_things`/`search_x` all allow, next write blocked again |
| 2.6 | `invalid_spiffe_identity` drops live | **PASS** | `"not-a-spiffe-id"`, `"http://evil/ns/x/sa/y"`, `""` → 3/3 `block`, trust 0.0 |
| 2.7 | A malformed `/evaluate` body 422s and never reaches the evaluator | **PASS** | 5 malformed shapes all 422; `evaluator_invalid_payload` is minted only from an OPA *result* shape |
| 2.8 | The authoring path that would mint `evaluator_invalid_payload` is rejected at Gate B | **PASS** | POST with partial-set rules and no resolver → 422; no policy row created |
| 2.9 | `engine_rejected_request`: any 4xx blocks at the PEP regardless of fail-open posture | **PASS** (code + preconditions) | 401/401/422 proven live; HTTP limiter 429 at 3000/60s; `engine.py:145-156`. Sidecar verdict itself not executed |
| 2.10 | `no_policy_loaded` cannot fire on this build | **PASS** | cm `NRVQ_NO_POLICY_DECISION=allow`; 3 namespaces with no class policy → `allow / default_allow` |
| 2.11 | `policy_load_pending` can still drop but is softenable | **PASS** | `evaluator.py:1743-1747`; softened in-process. Not driven live — needs a replica restart (forbidden) |
| 2.12 | No namespace on this cluster is in monitor mode | **PASS** | `GET /settings` → `enforcement_mode=block` for chatbot-prod, analytics, default, norviq. The chart's `enforcementMode: audit` is the per-policy mode |
| 2.13 | `engine_unavailable_fallback` / `thin_proxy_fail_open` allow on this deployment | **PASS** | `sdk_fallback_mode=allow` in config, on `norviq-webhook`, and on all 3 injected sidecars. A typo'd value coerces to `block` — whole data plane fails closed |
| 2.14 | The deployed baseline in analytics/default is the raw strict preset, not the compiled monitor build | **FAIL** (contested) | `GET /baseline/controls` `{monitor:14}` vs module `blocks:22, escalates:1, audits:1`, no compiler marker; `delete_thing` → `policy_audit_would_block:strict_default_block`. **Refuted on shipped impact** — see §5 |
| 2.15 | `system-health` surfaces the operational drops that are actually happening | **FAIL** (contested) | `{"status":"ok","issues":[]}` with 108 rate-limit blocks in the trailing hour; `_INFRA_RULE_IDS` omits 5 rule_ids. **Refuted** on scope for 2 of them; the 3 engine-minted ones stand |
| 2.16 | `trust_frozen` is produced only by an explicit admin freeze | **FAIL** | `_safe_frozen_only` returns `True` on any Redis exception → `frozen` → hard block. Live census: 165 agents, 0 frozen |
| 2.17 | `evaluator_timeout` / `evaluator_error` driven live against the deployed engine | **NOT_MEASURED** | Needs a >2.0s OPA evaluation or a persistently failing OPA query; the only lever was authoring deliberately expensive rego on a shared live cluster |

---

## 3. Baseline controls (the feature under test)

| # | claim | status | evidence |
|---|-------|--------|----------|
| 3.1 | `GET /baseline/controls` returns 14 controls, all `monitor`, each with title + description | **PASS** | HTTP 200, counts `{off:0, monitor:14, deny:0}`, all `desc_len > 0` |
| 3.2 | Controls with known false-positive modes carry a caveat | **PASS** | **four**, not the two the brief expected: `deny_shell_execution`, `pii_detection`, `chain_depth_limit`, `strict_default_block` |
| 3.3 | An isolating trigger exists for each of the 14 controls | **PASS** | 14/14 fired at monitor with the expected rule_id (except `deny_sql_multi_statement`, misattributed to `deny_shell_execution` — see §6/SEED-03) |
| 3.4 | **CRITICAL:** with every control at monitor there are no `blocks[]` heads, yet the module compiles and produces real decisions | **PASS** | region shows `blocks[id] { false; id := "__never__" }` sentinel + 24 audits heads; 15/15 live evaluations returned audit or allow; `audit/stats engine_errors: 0` |
| 3.5 | **CRITICAL:** the all-OFF state also compiles and produces real decisions | **PASS** | region is nothing but the three sentinels; 14/14 triggers + benign → `allow / default_allow`, zero `evaluator_error` |
| 3.6 | Control by control: deny blocks, benign allows, off allows (14 × 3 states, 28 PUTs) | **FAIL** | **13/14 block correctly.** `scope_violation_dangerous_tool` returns `audit` at deny. Benign allowed 14/14 |
| 3.7 | The `escalates[]` head keeps its severity at deny rather than collapsing to block | **PASS** | `llm06_excessive_agency` compiles both heads; `modify_config` → `escalate`, `truncate` → `block` |
| 3.8 | All-deny is behaviourally identical to the shipped strict preset | **PASS** | head-for-head diff against the pre-test deployed rego: 24 vs 24, MISSING `[]`, EXTRA `[]` |
| 3.9 | Adversarial input handling (unknown id, invalid effect, null, int, empty map, all-controls map, bad preset) | **PASS** | 422/422/422/422 · 200/200 · 404. Validation happens before any DB write |
| 3.10 | A non-admin token gets 403 on PUT | **NOT_MEASURED** | No non-admin credential exists; minting prohibited. 401 paths verified (`Missing token` / `Invalid token`); `require_admin` is the first statement of `set_controls` |
| 3.11 | `namespace="all"` is handled as a sentinel, not a literal namespace | **FAIL** | GET 200 for `all` **and** for a nonexistent namespace; PUT materialized a real `(all, __baseline__)` row at priority 1 reporting `matches: 3`. Cleaned up |
| 3.12 | Partial-map semantics: a one-control PUT leaves the other 13 at the DEFAULT | **PASS** | previous state all-deny → after `{'deny_shell_execution':'off'}`: counts `{off:1, monitor:13, deny:0}`, 23 audits heads |
| 3.13 | The compiled policy is stored at scope `__baseline__` and appears in `GET /policies` | **PASS** | priority 1, `matches: 2201`; `/policies/effective` shows one layer `chatbot-prod:__baseline__` |
| 3.14 | Traffic flagged by a control at monitor shows up in `/policy-compliance` | **FAIL** | 3 `install_package` calls → `audit / llm05_supply_chain`; polled to a 99s deadline, count stayed at 1. Audit rows exist with the bare rule_id |
| 3.15 | `chatbot-prod` restored byte-identically | **PASS** | original sha256 `8e175c0425e5ed9d` = restored; mode back to `audit`; 14/14 triggers matched pre-test rule_ids exactly |

---

## 4. Attack corpus and enforcement

| # | claim | status | evidence |
|---|-------|--------|----------|
| 4.1 | All 34 attacks drive cleanly at the default posture | **PASS** | 34 rows, all HTTP 200: 26 `audit`, 2 expected `allow` (RL-001, CE-002), 6 `allow` because the control is not installed |
| 4.2 | After promoting all 14 controls to deny, every enforceable attack blocks | **PASS** | 26/26 `block` with the correct rule_id across PI/DL/EA/CT/SQL/SH/SC/TM/CE/PB/PII/PCI/MCP-04/05 |
| 4.3 | RL-001 and CE-002 allow at BOTH postures → exactly two permanent false reds | **PASS** | unchanged by promoting all 14 to deny |
| 4.4 | FIN-001, PHI-001, OT-001, MCP-01/02/03 cannot block at any control setting | **PASS** | `input.mcp` count = 0 across all five shipped presets; none of the five conditional rule ids appear in the deployed baseline. Suite agrees (`applicable=false`) |
| 4.5 | The `chatbot` class policy overrides the namespace baseline entirely | **FAIL** (contested) | with all 14 at deny, `drop_table`/`exec_shell`/`get_customer`/`update_record` → `allow / demo_default_allow`; all 25 applicable got_through rows are class `chatbot`. **Refuted** — highest-priority-outright is documented, intended precedence, and the offending policy is demo dressing not shipped config |
| 4.6 | `POST /redteam/suite` is reachable; efficacy at deny | **PASS** | 646 rows, 78.5% pass, `{"total":494,"caught":469,"got_through":25,"proven_blocking_pct":94.9}` |
| 4.7 | At the shipped default the suite reports ~0% proven blocking | **FAIL** | 680 rows, 6.0% pass, `0.2%`; got_through by decision `{audit:494, allow:23, escalate:2}` |
| 4.8 | Suite traffic is `framework="redteam"` and excluded from KPIs by design | **PASS** | `redteam.py::_build_event`; `synthetic.py::audit_row_is_non_real`. Contrast: `cmp-corpus-monitor` (langchain) IS visible, 34 rows |
| 4.9 | Corpus rows reach `/policy-compliance` grouped by control | **PASS** | scanned 6482; `deny_shell_execution 463` including `cmp-corpus-monitor(2)`; prefix stripped correctly |
| 4.10 | A namespace-tier scope can decide evaluations while invisible to every read API | **FAIL** (contested) | 5 attacks returned `allow / cmp_nstier_audit_other`, a rule in no visible policy; `/policies/.../namespace:chatbot-prod` 404, versions `[]`, not in `/effective`. **Refuted** — enforcement and the read APIs share `loader._policies`, so the reads simply happened after the entry was gone |
| 4.11 | `GET /baseline/controls` reported a state that did not match the deployed artifact | **FAIL** (contested) | `{monitor:14}` while the deployed module was byte-identical to raw `strict.rego` (22 blocks). Same finding as 2.14 |
| 4.12 | Enforcement is stable at steady state | **PASS** | 50 unique-param evaluations → `{block:50}`, `{llm01_prompt_injection:50}`; 60-call windows at monitor and deny → 0 stray allows |

---

## 5. Policy tiers and precedence

| # | claim | status | evidence |
|---|-------|--------|----------|
| 5.1 | **HEADLINE:** a per-class allowlist at priority 200 strips a priority-1 namespace baseline entirely | **PASS** | `delete_customer` in `ns/default`: `audit / strict_default_block` → `allow / cmp_class_allowlisted`; `read_file` → `block / cmp_class_not_allowlisted`. Baselines are a default, not a floor |
| 5.2 | Base tiers resolve by highest priority outright; specificity is irrelevant | **PASS** | ns-tier @300 beats class @200 (`block`); re-POST the same policy at @50 and the class wins (`allow`). Both directions |
| 5.3 | The workload tier enforces, and only on an exact workload match | **PASS** | `workload=cmp-wl` → block; absent or `other-wl` → allow |
| 5.4 | Overlays are strictly tighten-only regardless of priority | **PASS** | full 2×2: guardrail block @1 beats base allow @200; guardrail allow @499 never relaxes base block @1 |
| 5.5 | A cross-namespace `target.namespace` must not store a key the evaluator never looks up | **FAIL** | stored as `namespace:analytics` @499, fires in neither namespace, reports `matches: 6516` — identical to the genuinely enforcing row |
| 5.6 | `namespace="all"` in `/evaluate` resolves the same tiers as a concrete namespace | **FAIL** | concrete → `block` (ns tier / workload tier); `all` → `allow` (class policy) in both cases. `_collect_candidates_union` omits both tiers |
| 5.7 | A `__guardrail__` can be created by a service token but removed only by an admin | **NOT_MEASURED** | Admin half verified live (422 without `confirm_managed`, 200 with). Service half is code-read only — minting a service token is prohibited |
| 5.8 | `__pack_weaken__` relaxes only the pack family and can never relax a `__guardrail__` | **NOT_MEASURED** | Generic write path closed (422, managed scope); the only remaining path mutates pack bookkeeping that could not be restored byte-for-byte |
| 5.9 | A high-priority audit-mode policy must not remove enforcement from a lower-priority block-mode policy | **FAIL** | `block / cmp_class_hard_block` → `audit / policy_audit_would_block:cmp_nstier_trial_block` after adding an audit-mode ns tier at 300 |
| 5.10 | The `ns='all'` sentinel is guarded at the policy write boundary (positive control) | **PASS** | 422 with the message *"would show as enforcing while protecting nothing"* — the same failure mode 5.5 is not guarded against |
| 5.11 | Cross-replica policy sync propagates creates and deletes | **PASS** | peer replica logged `nrvq.policy.remote_unloaded NRVQ-REG-5016 key=chatbot-prod:__guardrail__` |
| 5.12 | Half the API replicas reject a valid admin token (401) while Ready | **FAIL** (refuted) | 3/3 reproducible split across two pods of the same ReplicaSet. **Refuted** — the 401 leg was a local uvicorn dev server on the collided port; `kubectl port-forward` half-binds IPv6-only and `127.0.0.1` resolved to the laptop process |

---

## 6. Compliance view

| # | claim | status | evidence |
|---|-------|--------|----------|
| 6.1 | N monitor-mode calls are counted exactly (chart baseline, `blocks[]` + policy audit mode) | **PASS** | `ns/analytics`: 13 calls, count 5 → 18, **exactly +13**; scanned 7 → 20; baseline fingerprint identical before/after. Independent reconcile: 20 audit rows − 2 excluded = 18 |
| 6.2 | Step 1 in `chatbot-prod` as instructed | **NOT_MEASURED** | A concurrent actor promoted all 14 controls to deny mid-batch (decisions flipped from `audit` to `block` in flight; `__baseline__` became compiler output at v105) |
| 6.3 | **BLOCKER:** a control at `monitor` produces a BARE rule_id and is counted as ZERO | **FAIL** | `ns/default` 11 calls → count 2 → 2 (expected 13); confirmed with 5 more → 2 → 2; scanned moved +11 and +5. Over 1h: 33 would-block calls, 7 reported |
| 6.4 | `framework="redteam"` and probe-/e2e- classes are excluded, and `excluded_synthetic` reflects exactly those | **PASS** | 7 + 5 + 4 = 16 rows → `excluded_synthetic` 0 → 16; none appear in any breakdown |
| 6.5 | Calls that actually blocked are not counted | **PASS** | 9 hard blocks under a purpose-built deny policy → control count 18 → 18, delta 0; scanned +9 |
| 6.6 | Both would-block prefixes fold to ONE control rather than splitting | **PASS** | `_strip_prefix` on all three forms (incl. double-prefixed) → one control, count 6+4=10. Monitor half produced in-process — no namespace on the cluster is in monitor mode |
| 6.7 | `scanned` distinguishes an idle namespace from a compliant one | **PASS** | fresh namespace: `scanned 0, controls []`; after 6 benign calls: `scanned 6, controls []`; third state (analytics): `scanned 20, controls [18]` |
| 6.8 | Breakdowns sum to `count`, samples capped at 5 | **PASS** | all 19 control rows across 3 namespaces at 24h: `sum(classes) == count == sum(tools)`, `len(samples) == min(5, count)` |
| 6.9 | `scanned` reconciles exactly with `/audit/stats` | **PASS** | 4 independent pairs, all equal (6399/6399, 6455/6455, 7/7, 20/20, 114/114, 125/125) |
| 6.10 | Range handling is monotone and validated | **PASS** | 1h/6h/24h/7d → 30/30/54/227 scanned, monotone; `range=12h` → 422 |

---

## 7. Console surfaces

| # | claim | status | evidence |
|---|-------|--------|----------|
| 7.1 | `stats.would_blocked` moves with monitor-mode traffic | **PASS** | `ns/analytics`: `{total:1, blocked:0, would_blocked:0}` → `{total:5, blocked:0, would_blocked:4}` for 4 real + 2 synthetic calls |
| 7.2 | In an audit-baseline namespace `blocked` is structurally 0 and the tile relabels | **FAIL** (contested) | `__baseline__` mode `audit`, yet `blocked:184`, `would_blocked:678`, `coverage.namespace_mode=block` → `monitorScope=false`. **Refuted** as worded (`blocked` is never structurally 0 — `trust_frozen`/`rate_limit_exceeded` stay hard); the incompleteness stands |
| 7.3 | Would-block rows render with the original rule visible | **FAIL** | `AuditLog.tsx:458-465` handles only `monitor_would_block:`; live census 270/270 rows carry the other prefix |
| 7.4 | `/policy-compliance` is reachable and correct | **PASS** | `{scanned:5, excluded_synthetic:2, controls:[deny_shell_execution ×4]}`; prefix stripped to the bare control id |
| 7.5 | `_INFRA_RULE_VARIANTS` covers prefixed forms and folds them back | **PASS** | 15 variants (5 base × 3 forms); fold sums counts, maxes last_seen, unions namespaces |
| 7.6 | `/system-health` responds sanely | **PASS** | 200, positive liveness evidence (`751 real governed tool calls … none carried an infrastructure verdict`) rather than a bare empty list |
| 7.7 | A softened engine fault still raises the `/system-health` banner | **NOT_MEASURED** | No infra-rule rows exist anywhere (3 namespaces × 500 newest rows, none matching). Inducing one requires DoS-ing a shared cluster or mutating policy |
| 7.8 | `/coverage-by-category`, `/tools`, `/agents` are reachable and show monitor-mode traffic | **PASS** | coverage 100% / 8 categories; 123 tools, first `source=observed`; 18 agents with live `last_seen` |
| 7.9 | Synthetic traffic is excluded from `/audit/stats` totals | **PASS** | 6 calls sent, all 6 recorded in `/audit/records`, total moved +4 not +6; `/policy-compliance` independently reported `excluded_synthetic: 2` |

---

## 8. MCP and framework parity

| # | claim | status | evidence |
|---|-------|--------|----------|
| 8.1 | `vectors.py` catalogues 39 vectors: 4 evaluate-reachable, 29 proxy-only, 6 out of scope | **PASS** | executed: `TOTAL 39 {'proxy':29,'out_of_scope':6,'evaluate':4}`. Only the 4 evaluate vectors were scored through `/evaluate` |
| 8.2 | `base-allowlist-strips-baseline-floor` (MCP-04/05) is adjudicated | **PASS** | `audit / llm02_data_leakage` and `audit / cross_tenant_access` |
| 8.3 | `mcp-server-identity-unattested` (MCP-01/02/03) is adjudicated | **FAIL** | all three forged-identity payloads → `allow / default_allow`; no rule reads `input.mcp` in any shipped preset. **Refuted as a defect** — the opt-in guardrail template is default-off and the product marks the category `applicable=false` |
| 8.4 | `resources-read-uri-gate` has a URI gate | **FAIL** | `file:///proc/self/environ` → `allow`; `file:///etc/shadow` → `audit / deny_shell_execution`, an incidental shell-wordlist substring match that fires identically on an unrelated tool. Zero `uri` references in any shipped `.rego` |
| 8.5 | `eval-cache-key-omits-mcp-context` can be scored through `/evaluate` | **NOT_MEASURED** | With no policy discriminating on `input.mcp`, opposite MCP documents are indistinguishable at the decision level. Guarded instead by `tests/engine/test_cache_key_scope.py` (7 passed) |
| 8.6 | The local adversarial harness passes | **FAIL** | EXIT=1, 19/22. All Gate A rows pass; the 3 Gate B rows fail |
| 8.7 | The 3 Gate B failures are an environment artifact (no engine reachable) | **FAIL** | With `NRVQ_POLICY_ENGINE_URL` pointed at the live engine: `evaluate.ok: 6, fallback: 0` and **still 19/22**, same 3 rows. Independently reproduced with a healthy engine returning the shipped no-policy `allow`, and with `audit` — both 19/22; only `block` flips them |
| 8.8 | A destructive MCP call is blocked by policy and never executed | **FAIL** | `delete_records` → `audit / strict_default_block` in `ns/default`, upstream log shows `benign:delete_records executed with {"table":"users"}`. Same call in `chatbot-prod` at deny → `block` |
| 8.9 | `pytest tests/mcp` passes | **PASS** | 226 passed |
| 8.10 | `pytest tests/sdk` passes | **PASS** | 221 passed |
| 8.11 | The 2026-07-28 revision removes `Mcp-Session-Id`; the header is accepted-and-ignored | **PASS** | read nowhere in code (2 comment mentions); 3 POSTs with victim/attacker/absent session ids → 1 firewall instance, keyed on the attested SVID, all 3 evaluated, header forwarded verbatim |
| 8.12 | A bare `tools/call` with no initialize and no session header works and is still enforced | **PASS** | http 200, reached upstream, Gate B evaluated; under a block decision `is_error: true, gate: "B"`, upstream never reached |
| 8.13 | MCP pin state is per-process | **FAIL** | Refuted for the default path: `mcp_pin_store=='memory'` is refused and upgraded to control-plane; `build_store('control-plane','')` now raises; store installed before the listener binds. 8-process test: all 8 agreed on one approved digest |
| 8.14 | The Gate-A carry-over catalog is shared across instances under stateless HTTP | **FAIL** (contested) | Instance A blocked at gate A; cold instance B with the same shared `PinRegistry` forwarded. **Refuted** on shipped topology (sidecar, one client per process) — but sidecar-restart amnesia and the rug-pull window are default-reachable variants |
| 8.15 | Framework parity: framework, session_id and tool_params reach the engine consistently across all five adapters | **PASS** | real packages (langchain-core 1.4.9, langgraph 1.2.9, crewai 1.6.1, autogen-core 0.7.5, semantic-kernel 1.36.0) + real `ToolInterceptor`; all five delivered identical params and session_id. `semantic_kernel` reports the hyphenated `"semantic-kernel"` |
| 8.16 | Only the LangChain adapter holds `depth_scope()`, so `call_depth` is 0 elsewhere | **FAIL** (confirmed defect) | nested depth: langchain 1, crewai 0, autogen 0, semantic-kernel 0, langgraph 0 |
| 8.17 | LangGraph sends `{}` when tool args are not a dict | **FAIL** (confirmed defect) | JSON string / list / None → `{}`, all evaluated and ALLOWED. End-to-end exploitation not demonstrated (pydantic + `ToolNode` reject the shapes downstream) |

---

## 9. Refuted and dropped — 21 claims

Each was re-verified independently (three verdicts each) and did not survive. **Nothing below is
carried into `BUG-TRACKER.md`**, except where noted as re-scoped.

| dropped claim | why |
|---------------|-----|
| `strict_default_block` flags 31/31 harmless and 0/49 dangerous tools | Mechanism reproduces exactly, but the caught set includes `execute_sql`, `wipe_device_enrollment` and `erase_customer_pii_on_request`, so "all harmless" is false and "anti-correlated with risk" is risk-**blind**. Shipped effect is monitor → 0 blocked calls. The behaviour is disclosed verbatim in the control's own caveat, rendered inline in the console, and asserted by a test. 49 of the claimed 58 board rows were the harness's own traffic |
| `rate_limit_exceeded` is the largest source of blocked traffic in chatbot-prod | The 108-in-an-hour figure could not be re-measured (token invalid on re-verify) and is contradicted by `/metrics`, which shows 11 blocked calls total in chatbot-prod's lifetime and no `cmp-*` class anywhere. The "silent floor" premise is false — `rate_limit` is a first-class per-namespace setting exposed in the console. *Re-scoped into BUG-021.* |
| The deployed baseline in analytics/default is the raw preset "all controls at deny" | The chart writing the raw preset is by design; raw-at-audit and compiled-all-monitor are behaviourally identical (both `audit`, call proceeds); "all controls at deny" is wrong (12 pure block, 1 block+escalate, 1 audit-only). *Re-scoped into BUG-008.* |
| `system-health` surfaces the operational drops that are actually happening | The endpoint is deliberately scoped to infrastructure verdicts, pinned by an equality test whose rationale is *"A policy doing its job is not an outage"*; the evidence string never claims no drops occurred. *Re-scoped into BUG-028 for the three engine-minted verdicts nobody defended.* |
| The first PUT permanently flips the baseline from audit to block, with no way back | The flip is inert (the module it writes has zero `blocks[]` heads); no writer ever inherits a stored mode (`enforcement_mode = EXCLUDED.enforcement_mode`, and the controller requires `spec.enforcementMode`); and `DELETE …?confirm_managed=true` plus `PUT /settings` are documented ways back |
| Before the first PUT, `GET /baseline/controls` describes the DB table, not the deployed policy | Same substance as the above; refuted on blast radius (0 blocked calls in the default configuration). *Re-scoped into BUG-008.* |
| chatbot-prod's only real workload class bypasses every baseline control, even at deny | Highest-priority-outright precedence is documented in `baseline_router.py:41-44` (*"a floor that any authored policy can outrank, not a ceiling"*), `docs/concepts.md:240-253` and a passing test. The offending `demo_default_allow` body exists nowhere in the repo — it is demo dressing on the cluster |
| Namespace-tier policies are in-memory only, invisible to every read API, silently evicted | Enforcement and all three read APIs read the same `loader._policies`; `/policies/effective` literally calls `_collect_candidates`. `create()` persists to Postgres, `warm_cache()` rehydrates unfiltered, `_update_memory` is additive. Residual: the ns tier alone lacks the `load_from_db` self-heal |
| A namespace-tier scope can decide evaluations while invisible and absent from the DB | The 404 proves the key was absent from memory at read time, i.e. it could not have been deciding then. Reproduced the same symptom from the eval cache with zero policies loaded |
| `GET /baseline/controls` reported a state that did not match the deployed artifact | Duplicate of the two rows above; refuted on the same grounds |
| `scope_violation_dangerous_tool` can never appear in the compliance view, in any namespace | On an untouched namespace its guard is a strict subset of a `blocks["strict_default_block"]` guard, so it never wins the resolver and emits nothing; the same traffic is visible under `strict_default_block`. The invisibility is real only post-PUT, where it applies to **all 14** controls (BUG-002), not one |
| In an audit-baseline namespace `blocked` is structurally 0 and the tile relabels | Two different tiers were conflated (per-policy mode vs namespace posture); `blocked` is never structurally 0 because `trust_frozen`/`rate_limit_exceeded` stay hard. *Re-scoped into BUG-003.* |
| Gate-A carry-over catalog is per-process (as a multi-instance gateway problem) | Shipped placement is a sidecar with one client per process; default bind is `127.0.0.1`; the injector emits stdio only; a cold instance re-derives the verdict at its own `tools/list` from the shared pin store. *Re-scoped into BUG-019 as restart amnesia + rug-pull window.* |
| MCP pin state is per-process, so 8 processes would disagree | 8 real processes agreed on one digest; `build_store('control-plane','')` raises; the webhook stamps `NRVQ_MCP_PIN_STORE=control-plane` into every injected sidecar |
| `mcp-server-identity-unattested` is adjudicated | The guardrail is opt-in and default-off, and the product reports the gap rather than overclaiming (`_CONDITIONAL_CATEGORIES`, `applicable=false`, `unexercised_reachable`, console renders "— not enabled here") |
| `resources-read-uri-gate` has a URI gate | Confirmed there is none — the claim was that a gate exists. The vector's own catalogue entry says *"what is missing is a RULE, not a mechanism"* |
| The local adversarial harness passes | It does not — EXIT=1, 19/22 |
| The 3 Gate B failures are an environment artifact | They are not — they survive a reachable, healthy engine |
| A destructive MCP tool call is blocked by policy and never executed | It is not — it executes. Forward-on-audit is deliberate and test-pinned; the stale artifact is the harness and the "22/22" docs. *Re-scoped into BUG-018.* |
| `trust_frozen` is produced only by an explicit admin freeze | Refuting this claim **confirms** BUG-007 |
| Half the API replicas reject a valid admin token (401) | The 401 leg never reached a pod: port 18081 was held by a local uvicorn dev server since ~4h before the token was issued, and `kubectl port-forward` half-binds IPv6-only on a collided port while `curl http://127.0.0.1` forces IPv4 |

---

## 10. Cluster restoration

Every agent restored what it changed, verified by re-read.

| namespace | what changed | final state |
|-----------|--------------|-------------|
| `chatbot-prod` | ~39 `PUT /baseline/controls` (per-control cycles, all-deny, all-off, partial maps) + one `POST /policies` to restore the baseline bytes | Deviation rows back to **zero**; `__baseline__` restored byte-identically (sha256 `8e175c0425e5ed9d`, 40028 bytes, priority 1, `enforcement_mode=audit`); 14/14 triggers reproduce pre-test rule_ids. Version counter advanced 65 → 108 (append-only, content identical) |
| `default` | `PUT` promoting `pii_detection`/`deny_shell_execution` to deny, then restored from a captured backup in a `finally` block | `{off:0, monitor:14, deny:0}`, verified twice against `default_effects_BACKUP.json` |
| `analytics` | one temporary class policy `cmp-denyproof307481` | Deleted; listing matches pre-test exactly (4 rows, same priorities and modes) |
| `all` (sentinel) | phantom `(all, __baseline__)` created by the adversarial test | `PUT effects={}` then `DELETE …?confirm_managed=true` → `{"deleted": true}`; no `all` rows remain |
| policy tiers | 8 scopes created across `default`/`chatbot-prod` (class, ns-tier, workload-tier, cross-ns, guardrail) | All deleted; all three namespace listings match pre-test; guardrail delete confirmed propagated to the peer replica |
| `norviq`, `analytics` config | untouched | — |

**Not restorable, by design:** append-only audit rows and graph snapshots from ~7,000 `/evaluate`
calls under `cmp-*` classes with real framework names. Per the naming rule these are deliberately
**not** hidden by `synthetic.py`, so they appear in KPIs, coverage, compliance and tools-observed
as real governed traffic. Classes to prune if unwanted: `cmp-support`, `cmp-shelltest`,
`cmp-corpus-*`, `cmp-prec-*`, `cmp-drop-inv-a`, `cmp-ratelimit-probe`, `cmp-readexempt-probe`,
`cmp-final-probe`, `cmp-mcp-probe`, `cmp-hammer-a`, `cmp-window-*`, plus tools suffixed `307481`.
Two `RedTeamRun` records also remain. A namespace `cmpfresh307481` now holds 6 allow rows and will
appear in namespace pickers until they age out.

**No cluster mutations were made:** no helm, no `kubectl apply/delete/patch/scale/restart`, no
docker push, no git commit/push/tag, no `kubectl exec`, no Secret reads, no credential minting. The
pre-minted admin token was read from `/tmp/nrvq-signin-token.txt` and never printed.

**Outstanding environment issue:** a concurrent session rewrote `ns/chatbot-prod`'s baseline
controls throughout the campaign and left them at `deny ×14` at one point during the MCP agent's
run. That churn was not authored by any agent here and was deliberately not reverted.
