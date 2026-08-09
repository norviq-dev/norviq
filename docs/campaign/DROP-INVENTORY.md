# DROP INVENTORY — rev 30 (allow-by-default)

**Question this document answers:** in a build whose entire premise is *nothing is dropped unless a
customer policy asks for it*, what can still drop a call, at what measured rate, and does monitor
mode soften it?

Campaign: 8 agents, live AKS (`kube context norviq`), API port-forwarded on `127.0.0.1:8080`,
namespaces `chatbot-prod`, `analytics`, `default`. ~7,000 real `/evaluate` calls under `cmp-*`
agent classes with real framework names (so nothing was hidden by `norviq/api/synthetic.py`).

**Headline:** the allow-by-default flip works for the policy path. Zero hard blocks in 2,850
state-correlated calls in a confirmed-monitor window. The drops that remain are *infrastructure*
drops, and **5 of 13 non-policy rule_ids can still refuse a call in a namespace configured to
interrupt nothing** — three of them because they never reach the softening code at all.

---

## A. Non-policy drop paths (no customer policy asked for these)

Legend for **Softened by monitor?** — measured either live on the cluster or by executing the
shipped evaluator in-process with `posture={"monitor": True}`.

| # | rule_id | Can drop? | Measured rate | Softened by monitor? | Evidence |
|---|---------|-----------|---------------|----------------------|----------|
| 1 | `rate_limit_exceeded` | **YES** | **15 / 75** in a single-identity burst (calls 1-60 allow, 61-75 block). **87 / 200 = 43.5%** of an unpaced realistic support corpus. 108 rows in one hour namespace-wide in `chatbot-prod`. | **NO** — exempt by design (`monitor_exempt_rate_limit=True`, `config.py:83`) | `evaluator.py:341-351`, `config.py:169-170` |
| 2 | `trust_frozen` | **YES** | Not observed live (`GET /agents?namespace=all` → 165 agents, **0 frozen**). Fires on **100%** of calls when the Redis freeze read *errors*. | **NO** — permanently exempt (`_BASE_POSTURE_EXEMPT_RULES`) | `trust/calculator.py:263-269`, `evaluator.py:946-950` |
| 3 | `evaluator_timeout` | **YES** | Not driven live (would need a >2.0s OPA eval on a shared cluster). Hard block in-process. | **NO — and rev 30 claims it is.** Minted in the `except asyncio.TimeoutError` handler *after* `_apply_posture` | `evaluator.py:604-616` |
| 4 | `evaluator_fallback` | **YES** | Not driven live. Hard block in-process. | **NO** — same bypass (`except Exception`) | `evaluator.py:630-642` |
| 5 | `invalid_spiffe_identity` | **YES** | **3/3 live.** `"not-a-spiffe-id"`, `"http://evil/ns/x/sa/y"`, `""` → `block`, `trust_score 0.0` | **NO** — same bypass (`except InvalidSpiffeIdentity`) | `evaluator.py:617-629`, `:2383-2386` |
| 6 | `evaluator_error` | no | — | **YES** → `audit / monitor_would_block:evaluator_error` | executed in-process |
| 7 | `policy_load_pending` | conditional | Not driven live (needs a cold replica; restarting a pod is a forbidden mutation) | **YES** → `audit / monitor_would_block:policy_load_pending` | `evaluator.py:1743-1747` |
| 8 | `evaluator_invalid_payload` | no (not externally drivable) | Malformed `/evaluate` bodies 422 at the FastAPI layer and never reach the evaluator; the rego shape that mints it is rejected by the policy validator (422) | **YES** | `evaluator.py:1829/1903/1913` |
| 9 | `no_policy_loaded` | **cannot fire** | **0/3 namespaces.** `chatbot-prod`, `analytics`, `default` with no class policy → `allow / default_allow` | n/a | `evaluator.py:1748-1752`; cm `NRVQ_NO_POLICY_DECISION=allow` |
| 10 | `engine_rejected_request` | **YES** (PEP-side) | Not executed (needs an injected sidecar). Preconditions proven live: bad bearer → 401, no header → 401, malformed body → 422, HTTP limiter → 429 at 3000/60s | **NO** — decided in the SDK before the engine's posture ever applies | `sdk/client/engine.py:145-156`, `sidecar/remote_evaluator.py:215` |
| 11 | `thin_proxy_fail_open` / `engine_unavailable_fallback` | no (allows) | `NRVQ_SDK_FALLBACK_MODE=allow` confirmed on `norviq-webhook` and on all 3 injected sidecars | n/a (allow) | `config.py:103`, `sidecar/remote_evaluator.py:216-236` |
| 12 | `thin_proxy_fail_closed` | conditional | Only on a 4xx refusal, or if `NRVQ_SDK_FALLBACK_MODE` is typo'd (unrecognised mode coerces to `block` — the whole data plane fails closed) | **NO** | `sdk/client/engine.py:186-217` |
| 13 | Baseline control at `deny` | **YES — but a policy asked** | See §B. This is the intended path; the problem is *what* it drops | `webhook/presets/strict.rego` |

### The three that matter most

**#3/#4/#5 — the softening bypass (BLOCKER).** `_apply_posture` is reached from exactly three call
sites (`evaluator.py:595`, `:716`, `:733`), all inside the `try`. The three exception handlers at
`:604-642` mint their decisions and return them directly. So a namespace with
`enforcement_mode=audit` — whose entire contract is *evaluate everything, interrupt nothing* —
still drops customer traffic on an OPA timeout, on any unexpected engine exception, and on a
malformed identity. The rev-30 statement lists `evaluator_timeout` as softened. It is not.

This is latent on this cluster only because **no namespace is actually in monitor mode**:
`GET /api/v1/settings` returns `enforcement_mode=block` for `chatbot-prod`, `analytics`, `default`
and `norviq`. The chart's `enforcementMode: audit` is `baselineClusterPolicy.enforcementMode` — a
*per-policy* mode consumed by `_apply_policy_mode` — not namespace posture, and the Redis posture
mirror is only written by `PUT /settings`. The first customer who turns monitor on gets a promise
the engine does not keep.

**#2 — `trust_frozen` on a cache error.** `_safe_frozen_only` returns `True` when the Redis GET
raises. That `True` becomes `category="frozen"` becomes a hard block with the reason *"Agent trust
frozen — all tool calls blocked"*. A Redis blip therefore refuses **100%** of traffic in every
namespace, including monitor-only ones, under a rule_id asserting an administrator did it on
purpose. No administrator did. The exemption's own justification (`evaluator.py:339-340`) is about
operator intent and does not cover this producer.

**#1 — `rate_limit_exceeded`.** The single biggest source of real dropped traffic measured in this
campaign. 60 non-read calls per 60s per SPIFFE id, keyed on the runtime SVID which has no pod
component — so it is a budget shared across every replica under one ServiceAccount. The exemption
is deliberate and documented (a resource control protecting the customer's own backend, with a
working read-prefix carve-out verified at 3/3). Two caveats: `NRVQ_RATE_LIMIT=6000` in the
ConfigMap maps to **no settings field** and is silently ignored (the code default of 60 stands),
and the ceiling *is* a per-namespace setting (`PUT /api/v1/settings`, range 1..100000) that the
console exposes — so "silent floor" overstates it, but "60/min is a functional limit, not a
runaway-agent signal" stands.

---

## B. Policy-path drops: what a customer gets if they follow the documented workflow

Under the shipped default every control is at `monitor`, so **nothing here drops today**. It is
inventoried because the controls page's own caveat text says *"Observe before promoting"*, and
promotion converts every row below into a hard block. Proven, not assumed: promoting
`pii_detection` and `deny_shell_execution` to `deny` in `ns/default` turned the identical
ISO-date and semicolon calls into `block`, then the change was restored.

| Trigger | Control reported | Measured rate | At `monitor` | At `deny` |
|---------|------------------|---------------|--------------|-----------|
| A `;` in ordinary English prose | `deny_shell_execution` | **60/60 = 100%** (same 60 sentences with `.` → 0/60) | audit, call proceeds | **blocks 100%** |
| A `\|` or a backtick in prose | `deny_shell_execution` | **30/30 = 100%** each | audit | blocks |
| A bare ISO-8601 date as a param value | `pii_detection` — *"PII (SSN) detected"* | **60/60 = 100%** across 10 key names; `2026-07-01T00:00:00Z` → 0/30 | audit | **blocks 100%** |
| `GB1234567`-shaped business ref | `pii_detection` — *"SSN"* | **60/60 = 100%**; `GB-1234567` → 0/30 | audit | blocks |
| Opaque alphanumeric identifier | `deny_shell_execution` (base64 fan-out) | **4.0% @8 chars → 32.0% @64 chars**, 362/2850 = **12.7%** overall. Pure-digit ids 0/150. | audit | blocks 12.7% of id lookups |
| Any tool name starting `delete_ drop_ truncate_ destroy_ wipe_ purge_ erase_`, or `execute_sql` | `strict_default_block` | 31/31 of a name-matching set; 0/49 of a "dangerous verbs" set with identical params | audit | blocks on name alone |

**Aggregate:** **40 of 200 calls (20%)** in a realistic support-desk corpus were recorded as
non-compliant. Essentially none are security events. The customer-facing compliance board for
`chatbot-prod` reads `deny_shell_execution 460`, `pii_detection 128`, `strict_default_block 58` —
its three largest rows are all false positives from ordinary support traffic.

**Note on `strict_default_block`:** the "anti-correlated with risk" framing was refuted on
re-verification — the caught set *does* include `execute_sql` and `wipe_device_enrollment`, and
the 31/0 split is partly an artefact of sending inert params. The control is risk-**blind**, not
inversely correlated, and the behaviour is disclosed verbatim in its shipped caveat.

---

## C. Configuration paths that convert §B into live drops

1. **`baselineClusterPolicy.enforcementMode: block`.** Documented in `values.yaml` as the way to
   "restore the old posture cluster-wide". In `analytics` and `default` the materialized
   `__baseline__` module is the **raw strict preset** (22 `blocks[]`, 1 `escalates[]`, 1
   `audits[]`, no compiler marker) and is only non-blocking because the policy row carries
   `enforcement_mode=audit`. Flip that one flag and 22 deny heads go hard across every tenant
   namespace while `GET /baseline/controls` continues to report `monitor ×14`.
   *(Contested: re-verification argued the chart and controller always write rego and mode
   together, so an upgrade cannot inherit `block`. The console/artifact divergence is real; the
   inheritance hazard is not.)*
2. **A class policy outranking the baseline.** Base tiers resolve highest-priority-outright, and
   any authored policy defaults to priority 100 vs the baseline's 1. This is documented, intended
   precedence — but it means promoting a control to `deny` is a **no-op** for any class that has
   its own policy.
3. **An audit-mode policy at higher priority.** Introducing a priority-300 policy in audit mode
   turned an existing priority-100 hard block into `audit` and the call proceeded. The documented
   safe way to trial a rule is the action that switches off the enforcing rule beneath it.
4. **A typo'd `NRVQ_SDK_FALLBACK_MODE`.** Any unrecognised value coerces to `block` in
   `engine.py:186-217` — the entire data plane fails closed.

---

## D. Observability: drops that happen and are not surfaced

| Surface | Gap |
|---------|-----|
| `GET /system-health` | `_INFRA_RULE_IDS` omits `rate_limit_exceeded`, `trust_frozen`, `invalid_spiffe_identity`, `evaluator_timeout`, `evaluator_fallback`. Returned `{"status":"ok","issues":[]}` while 108 rate-limit refusals sat in the trailing hour. *(Contested: re-verification argues the endpoint's scope is deliberately infrastructure-only and its evidence string never claims "no drops". The omission of the three engine-minted verdicts — timeout/fallback/invalid-identity — was not defended by anyone.)* |
| `GET /audit/stats` | `engine_errors` uses an exact `rule_id == "evaluator_error"` match, so a *softened* engine fault reads 0 and is simultaneously counted as a policy would-block. `audit.py:249-250`. |
| `GET /policy-compliance` | A control at `monitor` emits a **bare** rule_id, which `_strip_prefix` drops. Measured: 11 calls → count moved 2 → 2. Over one hour in `ns/default`, 33 would-block calls, **7 reported**. |
| Overview KPI tile | Never relabels: `monitorScope` reads `namespace_settings.enforcement_mode` (`block`), so 678 would-blocks are fetched and never rendered while the tile shows `Blocked 184`. |
| Audit log UI | `AuditLog.tsx` only special-cases `monitor_would_block:`; **270/270** would-block rows on this deployment carry the other prefix and render raw. |

---

## E. What was NOT measured

- `evaluator_timeout` / `evaluator_error` **driven live** against the deployed OPA. Forcing a >2s
  evaluation needs a deliberately expensive rego on a shared cluster.
- `policy_load_pending` live — needs an API replica restart (forbidden mutation).
- Sidecar verdicts (`thin_proxy_fail_open` / `_closed`, `engine_rejected_request`) — need an
  engine outage or a sidecar restart. Code-level only.
- Trust-score decay to `escalate_low_trust` under ordinary high-entropy traffic. Observed
  `cmp-support` trust drifting 0.445-0.955 with `param_entropy=1.0`, but could not separate decay
  caused by legitimate traffic from decay caused by the harness's own earlier rate-limit
  violations (`violation_count` reached 96).
- Non-admin `403` on `PUT /baseline/controls` — no non-admin credential exists and minting is
  prohibited. 401 paths verified instead.
- Cert rotation — no agent exercised it.

---

## F. Environment caveats that bound every number above

- A **concurrent writer** rewrote `ns/chatbot-prod`'s baseline controls throughout the campaign
  (`__baseline__` v67 → v101+, controls observed at `off ×14`, `monitor ×14`, `deny ×14` at
  different times). An early uncorrelated 1,900-call sweep recorded 25 `block` decisions; a
  state-correlated re-run over 2,850 calls recorded **0**. Any `chatbot-prod` figure needs a
  timestamp to be interpretable. `analytics` and `default` re-read stable.
- The evaluator's own 60/60s throttle silently corrupts any unpaced sweep. All rate tables here
  were produced through a token-bucket governor with a background poller over
  `GET /baseline/controls`, discarding any call not made inside a confirmed control-state window.
