# F022-F024 Final Review — Priority Fix Verification + Full Red Team
# Usage: claude "$(cat prompts/reviews/F022-review.md)" --print 2>&1 | tee .reviews/F022-final.md

FINAL REVIEW of F022-F024 — PRIORITY ENFORCEMENT FIX + RED TEAM RECHECK.

This is the 5th review. C-1 (priority not enforced at runtime) has been reported 4 times and was supposedly fixed. VERIFY THE FIX IS REAL.

Read ALL of these files before answering:
- norviq/engine/policy_loader.py
- norviq/engine/evaluator.py
- norviq/api/routers/policies.py
- webhook/controller.go
- tests/engine/test_priority_enforcement.py
- helm/norviq/templates/resource-quota.yaml
- helm/norviq/templates/crd-rbac.yaml
- helm/norviq/templates/controller-rbac.yaml
- crds/norviq.io_nrvqpolicies.yaml
- crds/norviq.io_nrvqclasses.yaml
- crds/norviq.io_nrvqconfigs.yaml

═══════════════════════════════════════════════════
SECTION 0: C-1 PRIORITY FIX — TRACE THE FULL PATH
═══════════════════════════════════════════════════

Trace the ENTIRE lifecycle of a policy with priority. Every step must work.

Step 1: CRD creation
- User applies NrvqPolicy with priority: 499
- Does the CRD schema accept priority field? (check nrvqpolicies.yaml)
- Report: PASS or FAIL with file:line

Step 2: Controller extracts priority
- Does controller.go extract priority from the CRD spec?
- Does it pass priority in the API sync payload?
- Report: PASS or FAIL with file:line

Step 3: API receives priority
- Does PolicyCreate model in policies.py have priority field?
- Does create_policy() pass priority to loader.create()?
- Report: PASS or FAIL with file:line

Step 4: PolicyLoader stores priority
- Does loader.create() accept priority parameter?
- Does _policies dict store priority alongside rego?
- Is the structure {"rego": str, "priority": int} (not just str)?
- Report: PASS or FAIL with file:line

Step 5: Evaluator collects ALL matching policies
- Does evaluate() collect namespace baseline + agent class + workload policies?
- Does it look up __cluster__:__baseline__ key?
- Does it look up {namespace}:__baseline__ key?
- Does it look up {namespace}:{agent_class} key?
- Report: PASS or FAIL with file:line

Step 6: Evaluator evaluates EACH candidate
- Does evaluate() call _evaluate_single() for each candidate?
- Report: PASS or FAIL with file:line

Step 7: Precedence resolution
- Does _resolve_precedence() sort by priority DESC?
- On same priority, does it pick most restrictive (block > escalate > audit > allow)?
- Does it return the winner?
- Report: PASS or FAIL with file:line

Step 8: Integration test proves it works
- Does test_cluster_baseline_beats_tenant_policy exist?
- Does it create baseline with priority 900 (block)?
- Does it create tenant policy with priority 100 (audit)?
- Does it assert decision == "block"?
- Does test_higher_priority_wins_same_namespace exist?
- Report: PASS or FAIL with file:line

VERDICT ON C-1: Is priority enforcement ACTUALLY working end-to-end?
Answer: FIXED or STILL BROKEN (with exact step that fails)

═══════════════════════════════════════════════════
SECTION 1: H-1 RESOURCE QUOTA COVERAGE
═══════════════════════════════════════════════════

- Does resource-quota.yaml cover all tenant namespaces or only enumerated ones?
- Is there a ValidatingAdmissionPolicy blocking NrvqPolicy in uncapped namespaces?
- OR is there documentation requiring operators to add every namespace?
- Is the gap acceptable with documentation, or does it need enforcement?
- Report: PASS or FAIL with file:line

═══════════════════════════════════════════════════
SECTION 2: H-2 ALLOW-ALL REGO BYPASS
═══════════════════════════════════════════════════

- With C-1 fixed, does a cluster baseline (priority 900, block) beat a tenant allow-all (priority 100)?
- Is validateRego() still called?
- Is the residual risk (data-dependent unreachable block) now mitigated by baseline priority?
- Report: PASS or FAIL

═══════════════════════════════════════════════════
SECTION 3: M-3 FINALIZER RETRY
═══════════════════════════════════════════════════

- Does addFinalizerWithRetry exist in controller.go?
- Does it retry on IsConflict (up to 3 times)?
- Is it called from handlePolicy?
- Report: PASS or FAIL with file:line

═══════════════════════════════════════════════════
SECTION 4: POLICY DATA STRUCTURE CHANGE
═══════════════════════════════════════════════════

The _policies dict changed from dict[str, str] to dict[str, dict].
Verify EVERY place that reads _policies is updated:

- policy_loader.py: all reads use _policies[key]["rego"]?
- evaluator.py: all reads use _policies[key]["rego"]?
- API routers/policies.py: all reads handle new structure?
- No KeyError or TypeError possible from old code reading new structure?
- Report EVERY location: PASS or FAIL with file:line

═══════════════════════════════════════════════════
SECTION 5: CACHE INVALIDATION
═══════════════════════════════════════════════════

- Does policy_loader.create() delete Redis policy cache on update?
- Does it delete eval cache entries for the updated scope?
- Does it publish invalidation event via Redis pub/sub?
- Does start_invalidation_listener() exist and subscribe?
- Is eval cache TTL reduced to 5s (not 60s)?
- Is there a version stamp on cached policies?
- Report each: PASS or FAIL with file:line

═══════════════════════════════════════════════════
SECTION 6: RED TEAM RE-CHECK (condensed)
═══════════════════════════════════════════════════

For each attack vector, answer CLOSED or OPEN:

| # | Attack | Status |
|---|--------|--------|
| 1 | Rego injection (allow-all bypass) | ? |
| 2 | Sidecar image swap | ? |
| 3 | Enforcement disable | ? |
| 4 | Priority escalation (tenant beats admin) | ? |
| 5 | Namespace escape | ? |
| 6 | Wildcard agent class | ? |
| 7 | Rego ReDoS | ? |
| 8 | Mass delete | ? |
| 9 | Status manipulation | ? |
| 10 | CRD flood | ? |

═══════════════════════════════════════════════════
SECTION 7: GO VERSION
═══════════════════════════════════════════════════

- webhook/go.mod: go version is 1.26 (not 1.22)?
- webhook/Dockerfile: FROM golang:1.26-alpine?
- .github/workflows: go-version is 1.26?
- k8s.io packages compatible with Go 1.26?
- go test passes with no version errors?
- Report each: PASS or FAIL with file:line

═══════════════════════════════════════════════════
SECTION 8: STALE CODE
═══════════════════════════════════════════════════

- resolve_precedence() is CALLED (not dead code anymore)?
- No commented-out code?
- No unused imports?
- No TODO/FIXME without tracking?
- No fmt.Println?
- listPolicies removed if unused?
- Report each: PASS or FAIL with file:line

═══════════════════════════════════════════════════
SECTION 9: CLUSTER SAFETY RECHECK
═══════════════════════════════════════════════════

- If all Norviq CRDs deleted → cluster keeps running? (YES/NO)
- If controller crashes → existing pods keep running? (YES/NO)
- If bad NrvqPolicy applied → kube-apiserver crash? (YES/NO — must be NO)
- If priority enforcement fails → what happens? (describe fallback)
- Can any Norviq component cause node NotReady? (YES/NO — must be NO)
- Can any Norviq component restart kube-system pods? (YES/NO — must be NO)

═══════════════════════════════════════════════════
SECTION 10: TEST COVERAGE
═══════════════════════════════════════════════════

- test_priority_enforcement.py exists?
- test_cluster_baseline_beats_tenant_policy passes conceptually?
- test_higher_priority_wins_same_namespace passes conceptually?
- webhook/controller_test.go covers CRD add/update/delete?
- webhook/controller_test.go covers cross-namespace rejection?
- webhook/controller_test.go covers invalid rego rejection?
- webhook/controller_test.go covers finalizer retry?
- Report each: PASS or FAIL with file:line

═══════════════════════════════════════════════════
SUMMARY
═══════════════════════════════════════════════════

1. C-1 PRIORITY: FIXED or STILL BROKEN?
2. Total PASS / FAIL count
3. CRITICAL issues remaining (list each)
4. HIGH issues remaining (list each)
5. MEDIUM issues remaining (list each)

RED TEAM FINAL VERDICT:
- SAFE TO DEPLOY: Zero critical, all attack vectors closed
- FIX THEN DEPLOY: List what must be fixed
- DO NOT DEPLOY: Explain why

For every FAIL: exact file:line and specific fix with code.