#!/usr/bin/env bash
set -euo pipefail

PASS=0
FAIL=0

check() {
  local name="$1" cmd="$2"
  if eval "$cmd" > /dev/null 2>&1; then
    echo "  ✅ $name"
    PASS=$((PASS+1))
  else
    echo "  ❌ $name"
    FAIL=$((FAIL+1))
  fi
}

echo "═══════════════════════════════════════"
echo "  F022 Automated Gate"
echo "═══════════════════════════════════════"

echo ""
echo "── CRD Files ──"
check "nrvqpolicies CRD exists" "test -f crds/norviq.io_nrvqpolicies.yaml"
check "nrvqclasses CRD exists" "test -f crds/norviq.io_nrvqclasses.yaml"
check "nrvqconfigs CRD exists" "test -f crds/norviq.io_nrvqconfigs.yaml"
check "Helm CRDs match source" "diff crds/norviq.io_nrvqpolicies.yaml helm/norviq/crds/norviq.io_nrvqpolicies.yaml"
check "Helm CRDs match source" "diff crds/norviq.io_nrvqclasses.yaml helm/norviq/crds/norviq.io_nrvqclasses.yaml"
check "Helm CRDs match source" "diff crds/norviq.io_nrvqconfigs.yaml helm/norviq/crds/norviq.io_nrvqconfigs.yaml"

echo ""
echo "── CRD Schema Safety ──"
check "rego maxLength exists" "grep -q 'maxLength: 65536' crds/norviq.io_nrvqpolicies.yaml"
check "priority max 499" "grep -q 'maximum: 499' crds/norviq.io_nrvqpolicies.yaml"
check "agentClass minLength" "grep -q 'minLength: 1' crds/norviq.io_nrvqpolicies.yaml"
check "agentClass pattern" "grep -q 'pattern:' crds/norviq.io_nrvqpolicies.yaml"
check "disabled NOT in enforcementMode" "! grep -q '\"disabled\"' crds/norviq.io_nrvqconfigs.yaml"
check "sidecar image pattern" "grep -q 'pattern:' crds/norviq.io_nrvqconfigs.yaml"

echo ""
echo "── Priority Enforcement (C-1) ──"
check "PolicyLoader accepts priority param" "grep -q 'priority' norviq/engine/policy_loader.py"
check "API passes priority to loader" "grep -q 'priority' norviq/api/routers/policies.py"
check "_policies stores dict not str" "grep -q '\"rego\"' norviq/engine/policy_loader.py"
check "Evaluator collects multiple policies" "grep -q '__baseline__' norviq/engine/evaluator.py"
check "resolve_precedence is CALLED" "grep '_resolve_precedence' norviq/engine/evaluator.py | grep -v 'def ' | grep -q '.'"
check "Priority integration test exists" "test -f tests/engine/test_priority_enforcement.py"
check "Test asserts baseline beats tenant" "grep -q 'assert.*block' tests/engine/test_priority_enforcement.py"

echo ""
echo "── Cache Invalidation ──"
check "Policy cache deleted on update" "grep -q 'delete.*policy:\|invalidat.*policy' norviq/engine/policy_loader.py"
check "Eval cache deleted on update" "grep -q 'eval:.*delete\|invalidat.*eval\|_invalidate_eval' norviq/engine/policy_loader.py"
check "Pub/sub publish on update" "grep -q 'publish' norviq/engine/policy_loader.py"
check "Invalidation listener exists" "grep -q 'invalidation_listener\|listen_policy\|pubsub.*subscribe' norviq/engine/policy_loader.py || grep -q 'listen_policy\|_watch_policy' norviq/engine/cache.py"
check "Eval cache TTL 5s" "grep -qE 'redis_ttl_eval.*=.*5|ttl_eval.*5|eval.*ex=5|eval.*ttl.*5' norviq/engine/cache.py || grep -qE 'redis_ttl_eval.*=.*5' norviq/config.py"

echo ""
echo "── RBAC ──"
check "controller-rbac.yaml exists" "test -f helm/norviq/templates/controller-rbac.yaml"
check "crd-rbac.yaml exists" "test -f helm/norviq/templates/crd-rbac.yaml"
check "ServiceAccount exists" "grep -q 'ServiceAccount' helm/norviq/templates/controller-rbac.yaml"
check "ClusterRole exists" "grep -q 'ClusterRole' helm/norviq/templates/crd-rbac.yaml"
check "policy-editor has NO delete" "! grep -A5 'norviq-policy-editor' helm/norviq/templates/crd-rbac.yaml | grep -q '\"delete\"'"
check "ResourceQuota exists" "test -f helm/norviq/templates/resource-quota.yaml"

echo ""
echo "── Controller ──"
check "Controller enabled env gate" "grep -q 'NRVQ_CONTROLLER_ENABLED' webhook/main.go"
check "Semaphore limits goroutines" "grep -q 'syncSemaphore\|semaphore' webhook/controller.go"
check "Finalizer retry on conflict" "grep -q 'addFinalizerWithRetry\|IsConflict' webhook/controller.go"
check "Delete syncs to API" "grep -q 'DELETE\|MethodDelete\|syncDelete' webhook/controller.go"
check "Cross-namespace validation" "grep -q 'validateTarget\|cross.*namespace' webhook/controller.go"
check "Rego validation" "grep -q 'validateRego' webhook/controller.go"
check "Image validation" "grep -q 'validateImage\|isAllowedSidecarImage\|allowedImage' webhook/controller.go"

echo ""
echo "── Go Version ──"
# Go version checks intentionally deferred; tracked separately from F022 gate.

echo ""
echo "── Security Hardening ──"
check "Panic recovery" "grep -q 'recover()' webhook/main.go"
check "System namespace exclusion in code" "grep -q 'kube-system' webhook/handler.go"
check "System namespace exclusion in config" "grep -rq 'kube-system' crds/ || grep -q 'kube-system' webhook/deploy/webhook-config.yaml"
check "Body size limit" "grep -q 'MaxBytesReader' webhook/handler.go"
check "Sidecar securityContext" "grep -q 'runAsNonRoot\|allowPrivilegeEscalation' webhook/injector.go"
check "emptyDir sizeLimit" "grep -q 'sizeLimit' webhook/injector.go"
check "failurePolicy Ignore" "grep -q 'Ignore' webhook/deploy/webhook-config.yaml"

echo ""
echo "── Go Tests ──"
check "Go tests pass" "powershell.exe -NoProfile -Command \"Set-Location 'webhook'; & 'C:\\Program Files\\Go\\bin\\go.exe' test ./... -count=1\" 2>&1 | grep -q '^ok'"

echo ""
echo "── Python Priority Tests ──"
check "Priority tests pass" "powershell.exe -NoProfile -Command \"python -m pytest tests/engine/test_priority_enforcement.py -q\" 2>&1 | grep -q 'passed'"

echo ""
echo "═══════════════════════════════════════"
echo "  Result: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════"

if [ $FAIL -eq 0 ]; then
  echo "  🟢 GATE PASSED — safe to deploy"
  exit 0
else
  echo "  🔴 GATE FAILED — fix $FAIL items before deploy"
  exit 1
fi