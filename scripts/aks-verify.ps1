# AKS Verification - day9-local-dev-verify Branch

Use these commands to verify the local dev setup changes work on AKS before merging to main.

===================================================
PHASE 1 - Pre-verify (no AKS impact yet)
===================================================

Confirm the branch is pushed and CI built the image.

```powershell
# 1. Check branch on remote
git fetch origin
git log origin/day9-local-dev-verify --oneline -3

# 2. Wait for CI to build the image (3-5 min typically)
# Watch the GitHub Actions tab, or check Docker Hub:
$BRANCH_SHA = git rev-parse origin/day9-local-dev-verify | Select-Object -First 1
$IMAGE_TAG = "api-$($BRANCH_SHA.Substring(0,40))"
Write-Host "Looking for image: sanman97/norviq-engine:$IMAGE_TAG"

# 3. Verify image exists (will fail until CI completes)
docker pull sanman97/norviq-engine:$IMAGE_TAG 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Image ready" -ForegroundColor Green
} else {
    Write-Host "[WAIT] Image not built yet - wait for CI" -ForegroundColor Yellow
    exit 1
}
```

===================================================
PHASE 2 - Capture current AKS state (for rollback)
===================================================

```powershell
# 1. Save the CURRENT image (so we can roll back if needed)
$CURRENT_IMAGE = kubectl get deployment norviq-api -n norviq -o jsonpath='{.spec.template.spec.containers[0].image}'
Write-Host "Current AKS image: $CURRENT_IMAGE" -ForegroundColor Cyan
Write-Host "Save this - needed if rollback required." -ForegroundColor Yellow

# 2. Capture current attack test baseline
$env:NRVQ_API_URL = "http://localhost:8081"
$env:NRVQ_API_TOKEN = (python -c "from jose import jwt; print(jwt.encode({'sub':'admin','role':'admin'}, 'change-me-in-production', algorithm='HS256'))")

# 3. Port-forward current pods (BEFORE deploying new image)
Start-Job -ScriptBlock { kubectl port-forward svc/norviq-api 8081:8080 -n norviq } -Name "pf-baseline"
Start-Sleep -Seconds 3

# 4. Quick health check on current state
curl http://localhost:8081/healthz
Write-Host "Current state: HEALTHY" -ForegroundColor Green

# 5. Stop the baseline port-forward
Get-Job pf-baseline | Stop-Job; Get-Job pf-baseline | Remove-Job
```

===================================================
PHASE 3 - Deploy verification branch image
===================================================

```powershell
# 1. Deploy new image (without changing the deployment spec yet)
kubectl set image deployment/norviq-api api=sanman97/norviq-engine:$IMAGE_TAG -n norviq

# 2. Watch rollout
kubectl rollout status deployment/norviq-api -n norviq --timeout=120s

# 3. Check pod status
kubectl get pods -n norviq -l app=norviq-api

# Should show 1-2 pods Running
```

===================================================
PHASE 4 - Health + connectivity checks
===================================================

```powershell
# 1. Port-forward to new pods
Start-Job -ScriptBlock { kubectl port-forward svc/norviq-api 8081:8080 -n norviq } -Name "pf-verify"
Start-Sleep -Seconds 5

# 2. Healthz
$health = curl http://localhost:8081/healthz | ConvertFrom-Json
if ($health.status -eq "ok") {
    Write-Host "[OK] /healthz: OK" -ForegroundColor Green
} else {
    Write-Host "[FAIL] /healthz: FAILED - rollback now" -ForegroundColor Red
    Get-Job pf-verify | Stop-Job; Get-Job pf-verify | Remove-Job
    kubectl set image deployment/norviq-api api=$CURRENT_IMAGE -n norviq
    exit 1
}

# 3. Verify policy still in DB and applied
$policies = curl -H "Authorization: Bearer $env:NRVQ_API_TOKEN" http://localhost:8081/api/v1/policies | ConvertFrom-Json
if ($policies.Count -ge 1) {
    Write-Host "[OK] Policies persist: $($policies.Count) found" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Policies missing - DB connection or warm_cache broken" -ForegroundColor Red
    # Don't rollback yet - check logs first
    kubectl logs deployment/norviq-api -n norviq --tail=30
}

# 4. Verify Day 8 attack - delete_record should still block
$body = '{"tool_name":"delete_record","tool_params":{"table":"users","id":"123"},"agent_identity":{"spiffe_id":"spiffe://norviq/ns/default/sa/test","namespace":"default","agent_class":"customer-support"},"session_id":"verify-test","trust_score":0.95}'
$result = curl -X POST http://localhost:8081/api/v1/evaluate -H "Content-Type: application/json" -H "Authorization: Bearer $env:NRVQ_API_TOKEN" -d $body | ConvertFrom-Json

if ($result.decision -eq "block") {
    Write-Host "[OK] Attack test: delete_record blocked (rule: $($result.rule_id))" -ForegroundColor Green
} else {
    Write-Host "[FAIL] Attack test FAILED: got decision=$($result.decision)" -ForegroundColor Red
    Write-Host "Full result: $($result | ConvertTo-Json)" -ForegroundColor Yellow
}
```

===================================================
PHASE 5 - Full attack regression
===================================================

```powershell
# Run full Day 8 attack suite against the new pods
python -m pytest tests/attacks/ -v --tb=line 2>&1 | Tee-Object -Variable testResult | Select-Object -Last 5

# Extract pass count
$lastLine = $testResult | Select-Object -Last 1
if ($lastLine -match "(\d+) passed") {
    $passed = [int]$Matches[1]
    Write-Host "`nAttack pass count: $passed / 66" -ForegroundColor Cyan
    
    if ($passed -ge 60) {
        Write-Host "[OK] Regression OK ($passed >= 60 baseline)" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] Regression DETECTED ($passed < 60 baseline)" -ForegroundColor Red
        Write-Host "Rolling back to: $CURRENT_IMAGE" -ForegroundColor Yellow
        kubectl set image deployment/norviq-api api=$CURRENT_IMAGE -n norviq
        kubectl rollout status deployment/norviq-api -n norviq
        exit 1
    }
} else {
    Write-Host "[WARN] Could not parse test result - review manually" -ForegroundColor Yellow
    Write-Host $testResult
}
```

===================================================
PHASE 6 - Database schema check
===================================================

```powershell
# Verify the priority column exists (was the Day 8 blocker)
kubectl exec -it norviq-postgresql-0 -n norviq -- psql -U norviq -d norviq -c "\d policies" | Select-String "priority"

# Should show: priority | integer | default 100
# If missing, ALTER TABLE statement didn't execute on AKS pod
```

===================================================
PHASE 7 - SSL connection verification
===================================================

```powershell
# Check pod environment to confirm SSL mode set correctly
kubectl exec deployment/norviq-api -n norviq -- printenv | Select-String "NRVQ_DB_SSL"

# Should show: NRVQ_DB_SSL_MODE=require (from helm values.yaml)
# If shows nothing or "prefer" -> Helm chart not applied yet
# Fix: helm upgrade norviq helm/charts/norviq/ -n norviq
```

===================================================
PHASE 8 - Inspect logs for any startup errors
===================================================

```powershell
# Check last 100 lines for any ERROR or NRVQ-DB- codes
kubectl logs deployment/norviq-api -n norviq --tail=100 | Select-String "ERROR|NRVQ-DB-9|NRVQ-DB-DEBUG"

# Expected: only NRVQ-DB-DEBUG-1 through DEBUG-6 (clean startup)
# Bad: any NRVQ-DB-9 with error level, any traceback
```

===================================================
PHASE 9 - Cleanup port-forward
===================================================

```powershell
Get-Job pf-verify | Stop-Job; Get-Job pf-verify | Remove-Job
```

===================================================
PHASE 10 - Decision point
===================================================

If ALL of these are TRUE:

- [OK] /healthz returns ok
- [OK] Policies persist (>=1 found)
- [OK] delete_record returns block
- [OK] Attack tests >= 60/66
- [OK] priority column present in policies table
- [OK] NRVQ_DB_SSL_MODE=require in pod env (if Helm upgrade applied)
- [OK] No ERROR logs at startup

-> **MERGE TO MAIN:**

```powershell
git checkout main
git pull origin main
git merge day9-local-dev-verify
git push origin main

# Apply Helm changes (only if values.yaml was modified)
helm upgrade norviq helm/charts/norviq/ -n norviq

# Verify final state
kubectl rollout status deployment/norviq-api -n norviq
```

If ANY check fails:
- AKS already rolled back to $CURRENT_IMAGE (phases auto-rollback)
- Branch stays as `day9-local-dev-verify` for further debugging
- Do NOT merge to main
- Investigate logs:

```powershell
kubectl logs deployment/norviq-api -n norviq --tail=200
kubectl describe pod -n norviq -l app=norviq-api
```

===================================================
EMERGENCY ROLLBACK (manual)
===================================================

If anything broke and auto-rollback didn't fire:

```powershell
# Roll back to last known good image
kubectl set image deployment/norviq-api api=$CURRENT_IMAGE -n norviq

# Or use kubectl rollout undo (one step back)
kubectl rollout undo deployment/norviq-api -n norviq

# Watch rollback
kubectl rollout status deployment/norviq-api -n norviq

# Verify
kubectl port-forward svc/norviq-api 8081:8080 -n norviq
curl http://localhost:8081/healthz
```

===================================================
LOGGING - record this verification
===================================================

After completion, append to tests/.history/aks-verifications.md:

```markdown
## day9-local-dev-verify - YYYY-MM-DD

- Branch: day9-local-dev-verify
- Image: sanman97/norviq-engine:<sha>
- Attack tests: X/66
- Healthz: [OK]/[FAIL]
- Policy persistence: [OK]/[FAIL]
- delete_record block: [OK]/[FAIL]
- Schema: [OK]/[FAIL]
- SSL mode in pod: [OK]/[FAIL]
- Decision: MERGED | ROLLED_BACK | DEBUGGING
- Issues found: <list>
```

===================================================
TOTAL TIME ESTIMATE
===================================================

- Phase 1 (CI wait): 3-5 min
- Phase 2 (snapshot): 30 sec
- Phase 3 (deploy): 1-2 min
- Phase 4 (health): 30 sec
- Phase 5 (attacks): 2-3 min
- Phase 6-8 (verify): 1 min
- Total: ~10 min before merge decision

