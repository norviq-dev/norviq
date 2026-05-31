# F016 Master Review Prompt
# Usage: claude "$(cat prompts/reviews/F016-review.md)" --print 2>&1 | tee .reviews/F016.md

DEEP REVIEW of F016 Mutating Admission Webhook. Read specs/F016.md for the spec. Read ALL files in webhook/ directory.

You are a senior Go developer reviewing a Kubernetes admission webhook for production deployment. This webhook auto-injects sidecar containers into pods. Any bug here breaks the entire cluster.

## 1. CODE CORRECTNESS
- Does main.go start a TLS HTTPS server on the configured port?
- Does handler.go correctly parse AdmissionReview v1 requests?
- Does handler.go set Response.UID = Request.UID? (K8s requires this)
- Does handler.go return Allowed:true for non-Pod resources?
- Does handler.go check for norviq=enabled label correctly?
- Does handler.go skip injection if sidecar already present?
- Does injector.go produce valid JSON Patch (RFC 6902)?
- Does the patch add both container AND volume?
- Does the patch handle empty volumes array? (Pod might have no volumes)
- Are all error paths returning proper AdmissionResponse (not nil)?
- Report each: PASS or FAIL with file:line

## 2. MEMORY LEAKS & RESOURCE MANAGEMENT
- Is the request body read and closed properly (io.ReadAll + defer body.Close)?
- Are there any goroutine leaks (unbounded goroutines)?
- Is the HTTP server using timeouts (ReadTimeout, WriteTimeout, IdleTimeout)?
- Are there any unclosed resources (files, connections)?
- Is there any global mutable state that could cause race conditions?
- Does the handler allocate per-request (safe) or share state (unsafe)?
- Report each: PASS or FAIL with file:line

## 3. CONCURRENCY SAFETY
- Is the Handler struct safe for concurrent use? (multiple /mutate requests at once)
- Is the Injector struct safe for concurrent use?
- Any shared maps/slices being written without mutex?
- Is Config immutable after init? (should be)
- Report each: PASS or FAIL

## 4. SECURITY
- TLS: are both cert and key loaded correctly?
- TLS: is minimum TLS version set (should be TLS 1.2+)?
- Is there input validation on the AdmissionReview body size? (prevent OOM from huge payload)
- Is the sidecar image configurable via env (not hardcoded)?
- Are pod labels sanitized before use in patch?
- Could a malicious pod name/label cause JSON injection in the patch?
- Is failurePolicy set to Ignore in webhook config? (don't break cluster)
- Report each: PASS or FAIL with file:line

## 5. KUBERNETES CORRECTNESS
- Does MutatingWebhookConfiguration target only Pod CREATE operations?
- Does namespaceSelector use norviq-injection=enabled? (opt-in per namespace)
- Is admissionReviewVersions set to ["v1"]?
- Is sideEffects set to None?
- Is timeoutSeconds set (should be ≤10)?
- Does reinvocationPolicy prevent infinite loops?
- Does the webhook service correctly target port 443 → 8443?
- Is the CA bundle placeholder present for TLS verification?
- Report each: PASS or FAIL with file:line

## 6. SIDECAR INJECTION CORRECTNESS
- Does the injected container have the correct image from config?
- Does it expose the sidecar port (8282)?
- Does it set NRVQ_AGENT_CLASS env from pod label?
- Does it set NRVQ_HTTP_FALLBACK_PORT env?
- Does it have resource requests AND limits?
- Does it mount the shared emptyDir volume at /tmp?
- Does the volume use emptyDir (not hostPath — security risk)?
- Are resource limits reasonable (not too high, not too low)?
- Report each: PASS or FAIL with file:line

## 7. ERROR HANDLING
- What happens if TLS cert is missing? (should exit with NRVQ-WHK-4001)
- What happens if request body is empty? (should return 400)
- What happens if request body is not valid JSON? (should return 400)
- What happens if pod object is malformed? (should return Allowed:false with message)
- What happens if patch creation fails? (should return Allowed:false)
- Are all errors logged with NRVQ-WHK error codes?
- Does the webhook NEVER crash on bad input? (panic recovery?)
- Report each: PASS or FAIL with file:line

## 8. DOCKERFILE
- Multi-stage build (builder + runtime)?
- CGO_ENABLED=0 for static binary?
- Using distroless or scratch base image?
- Running as non-root user?
- Only the binary is copied (no source code in final image)?
- Image size should be <20MB — is it?
- Report each: PASS or FAIL with file:line

## 9. TESTING
- Test: pod without label → allowed, no patch?
- Test: pod with norviq=enabled → allowed, patch with sidecar?
- Test: pod with sidecar already present → no double injection?
- Test: non-Pod resource → allowed, no patch?
- Test: healthz returns 200?
- Test: malformed body → proper error response?
- Test: agent_class label passed to sidecar env?
- Are tests using httptest (not real server)?
- Report each: PASS or FAIL with file:line

## 10. PRODUCTION READINESS
- HTTP server has ReadTimeout and WriteTimeout set?
- HTTP server has MaxHeaderBytes set?
- Graceful shutdown on SIGTERM? (context.WithCancel + server.Shutdown)
- Liveness probe configured in deployment YAML?
- Readiness probe configured in deployment YAML?
- Resource limits in deployment YAML?
- Is there a /readyz endpoint separate from /healthz?
- Deployment uses imagePullSecrets for Docker Hub?
- Report each: PASS or FAIL with file:line

## 11. GO BEST PRACTICES
- go.mod has correct module path?
- go.mod Go version matches Dockerfile?
- No unused imports?
- No fmt.Println (use slog)?
- Error wrapping with proper context?
- Functions under 30 lines?
- SPDX headers on all .go files?
- Report each: PASS or FAIL with file:line

## 12. DEPLOYMENT MANIFESTS
- webhook-deployment.yaml: correct image, ports, probes, volumes, imagePullSecrets?
- webhook-service.yaml: port 443 → 8443 targeting?
- webhook-config.yaml: correct rules, selectors, failurePolicy?
- All in norviq namespace?
- Report each: PASS or FAIL with file:line

## 13. ARCHITECTURE DIAGRAMS (Mermaid)
- architecture/F016.class.mmd exists?
  Must show: main.go, Handler, Injector, Config and their relationships
- architecture/F016.sequence.mmd exists?
  Must show: K8s API Server → Webhook → Handler → Injector → Response → Pod with sidecar
- architecture/F016.deps.mmd exists?
  Must show: F016 depends on F015, F021. F016 blocks F022-F024.
- Diagrams are valid Mermaid syntax?
- Report each: PASS or FAIL with file path

## 14. REGISTRY FILE
- registry/F016.md exists?
- Has 12 sections?
- Section 3 (Dependencies): lists k8s.io/api, k8s.io/apimachinery with versions?
- Section 9 (Upstream): lists F015 (sidecar image), F021 (Dockerfile)?
- Section 10 (Error Codes): lists all 10 NRVQ-WHK codes (4000-4009)?
- Section 12 (Debug Guide): has minimum 7 rows with exact file:line refs?
  Required rows:
  | Webhook not intercepting pods | namespace label | kubectl label ns |
  | Sidecar not injected | pod label missing | add norviq=enabled |
  | TLS handshake failed | CA bundle mismatch | regenerate cert |
  | Double injection | name check | verify container name |
  | Webhook down pods stuck | failurePolicy | set to Ignore |
  | ImagePullBackOff on sidecar | wrong image | check NRVQ_SIDECAR_IMAGE |
  | Pod rejected | patch error | check webhook logs |
- Section 12b (Downstream Impact): describes impact on F022-F024 CRDs?
- All sections use table format with file:line references (not prose)?
- Report each: PASS or FAIL with file path and line



## 15. CLUSTER SAFETY — MOST CRITICAL SECTION (any FAIL = do NOT deploy)

- failurePolicy is Ignore (NOT Fail)?
- System namespaces excluded in webhook-config.yaml (kube-system, kube-public, kube-node-lease, norviq)?
- System namespaces excluded in handler.go code (belt AND suspenders)?
- timeoutSeconds ≤ 5?
- Request body size limited (http.MaxBytesReader 1MB)?
- Content-Type validated as application/json?
- Panic recovery middleware on ALL handlers?
- On panic: returns Allowed:true (NEVER blocks pod creation)?
- On ANY internal error: returns Allowed:true (fail-open)?
- HTTP server has ReadTimeout, WriteTimeout, IdleTimeout, ReadHeaderTimeout?
- HTTP server has MaxHeaderBytes?
- Graceful shutdown on SIGTERM (signal.NotifyContext + server.Shutdown)?
- Sidecar securityContext has ALL of: runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation:false, drop ALL capabilities, seccompProfile RuntimeDefault?
- Shared volume is emptyDir with sizeLimit 10Mi (NOT hostPath)?
- Sidecar has resource requests AND limits?
- Sidecar has liveness probe?
- Label validation (isValidLabel) before using in JSON patch?
- Pods with norviq=disabled label are skipped?
- Pods with norviq.io/skip-injection annotation are skipped?
- DryRun requests handled correctly?
- Webhook deployment has replicas: 2?
- Webhook deployment has podAntiAffinity?
- PodDisruptionBudget exists (minAvailable: 1)?
- Webhook pod has imagePullSecrets?
- Webhook pod has its own securityContext (runAsNonRoot)?

For each: PASS or FAIL. ANY FAIL in this section is CRITICAL — must fix before deploy.

## 16. STALE CODE CHECK

- Zero commented-out code blocks in ALL .go files?
- Zero TODO/FIXME/HACK comments?
- Zero unused imports (go vet clean)?
- Zero unused functions or variables?
- Zero fmt.Println or fmt.Printf (must use slog)?
- Zero dead code paths?
- injector.go patchesWithInit removed if unused?
- Every function has a clear purpose?

For each: PASS or FAIL with file:line

## 17. PERFORMANCE

- Sidecar container template pre-computed at init (not per request)?
- Patch slice pre-allocated with capacity?
- json.NewEncoder used for response (not Marshal + Write)?
- Latency logged in microseconds on every request?
- Target: <10ms per request — any code path that could exceed this?

For each: PASS or FAIL with file:line

## 18. EDGE CASES

- Pod with zero volumes → patch creates volumes array first, then appends?
- Pod with existing volumes → patch appends only?
- Pod with zero containers → should never happen but handled?
- Pod with norviq=enabled but no agent-class label → what happens? Should inject with empty agent class or skip?
- Pod with very long label values (>63 chars) → handled?
- Multiple rapid requests → no race conditions (run tests with -race flag)?
- Webhook restart during pod creation → pod still creates (failurePolicy Ignore)?
- CreatePatch receives full pod object (not just agentClass string)?

For each: PASS or FAIL with file:line


For each: PASS or FAIL. Any FAIL in this section is CRITICAL — must fix before deploy.

## SUMMARY
Provide:
1. Total PASS / FAIL count
2. CRITICAL issues (will break cluster or cause security vulnerability)
3. HIGH issues (will cause problems in production)
4. MEDIUM issues (should fix before release)
5. LOW issues (nice to have)

For every FAIL: exact file:line and specific fix with code.
