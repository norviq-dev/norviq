// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"

	"golang.org/x/oauth2"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

func newTestController() *Controller {
	runtime := &RuntimeConfig{}
	runtime.SetSidecarImage("norviq/norviq-engine:engine-latest")
	return &Controller{
		syncSemaphore:        make(chan struct{}, 10),
		presetBasePath:       "/app/presets",
		adminPolicyNamespace: "norviq",
		runtime:              runtime,
		defaultSidecarImage:  "norviq/norviq-engine:engine-latest",
	}
}

func TestBuildPolicySyncPayload_UsesRegoWhenProvided(t *testing.T) {
	controller := newTestController()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"enforcementMode": "block",
				"target": map[string]interface{}{
					"agentClass": "customer-support",
				},
				"rego":   "package norviq.custom",
				"preset": "strict",
			},
		},
	}
	obj.SetName("chatbot-strict")
	obj.SetNamespace("chatbot-prod")

	payload, err := controller.buildPolicySyncPayload(obj)
	if err != nil {
		t.Fatalf("buildPolicySyncPayload returned error: %v", err)
	}
	if payload.RegoSource != "package norviq.custom" {
		t.Fatalf("expected rego source to be custom rego, got %q", payload.RegoSource)
	}
	if payload.AgentClass != "customer-support" {
		t.Fatalf("expected target agent class customer-support, got %q", payload.AgentClass)
	}
	if payload.Target["agentClass"] != "customer-support" {
		t.Fatalf("expected target.agentClass to remain customer-support, got %+v", payload.Target["agentClass"])
	}
	if payload.Target["namespace"] != "chatbot-prod" {
		t.Fatalf("expected target.namespace to be defaulted from CR namespace, got %+v", payload.Target["namespace"])
	}
}

func TestBuildPolicySyncPayload_DefaultsNamespaceForWorkloadTarget(t *testing.T) {
	controller := newTestController()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"enforcementMode": "block",
				"target": map[string]interface{}{
					"kind": "Deployment",
					"name": "smartsales-agent",
				},
				"rego": "package norviq.custom",
			},
		},
	}
	obj.SetName("workload-policy")
	obj.SetNamespace("chatbot-prod")

	payload, err := controller.buildPolicySyncPayload(obj)
	if err != nil {
		t.Fatalf("buildPolicySyncPayload returned error: %v", err)
	}
	if payload.Target["namespace"] != "chatbot-prod" {
		t.Fatalf("expected workload target namespace defaulted from CR namespace, got %+v", payload.Target["namespace"])
	}
}

func TestBuildPolicySyncPayload_NamespaceBaselineKeyedToTargetNamespace(t *testing.T) {
	controller := newTestController()
	// Mirrors the helm baseline CR: authored in the admin namespace with clusterPriority,
	// targeting a tenant namespace with no agentClass. Must be stored at <targetNs>:__baseline__
	// so the engine's baseline fallback can resolve it (otherwise unseeded agent classes deny).
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"enforcementMode": "block",
				"clusterPriority": int64(900),
				"rego":            "package norviq.presets.strict",
				"target": map[string]interface{}{
					"namespace": "default",
				},
			},
		},
	}
	obj.SetName("baseline-cluster-guard-default")
	obj.SetNamespace("norviq")

	payload, err := controller.buildPolicySyncPayload(obj)
	if err != nil {
		t.Fatalf("buildPolicySyncPayload returned error: %v", err)
	}
	if payload.Namespace != "default" {
		t.Fatalf("expected baseline keyed to target namespace default, got %q", payload.Namespace)
	}
	if payload.AgentClass != "__baseline__" {
		t.Fatalf("expected baseline agent class __baseline__, got %q", payload.AgentClass)
	}
	// clusterPriority (900) authorizes the cross-namespace target but must NOT become the evaluation
	// priority — the baseline is a fallback and must lose to any real policy.
	if payload.Priority != baselineFallbackPriority {
		t.Fatalf("expected baseline stored at fallback priority %d, got %d", baselineFallbackPriority, payload.Priority)
	}
}

func TestNamespaceBaselineKey_OnlyMatchesWholeNamespaceClusterBaseline(t *testing.T) {
	mk := func(spec map[string]interface{}) *unstructured.Unstructured {
		u := &unstructured.Unstructured{Object: map[string]interface{}{"spec": spec}}
		u.SetName("p")
		u.SetNamespace("norviq")
		return u
	}
	// Positive: cluster-priority whole-namespace target.
	if ns, class, ok := namespaceBaselineKey(mk(map[string]interface{}{
		"clusterPriority": int64(900),
		"target":          map[string]interface{}{"namespace": "default"},
	})); !ok || ns != "default" || class != "__baseline__" {
		t.Fatalf("expected (default, __baseline__, true), got (%q, %q, %v)", ns, class, ok)
	}
	// Negative: agentClass target (a normal namespace/workload policy) is untouched.
	if _, _, ok := namespaceBaselineKey(mk(map[string]interface{}{
		"clusterPriority": int64(900),
		"target":          map[string]interface{}{"namespace": "default", "agentClass": "customer-support"},
	})); ok {
		t.Fatalf("agentClass target must not be treated as a namespace baseline")
	}
	// Negative: no clusterPriority (an ordinary tenant policy) is untouched.
	if _, _, ok := namespaceBaselineKey(mk(map[string]interface{}{
		"target": map[string]interface{}{"namespace": "default"},
	})); ok {
		t.Fatalf("non-cluster-priority namespace target must not be treated as a baseline")
	}
	// Negative: workload kind+name target is untouched.
	if _, _, ok := namespaceBaselineKey(mk(map[string]interface{}{
		"clusterPriority": int64(900),
		"target":          map[string]interface{}{"namespace": "default", "kind": "Deployment", "name": "x"},
	})); ok {
		t.Fatalf("workload target must not be treated as a namespace baseline")
	}
}

func TestBuildPolicySyncPayload_UsesPresetFallback(t *testing.T) {
	controller := newTestController()
	tmp := t.TempDir()
	controller.presetBasePath = tmp
	if err := os.WriteFile(filepath.Join(tmp, "moderate.rego"), []byte("package norviq.presets.moderate"), 0o644); err != nil {
		t.Fatalf("write preset file: %v", err)
	}

	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"enforcementMode": "audit",
				"preset":          "moderate",
			},
		},
	}
	obj.SetName("analyst-moderate")
	obj.SetNamespace("analytics")

	payload, err := controller.buildPolicySyncPayload(obj)
	if err != nil {
		t.Fatalf("buildPolicySyncPayload returned error: %v", err)
	}
	if payload.RegoSource != "package norviq.presets.moderate" {
		t.Fatalf("expected loaded preset rego source, got %q", payload.RegoSource)
	}
}

func TestBuildPolicySyncPayload_PresetRoundTripValidation(t *testing.T) {
	controller := newTestController()
	tmp := t.TempDir()
	controller.presetBasePath = tmp
	rego := `package norviq.presets.permissive
default decision = "allow"
decision = "escalate" { input.trust_score < 0.4 }
rule_id = "r"
reason = "x"`
	if err := os.WriteFile(filepath.Join(tmp, "permissive.rego"), []byte(rego), 0o644); err != nil {
		t.Fatalf("write preset file: %v", err)
	}
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"enforcementMode": "audit",
				"preset":          "permissive",
			},
		},
	}
	obj.SetName("permissive-policy")
	obj.SetNamespace("analytics")
	payload, err := controller.buildPolicySyncPayload(obj)
	if err != nil {
		t.Fatalf("buildPolicySyncPayload returned error: %v", err)
	}
	if err := validateRego(payload.RegoSource); err != nil {
		t.Fatalf("expected preset rego to validate, got %v", err)
	}
}

func TestBuildPolicySyncPayload_MissingEnforcementMode(t *testing.T) {
	controller := newTestController()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{},
		},
	}
	obj.SetName("invalid")
	obj.SetNamespace("default")

	if _, err := controller.buildPolicySyncPayload(obj); err == nil {
		t.Fatal("expected error when enforcement mode is missing")
	}
}

func TestSyncPolicy_PostsJSONPayload(t *testing.T) {
	var received policySyncRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		got := r.Header.Get("Authorization")
		if !strings.HasPrefix(got, "Bearer ") {
			t.Fatalf("missing bearer authorization header %q", got)
		}
		role, sub, err := verifyServiceJWT(strings.TrimPrefix(got, "Bearer "), "secret")
		if err != nil {
			t.Fatalf("controller token is not a valid HS256 JWT: %v", err)
		}
		if role != "service" || sub != "norviq-webhook" {
			t.Fatalf("unexpected token claims role=%q sub=%q", role, sub)
		}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	controller := newTestController()
	controller.apiURL = server.URL
	controller.apiSecret = "secret"
	controller.httpClient = server.Client()

	payload := policySyncRequest{
		Namespace:       "default",
		AgentClass:      "chatbot-strict",
		EnforcementMode: "block",
		SavedBy:         "crd/chatbot-strict",
		RegoSource:      "package norviq.presets.strict",
		PolicyName:      "chatbot-strict",
	}

	if err := controller.syncPolicy(context.Background(), payload); err != nil {
		t.Fatalf("syncPolicy returned error: %v", err)
	}
	if received.AgentClass != "chatbot-strict" || received.EnforcementMode != "block" {
		t.Fatalf("unexpected received payload: %+v", received)
	}
}

func TestSyncPolicy_ReturnsErrorOnServerFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	controller := newTestController()
	controller.apiURL = server.URL
	controller.apiSecret = "secret"
	controller.httpClient = server.Client()
	payload := policySyncRequest{
		Namespace:       "default",
		AgentClass:      "chatbot-strict",
		EnforcementMode: "block",
		SavedBy:         "crd/chatbot-strict",
		PolicyName:      "chatbot-strict",
	}
	if err := controller.syncPolicy(context.Background(), payload); err == nil {
		t.Fatal("expected syncPolicy error on 500 response")
	}
}

func TestSyncDelete_ReturnsErrorOnServerFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	controller := newTestController()
	controller.apiURL = server.URL
	controller.apiSecret = "secret"
	controller.httpClient = server.Client()
	if err := controller.syncDelete(context.Background(), "/api/v1/policies/default/chatbot-strict"); err == nil {
		t.Fatal("expected syncDelete error on 500 response")
	}
}

func TestSyncDelete_TreatsNotFoundAsSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Fatalf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	controller := newTestController()
	controller.apiURL = server.URL
	controller.apiSecret = "secret"
	controller.httpClient = server.Client()
	if err := controller.syncDelete(context.Background(), "/api/v1/policies/default/missing"); err != nil {
		t.Fatalf("expected 404 delete to be treated as success, got %v", err)
	}
}

func TestHandlePolicy_TriggersSync(t *testing.T) {
	var syncCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/policies" {
			atomic.AddInt32(&syncCalls, 1)
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	controller := newTestController()
	controller.apiURL = server.URL
	controller.apiSecret = "secret"
	controller.httpClient = server.Client()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"enforcementMode": "block",
				"target": map[string]interface{}{
					"agentClass": "customer-support",
				},
			},
		},
	}
	obj.SetName("chatbot-strict")
	obj.SetNamespace("default")

	controller.handlePolicy(obj, "created")
	controller.wg.Wait()

	if atomic.LoadInt32(&syncCalls) != 1 {
		t.Fatalf("expected one sync call, got %d", atomic.LoadInt32(&syncCalls))
	}
}

func TestHandlePolicy_MalformedObjectNoPanic(t *testing.T) {
	controller := newTestController()
	controller.handlePolicy("unexpected-object", "created")
}

func TestHandlePolicyDelete_TriggersDeleteSync(t *testing.T) {
	var deleteCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/policies/default/chatbot-strict" {
			atomic.AddInt32(&deleteCalls, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	controller := newTestController()
	controller.apiURL = server.URL
	controller.apiSecret = "secret"
	controller.httpClient = server.Client()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"target": map[string]interface{}{
					"agentClass": "customer-support",
				},
			},
		},
	}
	obj.SetName("chatbot-strict")
	obj.SetNamespace("default")

	controller.handlePolicyDelete(obj)
	controller.wg.Wait()

	if atomic.LoadInt32(&deleteCalls) != 1 {
		t.Fatalf("expected one delete sync call, got %d", atomic.LoadInt32(&deleteCalls))
	}
}

func TestHandlePolicyDelete_SkipsWhenDeleteAlreadySynced(t *testing.T) {
	var deleteCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			atomic.AddInt32(&deleteCalls, 1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	controller := newTestController()
	controller.apiURL = server.URL
	controller.apiSecret = "secret"
	controller.httpClient = server.Client()
	obj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	obj.SetName("chatbot-strict")
	obj.SetNamespace("default")
	obj.SetAnnotations(map[string]string{deleteSyncedAnnotation: "true"})

	controller.handlePolicyDelete(obj)
	controller.wg.Wait()
	if atomic.LoadInt32(&deleteCalls) != 0 {
		t.Fatalf("expected no delete call when already synced, got %d", atomic.LoadInt32(&deleteCalls))
	}
}

func TestShouldProcessUpdate_SkipsStatusOnlyUpdates(t *testing.T) {
	oldObj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	newObj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	oldObj.SetGeneration(3)
	newObj.SetGeneration(3)
	if shouldProcessUpdate(oldObj, newObj) {
		t.Fatal("expected status-only update to be skipped")
	}
}

func TestShouldProcessUpdate_ProcessesSpecGenerationChange(t *testing.T) {
	oldObj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	newObj := &unstructured.Unstructured{Object: map[string]interface{}{}}
	oldObj.SetGeneration(3)
	newObj.SetGeneration(4)
	if !shouldProcessUpdate(oldObj, newObj) {
		t.Fatal("expected generation change update to be processed")
	}
}

func TestValidateTargetRejectsCrossNamespace(t *testing.T) {
	target := map[string]interface{}{"namespace": "other"}
	if err := validateTarget("default", "norviq", target, false); err == nil {
		t.Fatal("expected cross-namespace target rejection")
	}
}

func TestValidateTargetRejectsEmptyTarget(t *testing.T) {
	if err := validateTarget("default", "norviq", map[string]interface{}{}, false); err == nil {
		t.Fatal("expected empty target rejection")
	}
}

func TestValidateTargetAdminCrossNamespaceRequiresScopedOrPriority(t *testing.T) {
	target := map[string]interface{}{"namespace": "chatbot-prod"}
	if err := validateTarget("norviq", "norviq", target, false); err == nil {
		t.Fatal("expected admin cross-namespace target to require clusterPriority or scoped target")
	}
}

func TestValidateTargetAdminCrossNamespaceAllowedWithAgentClass(t *testing.T) {
	target := map[string]interface{}{"namespace": "chatbot-prod", "agentClass": "customer-support"}
	if err := validateTarget("norviq", "norviq", target, false); err != nil {
		t.Fatalf("expected scoped admin cross-namespace target to pass, got %v", err)
	}
}

func TestValidateRegoRejectsCommentBypass(t *testing.T) {
	rego := `# block escalate decision rule_id reason
default decision = "allow"`
	if err := validateRego(rego); err == nil {
		t.Fatal("expected comment-only bypass rego to be rejected")
	}
}

func TestValidateRegoRejectsUnreachableEnforcement(t *testing.T) {
	rego := `package norviq
decision = "block" { false }
decision = "allow" { true }
rule_id = "R-1"
reason = "unit test"`
	if err := validateRego(rego); err == nil {
		t.Fatal("expected unreachable block rule to be rejected")
	}
}

func TestValidateRegoRejectsTooManyRegexOps(t *testing.T) {
	rego := `package norviq
decision = "block" { regex.match("a", input.tool_name) }
decision = "block" { regex.match("b", input.tool_name) }
decision = "block" { regex.match("c", input.tool_name) }
decision = "block" { regex.match("d", input.tool_name) }
decision = "block" { regex.match("e", input.tool_name) }
decision = "block" { regex.match("f", input.tool_name) }
rule_id = "R-1"
reason = "regex flood test"`
	if err := validateRego(rego); err == nil {
		t.Fatal("expected regex operation limit rejection")
	}
}

func TestValidateRegoDoesNotCountRegexInStringLiterals(t *testing.T) {
	rego := `package norviq
default decision = "allow"
decision = "block" { input.tool_name == "regex.match in string" }
rule_id = "R-1"
reason = "string literal should not count regex op"`
	if err := validateRego(rego); err != nil {
		t.Fatalf("expected policy with regex text literals to pass, got %v", err)
	}
}

// FIX 5 (enforcement-correctness parity): a policy with a block rule but no `default decision`
// silently evaluates `decision` as undefined (== allow to the engine) whenever the rule doesn't fire.
// Reject it at admission time, same error path as the other validateRego failures.
func TestValidateRegoRejectsMissingDefaultDecision(t *testing.T) {
	rego := `package norviq
decision = "block" { input.tool_name == "delete_user" }
rule_id = "R-1"
reason = "no default"`
	if err := validateRego(rego); err == nil {
		t.Fatal("expected rego without default decision to be rejected")
	}
}

func TestValidateRegoAcceptsExplicitDefaultDecision(t *testing.T) {
	rego := `package norviq
default decision = "allow"
decision = "block" { input.tool_name == "delete_user" }
rule_id = "R-1"
reason = "has default"`
	if err := validateRego(rego); err != nil {
		t.Fatalf("expected rego with default decision to be accepted, got %v", err)
	}
}

func TestValidateRegoAllowsDefaultAllowWhenEnforcementExists(t *testing.T) {
	rego := `package norviq
default decision = "allow"
decision = "block" { input.tool_name == "delete_user" }
rule_id = "R-1"
reason = "default allow rejected"`
	if err := validateRego(rego); err != nil {
		t.Fatalf("expected default allow policy with enforcement rules to pass, got %v", err)
	}
}

func TestValidateClusterPriorityRejected(t *testing.T) {
	spec := map[string]interface{}{"clusterPriority": int64(900)}
	if err := validateClusterPriority("default", spec, "norviq"); err == nil {
		t.Fatal("expected clusterPriority rejection")
	}
}

func TestValidateClusterPriorityAllowedForAdminNamespace(t *testing.T) {
	spec := map[string]interface{}{"clusterPriority": int64(900)}
	if err := validateClusterPriority("norviq", spec, "norviq"); err != nil {
		t.Fatalf("expected admin clusterPriority to be allowed, got %v", err)
	}
}

func TestHandlePolicyQueueFullSkipsSync(t *testing.T) {
	controller := newTestController()
	controller.syncSemaphore <- struct{}{}
	defer func() { <-controller.syncSemaphore }()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"enforcementMode": "block",
				"target": map[string]interface{}{
					"agentClass": "customer-support",
				},
			},
		},
	}
	obj.SetName("chatbot-strict")
	obj.SetNamespace("default")
	controller.handlePolicy(obj, "updated")
}

func TestHandlePolicy_WithFinalizerStillSyncsUpdates(t *testing.T) {
	var syncCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/v1/policies" {
			atomic.AddInt32(&syncCalls, 1)
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	controller := newTestController()
	controller.apiURL = server.URL
	controller.apiSecret = "secret"
	controller.httpClient = server.Client()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"enforcementMode": "block",
				"target": map[string]interface{}{
					"agentClass": "customer-support",
				},
			},
		},
	}
	obj.SetName("chatbot-strict")
	obj.SetNamespace("default")
	obj.SetFinalizers([]string{"norviq.io/policy-protection"})

	controller.handlePolicy(obj, "updated")
	controller.wg.Wait()

	if atomic.LoadInt32(&syncCalls) != 1 {
		t.Fatalf("expected one sync call for finalized update, got %d", atomic.LoadInt32(&syncCalls))
	}
}

func TestHandlePolicy_DeletingWithFinalizerReconcilesDelete(t *testing.T) {
	var deleteCalls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/api/v1/policies/default/chatbot-strict" {
			atomic.AddInt32(&deleteCalls, 1)
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	controller := newTestController()
	controller.apiURL = server.URL
	controller.apiSecret = "secret"
	controller.httpClient = server.Client()
	now := metav1.Now()
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"spec": map[string]interface{}{
				"enforcementMode": "block",
				"target": map[string]interface{}{
					"agentClass": "customer-support",
				},
			},
		},
	}
	obj.SetName("chatbot-strict")
	obj.SetNamespace("default")
	obj.SetFinalizers([]string{"norviq.io/policy-protection"})
	obj.SetDeletionTimestamp(&now)

	controller.handlePolicy(obj, "updated")
	controller.wg.Wait()
	if atomic.LoadInt32(&deleteCalls) != 1 {
		t.Fatalf("expected one delete reconcile call, got %d", atomic.LoadInt32(&deleteCalls))
	}
}

func TestAddFinalizerWithRetry_AddsFinalizer(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "norviq.io/v1alpha1",
			"kind":       "NrvqPolicy",
			"spec": map[string]interface{}{
				"enforcementMode": "block",
				"target": map[string]interface{}{
					"agentClass": "customer-support",
				},
			},
		},
	}
	obj.SetName("finalizer-test")
	obj.SetNamespace("default")

	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme, obj)
	controller := newTestController()
	controller.client = client

	if err := controller.addFinalizerWithRetry(context.Background(), "default", "finalizer-test"); err != nil {
		t.Fatalf("expected finalizer add retry helper to succeed, got %v", err)
	}
	updated, err := client.Resource(policyGVR).Namespace("default").Get(context.Background(), "finalizer-test", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get updated policy: %v", err)
	}
	if !containsFinalizer(updated, "norviq.io/policy-protection") {
		t.Fatal("expected norviq finalizer to be present")
	}
}

func TestAddFinalizerWithRetry_RetriesOnConflict(t *testing.T) {
	obj := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "norviq.io/v1alpha1",
			"kind":       "NrvqPolicy",
		},
	}
	obj.SetName("finalizer-conflict")
	obj.SetNamespace("default")

	scheme := runtime.NewScheme()
	client := dynamicfake.NewSimpleDynamicClient(scheme, obj)
	var updateAttempts int32
	client.PrependReactor("update", "nrvqpolicies", func(action k8stesting.Action) (bool, runtime.Object, error) {
		attempt := atomic.AddInt32(&updateAttempts, 1)
		if attempt == 1 {
			return true, nil, apierrors.NewConflict(
				schema.GroupResource{Group: "norviq.io", Resource: "nrvqpolicies"},
				"finalizer-conflict",
				fmt.Errorf("simulated conflict"),
			)
		}
		return false, nil, nil
	})

	controller := newTestController()
	controller.client = client

	if err := controller.addFinalizerWithRetry(context.Background(), "default", "finalizer-conflict"); err != nil {
		t.Fatalf("expected conflict retry helper to succeed, got %v", err)
	}
	if atomic.LoadInt32(&updateAttempts) < 2 {
		t.Fatalf("expected retry after conflict, got %d update attempts", atomic.LoadInt32(&updateAttempts))
	}
	updated, err := client.Resource(policyGVR).Namespace("default").Get(context.Background(), "finalizer-conflict", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get updated policy: %v", err)
	}
	if !containsFinalizer(updated, "norviq.io/policy-protection") {
		t.Fatal("expected norviq finalizer to be present after retry")
	}
}

func TestBearerToken_PrefersOIDCThenFallsBackToHS256(t *testing.T) {
	// With an OIDC token source set, bearerToken returns the access token (not the HS256 JWT).
	c := newTestController()
	c.apiSecret = "secret"
	c.oidcTokenSource = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "oidc-access-token"})
	if got := c.bearerToken(); got != "oidc-access-token" {
		t.Fatalf("expected OIDC access token, got %q", got)
	}
	// Without an OIDC source, it mints the HS256 service JWT (role=service).
	c.oidcTokenSource = nil
	c.cachedJWT = ""
	tok := c.bearerToken()
	role, sub, err := verifyServiceJWT(tok, "secret")
	if err != nil || role != "service" || sub != "norviq-webhook" {
		t.Fatalf("expected HS256 service JWT fallback, got role=%q sub=%q err=%v", role, sub, err)
	}
}

// verifyServiceJWT validates an HS256 JWT against secret and returns (role, sub). Test-only helper.
func verifyServiceJWT(token, secret string) (string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("not a 3-part JWT")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		return "", "", fmt.Errorf("bad signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", err
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", "", err
	}
	role, _ := claims["role"].(string)
	sub, _ := claims["sub"].(string)
	return role, sub, nil
}
