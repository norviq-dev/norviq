// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestHealthz(t *testing.T) {
	h := NewHandler(LoadConfig())
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.Healthz(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if got := w.Body.String(); got != `{"status":"ok"}` {
		t.Fatalf("expected health body, got %q", got)
	}
}

func TestReadyz(t *testing.T) {
	h := NewHandler(LoadConfig())
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	h.Readyz(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

// SIDE-3: the namespace opts in via the MutatingWebhookConfiguration namespaceSelector (not exercised
// in this unit test), so a pod that reaches the handler with no opt-out label IS injected. Previously an
// unlabeled pod was silently skipped even in a selected namespace, which made the documented
// "label the namespace" workflow a no-op.
func TestMutateNoLabelStillInjects(t *testing.T) {
	h := NewHandler(LoadConfig())
	resp := sendReview(t, h, createReview(map[string]string{}, nil))
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("expected injection for a pod with no opt-out label (namespace-gated by the MWC)")
	}
}

func TestMutate_EmptyBody(t *testing.T) {
	h := NewHandler(LoadConfig())
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(nil))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Mutate(w, req)
	assertFailClosedDecodeResponse(t, w)
}

func TestMutateWithLabel(t *testing.T) {
	h := NewHandler(LoadConfig())
	labels := map[string]string{"norviq": "enabled", "norviq.io/agent-class": "customer-support"}
	resp := sendReview(t, h, createReview(labels, []corev1.Volume{}))
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("expected patch response")
	}
	var patches []patchOp
	if err := json.Unmarshal(resp.Response.Patch, &patches); err != nil {
		t.Fatalf("patch unmarshal failed: %v", err)
	}
	if len(patches) != 5 {
		t.Fatalf("expected 5 patch ops, got %d", len(patches))
	}
	sidecarEnv := patches[0].Value.(map[string]interface{})["env"].([]interface{})
	found := false
	for _, item := range sidecarEnv {
		env := item.(map[string]interface{})
		if env["name"] == "NRVQ_AGENT_CLASS" && env["value"] == "customer-support" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected NRVQ_AGENT_CLASS to match pod label")
	}
}

func TestMutate_InvalidJSON(t *testing.T) {
	h := NewHandler(LoadConfig())
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewBufferString("{bad"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Mutate(w, req)
	assertFailClosedDecodeResponse(t, w)
}

func TestMutate_WrongContentType(t *testing.T) {
	h := NewHandler(LoadConfig())
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewBufferString("{}"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.Mutate(w, req)
	assertFailClosedDecodeResponse(t, w)
}

func TestMutateWithCustomEnableValue(t *testing.T) {
	cfg := LoadConfig()
	cfg.EnableValue = "active"
	h := NewHandler(cfg)
	labels := map[string]string{"norviq": "active", "norviq.io/agent-class": "customer-support"}
	resp := sendReview(t, h, createReview(labels, []corev1.Volume{}))
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("expected patch response with custom enable value")
	}
}

func TestMutateResponseUIDMatchesRequestUID(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := createReview(map[string]string{"norviq": "enabled", "norviq.io/agent-class": "sales"}, nil)
	review.Request.UID = "uid-check"
	resp := sendReview(t, h, review)
	if resp.Response == nil || resp.Response.UID != "uid-check" {
		t.Fatalf("expected response UID uid-check, got %q", resp.Response.UID)
	}
}

func TestMutate_NoAgentClassStillInjects(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := createReview(map[string]string{"norviq": "enabled"}, nil)
	resp := sendReview(t, h, review)
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("expected patch when agent-class label is absent")
	}
}

// FIX 4: hasSidecar must identify the real sidecar by the injector-controlled IMAGE (or the
// injectedAnnotation it stamps), never by the attacker-controllable container NAME. A pod already
// carrying the REAL sidecar image is skipped (idempotency preserved).
func TestMutateAlreadyInjected(t *testing.T) {
	cfg := LoadConfig()
	h := NewHandler(cfg)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Labels: map[string]string{"norviq": "enabled"}},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "norviq-sidecar", Image: cfg.SidecarImage}}},
	}
	resp := sendReview(t, h, makeReviewFromPod(pod, metav1.GroupVersionKind{Kind: "Pod"}, "default"))
	if !resp.Response.Allowed || resp.Response.Patch != nil {
		t.Fatal("expected no patch for pod already carrying the real sidecar image")
	}
}

// A pod already stamped with injectedAnnotation is also treated as injected, even if the configured
// sidecar image has since rotated (NrvqConfig image update) and no container image matches anymore.
func TestMutateAlreadyInjectedByAnnotation(t *testing.T) {
	h := NewHandler(LoadConfig())
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "test",
			Labels:      map[string]string{"norviq": "enabled"},
			Annotations: map[string]string{injectedAnnotation: "true"},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app"}, {Name: "norviq-sidecar", Image: "norviq/norviq-engine:some-old-sha"}}},
	}
	resp := sendReview(t, h, makeReviewFromPod(pod, metav1.GroupVersionKind{Kind: "Pod"}, "default"))
	if !resp.Response.Allowed || resp.Response.Patch != nil {
		t.Fatal("expected no patch for pod already stamped with the injected annotation")
	}
}

// H6-style decoy: an attacker-controlled container merely NAMED "norviq-sidecar" but running a
// different image must NOT suppress injection of the real sidecar — otherwise the pod runs unpoliced.
func TestMutateDecoySidecarNameStillInjectsRealSidecar(t *testing.T) {
	h := NewHandler(LoadConfig())
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Labels: map[string]string{"norviq": "enabled"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "app", Image: "nginx"},
			{Name: "norviq-sidecar", Image: "attacker/decoy:latest"},
		}},
	}
	resp := sendReview(t, h, makeReviewFromPod(pod, metav1.GroupVersionKind{Kind: "Pod"}, "default"))
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("expected the real sidecar to be injected despite a decoy container named norviq-sidecar with a different image")
	}
	var patches []patchOp
	if err := json.Unmarshal(resp.Response.Patch, &patches); err != nil {
		t.Fatalf("patch unmarshal failed: %v", err)
	}
	sidecar := patches[0].Value.(map[string]interface{})
	if sidecar["name"] != "norviq-sidecar" || sidecar["image"] != h.cfg.SidecarImage {
		t.Fatalf("expected the real norviq-sidecar container to be appended, got %+v", sidecar)
	}
}

func TestMutate_DisabledLabel(t *testing.T) {
	h := NewHandler(LoadConfig())
	// SIDE-3: opt out with the unified norviq-injection=disabled label (the default EnableLabel).
	labels := map[string]string{"norviq-injection": "disabled", "norviq.io/agent-class": "sales"}
	resp := sendReview(t, h, createReview(labels, nil))
	if !resp.Response.Allowed || resp.Response.Patch != nil {
		t.Fatal("expected allowed response without patch")
	}
}

func TestMutate_SkipAnnotation(t *testing.T) {
	h := NewHandler(LoadConfig())
	labels := map[string]string{"norviq": "enabled", "norviq.io/agent-class": "sales"}
	resp := sendReview(t, h, createReviewWithAnnotations(labels, map[string]string{"norviq.io/skip-injection": "true"}, nil, "default"))
	if !resp.Response.Allowed || resp.Response.Patch != nil {
		t.Fatal("expected allowed response without patch")
	}
}

// P3: when allowPodOptOut=false, the per-pod opt-out (skip-injection annotation / disabled label)
// is IGNORED so a pod author cannot self-exempt from enforcement — the pod is injected anyway.
func TestMutate_OptOutIgnoredWhenDisabled_Annotation(t *testing.T) {
	t.Setenv("NRVQ_ALLOW_POD_OPT_OUT", "false")
	h := NewHandler(LoadConfig())
	labels := map[string]string{"norviq": "enabled", "norviq.io/agent-class": "sales"}
	resp := sendReview(t, h, createReviewWithAnnotations(labels, map[string]string{"norviq.io/skip-injection": "true"}, nil, "default"))
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("with allowPodOptOut=false, skip-injection annotation must be ignored and the pod injected (patch expected)")
	}
}

func TestMutate_OptOutIgnoredWhenDisabled_Label(t *testing.T) {
	t.Setenv("NRVQ_ALLOW_POD_OPT_OUT", "false")
	h := NewHandler(LoadConfig())
	labels := map[string]string{"norviq-injection": "disabled", "norviq.io/agent-class": "sales"}
	resp := sendReview(t, h, createReviewWithAnnotations(labels, nil, nil, "default"))
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("with allowPodOptOut=false, norviq-injection=disabled must be ignored and the pod injected (patch expected)")
	}
}

func TestMutate_SystemNamespace(t *testing.T) {
	h := NewHandler(LoadConfig())
	labels := map[string]string{"norviq": "enabled", "norviq.io/agent-class": "sales"}
	resp := sendReview(t, h, createReviewWithAnnotations(labels, nil, nil, "kube-system"))
	if !resp.Response.Allowed || resp.Response.Patch != nil {
		t.Fatal("expected allowed response without patch")
	}
}

func TestMutateNonPod(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request:  &admissionv1.AdmissionRequest{UID: "uid-1", Kind: metav1.GroupVersionKind{Kind: "Service"}},
	}
	resp := sendReview(t, h, review)
	if !resp.Response.Allowed {
		t.Fatal("non-pod should be allowed")
	}
}

func TestMutateMalformedBody(t *testing.T) {
	h := NewHandler(LoadConfig())
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewBufferString("{bad"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Mutate(w, req)
	assertFailClosedDecodeResponse(t, w)
}

func TestMutateBodyTooLarge(t *testing.T) {
	h := NewHandler(LoadConfig())
	req := httptest.NewRequest(http.MethodPost, "/mutate", io.NopCloser(bytes.NewReader(make([]byte, maxAdmissionBodySize+1))))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Mutate(w, req)
	assertFailClosedDecodeResponse(t, w)
}

func TestMutate_LargeBody(t *testing.T) {
	TestMutateBodyTooLarge(t)
}

func TestMutateNilRequest(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
	}
	body, _ := json.Marshal(review)
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Mutate(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if out.Response == nil || !out.Response.Allowed {
		t.Fatal("expected allowed response for nil admission request")
	}
}

func TestMutateDryRunReturnsPatch(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := createReview(map[string]string{"norviq": "enabled", "norviq.io/agent-class": "sales"}, nil)
	dryRun := true
	review.Request.DryRun = &dryRun
	resp := sendReview(t, h, review)
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("expected dry-run response to include mutation patch")
	}
}

func TestMutate_DryRun(t *testing.T) {
	TestMutateDryRunReturnsPatch(t)
}

func TestMutate_InvalidAgentClass(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := createReview(map[string]string{"norviq": "enabled", "norviq.io/agent-class": "bad class"}, nil)
	resp := sendReview(t, h, review)
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("expected patch response with invalid agent class sanitized to empty")
	}
	var patches []patchOp
	if err := json.Unmarshal(resp.Response.Patch, &patches); err != nil {
		t.Fatalf("patch unmarshal failed: %v", err)
	}
	sidecarEnv := patches[0].Value.(map[string]interface{})["env"].([]interface{})
	for _, item := range sidecarEnv {
		env := item.(map[string]interface{})
		if env["name"] == "NRVQ_AGENT_CLASS" && env["value"] != "" {
			t.Fatal("expected invalid agent class to be replaced with empty value")
		}
	}
}

func TestMutate_DisabledWithCustomEnableLabel(t *testing.T) {
	cfg := LoadConfig()
	cfg.EnableLabel = "norviq-enabled"
	h := NewHandler(cfg)
	labels := map[string]string{"norviq-enabled": "disabled", "norviq.io/agent-class": "sales"}
	resp := sendReview(t, h, createReview(labels, nil))
	if !resp.Response.Allowed || resp.Response.Patch != nil {
		t.Fatal("expected allowed response without patch when custom enable label is disabled")
	}
}

func TestMutate_MalformedPodFailClosed(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       "uid-malformed-pod",
			Kind:      metav1.GroupVersionKind{Kind: "Pod"},
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: []byte(`{"metadata":{"name":"bad"},"spec":{"containers":"invalid"}}`)},
		},
	}
	resp := sendReview(t, h, review)
	if resp.Response.Allowed {
		t.Fatal("expected malformed pod parse failure to be denied")
	}
	if resp.Response.Patch != nil {
		t.Fatal("expected no patch when pod object cannot be parsed")
	}
}

func createReview(labels map[string]string, volumes []corev1.Volume) admissionv1.AdmissionReview {
	return createReviewWithAnnotations(labels, nil, volumes, "default")
}

func createReviewWithAnnotations(labels map[string]string, annotations map[string]string, volumes []corev1.Volume, namespace string) admissionv1.AdmissionReview {
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod", Labels: labels, Annotations: annotations, Namespace: namespace},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx"}}, Volumes: volumes},
	}
	return makeReviewFromPod(pod, metav1.GroupVersionKind{Kind: "Pod"}, namespace)
}

func makeReviewFromPod(pod corev1.Pod, kind metav1.GroupVersionKind, namespace string) admissionv1.AdmissionReview {
	raw, _ := json.Marshal(pod)
	return admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request:  &admissionv1.AdmissionRequest{UID: "uid-1", Kind: kind, Namespace: namespace, Object: runtime.RawExtension{Raw: raw}},
	}
}

func sendReview(t *testing.T, h *Handler, review admissionv1.AdmissionReview) admissionv1.AdmissionReview {
	t.Helper()
	body, _ := json.Marshal(review)
	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.Mutate(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var response admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("response unmarshal failed: %v", err)
	}
	return response
}

func assertFailClosedDecodeResponse(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("expected admission review response, got unmarshal error: %v", err)
	}
	if out.Response == nil || out.Response.Allowed {
		t.Fatal("expected fail-closed denied response")
	}
	if out.Response.Patch != nil {
		t.Fatal("expected no patch on decode failure")
	}
}

func TestValidatePolicyRejectsCrossNamespaceTarget(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       "uid-validate",
			Kind:      metav1.GroupVersionKind{Group: "norviq.io", Version: "v1alpha1", Kind: "NrvqPolicy"},
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: []byte(`{"apiVersion":"norviq.io/v1alpha1","kind":"NrvqPolicy","metadata":{"name":"bad","namespace":"default"},"spec":{"target":{"namespace":"other"},"enforcementMode":"block","rego":"package p\ndecision = \"block\" { true }\nrule_id = \"r\"\nreason = \"x\""}}`)},
		},
	}
	body, _ := json.Marshal(review)
	req := httptest.NewRequest(http.MethodPost, "/validate-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ValidatePolicy(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if out.Response == nil || out.Response.Allowed {
		t.Fatal("expected cross-namespace policy to be denied")
	}
}

func TestValidatePolicyAllowsValidPolicy(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       "uid-validate-ok",
			Kind:      metav1.GroupVersionKind{Group: "norviq.io", Version: "v1alpha1", Kind: "NrvqPolicy"},
			Namespace: "default",
			Object:    runtime.RawExtension{Raw: []byte(`{"apiVersion":"norviq.io/v1alpha1","kind":"NrvqPolicy","metadata":{"name":"ok","namespace":"default"},"spec":{"target":{"agentClass":"customer-support"},"enforcementMode":"block","rego":"package p\ndefault decision = \"allow\"\ndecision = \"block\" { true }\nrule_id = \"r\"\nreason = \"x\""}}`)},
		},
	}
	body, _ := json.Marshal(review)
	req := httptest.NewRequest(http.MethodPost, "/validate-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ValidatePolicy(w, req)
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if out.Response == nil || !out.Response.Allowed {
		t.Fatal("expected valid policy to be allowed")
	}
}

func TestValidatePolicyRejectsClusterPriorityWithoutAdminGroup(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       "uid-cluster-priority-deny",
			Kind:      metav1.GroupVersionKind{Group: "norviq.io", Version: "v1alpha1", Kind: "NrvqPolicy"},
			Namespace: "norviq",
			UserInfo:  authv1.UserInfo{Groups: []string{"devs"}},
			Object:    runtime.RawExtension{Raw: []byte(`{"apiVersion":"norviq.io/v1alpha1","kind":"NrvqPolicy","metadata":{"name":"cp-no-admin","namespace":"norviq"},"spec":{"target":{"agentClass":"customer-support"},"enforcementMode":"block","clusterPriority":700,"rego":"package p\ndecision = \"block\" { true }\nrule_id = \"r\"\nreason = \"x\""}}`)},
		},
	}
	body, _ := json.Marshal(review)
	req := httptest.NewRequest(http.MethodPost, "/validate-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ValidatePolicy(w, req)
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if out.Response == nil || out.Response.Allowed {
		t.Fatal("expected non-admin clusterPriority policy to be denied")
	}
}

func TestValidatePolicyAllowsClusterPriorityForAdminGroup(t *testing.T) {
	h := NewHandler(LoadConfig())
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request: &admissionv1.AdmissionRequest{
			UID:       "uid-cluster-priority-allow",
			Kind:      metav1.GroupVersionKind{Group: "norviq.io", Version: "v1alpha1", Kind: "NrvqPolicy"},
			Namespace: "norviq",
			UserInfo:  authv1.UserInfo{Groups: []string{"system:masters"}},
			Object:    runtime.RawExtension{Raw: []byte(`{"apiVersion":"norviq.io/v1alpha1","kind":"NrvqPolicy","metadata":{"name":"cp-admin","namespace":"norviq"},"spec":{"target":{"agentClass":"customer-support"},"enforcementMode":"block","clusterPriority":700,"rego":"package p\ndefault decision = \"allow\"\ndecision = \"block\" { true }\nrule_id = \"r\"\nreason = \"x\""}}`)},
		},
	}
	body, _ := json.Marshal(review)
	req := httptest.NewRequest(http.MethodPost, "/validate-policy", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ValidatePolicy(w, req)
	var out admissionv1.AdmissionReview
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if out.Response == nil || !out.Response.Allowed {
		t.Fatal("expected admin clusterPriority policy to be allowed")
	}
}
