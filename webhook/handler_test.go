// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// The namespace opts in via the MutatingWebhookConfiguration namespaceSelector (not exercised
// in this unit test), so a pod that reaches the handler with no opt-out label IS injected.
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
	// sidecar + 2 volumes (shared socket, sidecar-private tmpfs) + app mount + app env + annotation.
	if len(patches) != 6 {
		t.Fatalf("expected 6 patch ops, got %d", len(patches))
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

// fullyInjectedContainer is an app container wired the way the injector wires one: the norviq-socket
// volume at socketMountPath and NRVQ_SOCKET_PATH. A pod carrying it is refused at CREATE (NRVQ-WHK-4063).
func fullyInjectedContainer(name, image string) corev1.Container {
	return corev1.Container{
		Name:         name,
		Image:        image,
		VolumeMounts: []corev1.VolumeMount{{Name: "norviq-socket", MountPath: socketMountPath}},
		Env:          []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}},
	}
}

// trustedSidecar is a sidecar container carrying the injector's routing env (proxy mode pointed at the
// configured engine). extraMounts lets a test add the socket mount.
func trustedSidecar(name, image string, cfg Config, mounts ...corev1.VolumeMount) corev1.Container {
	return corev1.Container{
		Name:         name,
		Image:        image,
		VolumeMounts: mounts,
		Env: []corev1.EnvVar{
			{Name: "NRVQ_SIDECAR_MODE", Value: "proxy"},
			{Name: "NRVQ_API_URL", Value: cfg.ApiURL},
		},
	}
}

func TestMutateAlreadyInjectedIsRefused(t *testing.T) {
	cfg := LoadConfig()
	h := NewHandler(cfg)
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Labels: map[string]string{"norviq": "enabled"}},
		Spec: corev1.PodSpec{
			Volumes:    []corev1.Volume{{Name: "norviq-socket"}},
			Containers: []corev1.Container{fullyInjectedContainer("app", "nginx"), trustedSidecar("norviq-sidecar", cfg.SidecarImage, cfg)},
		},
	}
	resp := sendReview(t, h, makeReviewFromPod(pod, metav1.GroupVersionKind{Kind: "Pod"}, "default"))
	// Rewritten: this asserted SKIP (admitted, no patch). The webhook is CREATE-only, so a pod arriving
	// already injected is a copied spec, and admission now refuses it rather than trusting the copy.
	assertRefusedAsCopy(t, resp)
}

// assertRefusedAsCopy is the outcome for a pod that already carries injector-owned parts.
func assertRefusedAsCopy(t *testing.T, resp admissionv1.AdmissionReview) {
	t.Helper()
	if resp.Response.Allowed || resp.Response.Patch != nil {
		t.Fatalf("a pod carrying injector-owned parts must be refused; allowed=%v patched=%v",
			resp.Response.Allowed, resp.Response.Patch != nil)
	}
	if resp.Response.Result == nil || !strings.HasPrefix(resp.Response.Result.Message, "NRVQ-WHK-4063: ") {
		t.Fatalf("refused, but not under NRVQ-WHK-4063: %+v", resp.Response.Result)
	}
}

// A pod author can write norviq.io/injected on a CREATE, so the annotation is never evidence that a pod is
// governed. It must never let the pod through unpatched.
//
// Rewritten: this asserted the pod was INJECTED with the annotation ignored. The annotation is now one of
// the injector-owned parts, so the pod is refused instead; both outcomes keep it from running unpatched,
// and the refusal names the annotation so the author can remove it.
func TestMutateSelfStampAnnotationDoesNotBypassInjection(t *testing.T) {
	h := NewHandler(LoadConfig())
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "attacker",
			Labels:      map[string]string{"norviq": "enabled"},
			Annotations: map[string]string{injectedAnnotation: "true"}, // self-stamped, no real sidecar
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "busybox"}}},
	}
	resp := sendReview(t, h, makeReviewFromPod(pod, metav1.GroupVersionKind{Kind: "Pod"}, "default"))
	assertRefusedAsCopy(t, resp)
	if !strings.Contains(resp.Response.Result.Message, injectedAnnotation) {
		t.Fatalf("the refusal must name the annotation: %q", resp.Response.Result.Message)
	}
}

// An injected pod's spec, copied after an NrvqConfig image rotation so its sidecar names an older engine tag.
//
// Rewritten: this asserted SKIP, tolerating the tag drift as the injector's own output. Every copy is now
// refused, whatever image its sidecar names, since the webhook builds the sidecar on every CREATE.
func TestMutateAlreadyInjectedAfterImageDriftIsRefused(t *testing.T) {
	h := NewHandler(LoadConfig())
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Labels: map[string]string{"norviq": "enabled"}},
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{{Name: "norviq-socket"}},
			Containers: []corev1.Container{
				fullyInjectedContainer("app", "nginx"),
				// drifted image (old tag) but same name "norviq-engine" + socket mount + trusted routing → recognized.
				// The project's own registry: this fixture used Docker Hub's `norviq/` namespace, which the
				// project does not own and which is no longer trusted (see the test below).
				trustedSidecar("norviq-sidecar", "ghcr.io/norviq-dev/norviq-engine:engine-some-old-sha", h.cfg,
					corev1.VolumeMount{Name: "norviq-socket", MountPath: socketMountPath}),
			},
		},
	}
	resp := sendReview(t, h, makeReviewFromPod(pod, metav1.GroupVersionKind{Kind: "Pod"}, "default"))
	assertRefusedAsCopy(t, resp)
}

// A self-wired "sidecar" from Docker Hub's `norviq` namespace must not make a pod count as already
// injected. That namespace is unowned (anyone can register it and push norviq/norviq-engine), and it
// used to be on the allowlist the skip path consults — so a tenant could ship their own image under
// that name, wire it like the real sidecar, and have the webhook skip injecting the real one. The
// tool calls would then be judged by the tenant's image.
func TestMutateDockerHubNorviqSidecarIsNotTrustedAsInjected(t *testing.T) {
	prev := allowLocalSidecarImages
	t.Cleanup(func() { allowLocalSidecarImages = prev })
	allowLocalSidecarImages = false
	h := NewHandler(LoadConfig())
	for _, img := range []string{"norviq/norviq-engine:engine-latest", "docker.io/norviq/norviq-engine:engine-x"} {
		pod := corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Labels: map[string]string{"norviq": "enabled"}},
			Spec: corev1.PodSpec{
				Volumes: []corev1.Volume{{Name: "norviq-socket"}},
				Containers: []corev1.Container{
					fullyInjectedContainer("app", "nginx"),
					trustedSidecar("norviq-sidecar", img, h.cfg,
						corev1.VolumeMount{Name: "norviq-socket", MountPath: socketMountPath}),
				},
			},
		}
		resp := sendReview(t, h, makeReviewFromPod(pod, metav1.GroupVersionKind{Kind: "Pod"}, "default"))
		if resp.Response.Allowed && resp.Response.Patch == nil {
			t.Fatalf("%s was trusted as the real sidecar and injection was skipped", img)
		}
	}
}

// A container merely NAMED "norviq-sidecar" but running another image must not leave the pod unpatched.
//
// Rewritten: this asserted the real sidecar was INJECTED beside it. That patch adds a second container
// named norviq-sidecar, which the API server rejects as a duplicate, so the pod could never have started;
// the name is now an injector-owned part and admission refuses the pod with a message naming it.
func TestMutateDecoySidecarNameIsRefused(t *testing.T) {
	h := NewHandler(LoadConfig())
	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Labels: map[string]string{"norviq": "enabled"}},
		Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Name: "app", Image: "nginx"},
			{Name: "norviq-sidecar", Image: "attacker/decoy:latest"},
		}},
	}
	resp := sendReview(t, h, makeReviewFromPod(pod, metav1.GroupVersionKind{Kind: "Pod"}, "default"))
	assertRefusedAsCopy(t, resp)
	if !strings.Contains(resp.Response.Result.Message, "container norviq-sidecar takes the injected sidecar's name") {
		t.Fatalf("the refusal must name the container: %q", resp.Response.Result.Message)
	}
}

func TestMutate_DisabledLabel(t *testing.T) {
	h := NewHandler(LoadConfig())
	// Opt out with the unified norviq-injection=disabled label (the default EnableLabel).
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

// When allowPodOptOut=false, the per-pod opt-out (skip-injection annotation / disabled label)
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
