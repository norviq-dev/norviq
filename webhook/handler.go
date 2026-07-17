// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

type Handler struct {
	cfg      Config
	injector *Injector
}

const maxAdmissionBodySize = 1 << 20

// injectedAnnotation is stamped onto every pod the injector patches (see injector.go), independent of
// the attacker-controllable container name, so hasSidecar can positively identify a real prior
// injection even if the configured sidecar image has since rotated.
const injectedAnnotation = "norviq.io/injected"

var systemExcludedNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"norviq":          true,
}

func NewHandler(cfg Config) *Handler {
	return &Handler{cfg: cfg, injector: NewInjector(cfg)}
}

func (h *Handler) Healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (h *Handler) Readyz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

func (h *Handler) Mutate(w http.ResponseWriter, r *http.Request) {
	review, ok := decodeReview(w, r)
	if !ok {
		uid, _ := r.Context().Value(admissionUIDKey).(string)
		writeFailClosedResponse(w, uid, "invalid admission review request")
		return
	}
	if review.Request == nil {
		review.Response = &admissionv1.AdmissionResponse{Allowed: true}
		writeReview(w, review)
		return
	}
	response := h.handleAdmission(review.Request)
	response.UID = review.Request.UID
	review.Response = response
	writeReview(w, review)
}

func (h *Handler) ValidatePolicy(w http.ResponseWriter, r *http.Request) {
	review, ok := decodeReview(w, r)
	if !ok || review.Request == nil {
		writeReview(w, admissionv1.AdmissionReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
			Response: &admissionv1.AdmissionResponse{
				Allowed: false,
				Result:  &metav1.Status{Message: "invalid admission review request"},
			},
		})
		return
	}
	req := review.Request
	resp := &admissionv1.AdmissionResponse{UID: req.UID, Allowed: true}
	if req.Kind.Kind != "NrvqPolicy" {
		review.Response = resp
		writeReview(w, review)
		return
	}

	var u unstructured.Unstructured
	if err := json.Unmarshal(req.Object.Raw, &u.Object); err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: "invalid NrvqPolicy object"}
		review.Response = resp
		writeReview(w, review)
		return
	}
	spec, _, _ := unstructured.NestedMap(u.Object, "spec")
	namespace := u.GetNamespace()
	if namespace == "" {
		namespace = req.Namespace
	}
	if err := validateClusterPriority(namespace, spec, h.cfg.AdminPolicyNamespace); err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: err.Error()}
		review.Response = resp
		writeReview(w, review)
		return
	}
	if _, found := spec["clusterPriority"]; found && !isClusterPriorityAdmin(req.UserInfo.Groups) {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: "clusterPriority requires cluster-admin privileges"}
		review.Response = resp
		writeReview(w, review)
		return
	}
	target, _ := spec["target"].(map[string]interface{})
	_, hasClusterPriority := spec["clusterPriority"]
	if err := validateTarget(req.Namespace, h.cfg.AdminPolicyNamespace, target, hasClusterPriority); err != nil {
		resp.Allowed = false
		resp.Result = &metav1.Status{Message: err.Error()}
		review.Response = resp
		writeReview(w, review)
		return
	}
	if rego, found, _ := unstructured.NestedString(u.Object, "spec", "rego"); found && rego != "" {
		if err := validateRego(rego); err != nil {
			resp.Allowed = false
			resp.Result = &metav1.Status{Message: err.Error()}
			review.Response = resp
			writeReview(w, review)
			return
		}
	}

	review.Response = resp
	writeReview(w, review)
}

func decodeReview(w http.ResponseWriter, r *http.Request) (admissionv1.AdmissionReview, bool) {
	review := admissionv1.AdmissionReview{}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		slog.Error("NRVQ-WHK-4013: wrong content type", "content_type", r.Header.Get("Content-Type"))
		return review, false
	}
	defer r.Body.Close()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAdmissionBodySize))
	if err != nil {
		slog.Error("NRVQ-WHK-4014: admission review read failed", "error", err)
		return review, false
	}
	if err = json.Unmarshal(body, &review); err != nil {
		slog.Error("NRVQ-WHK-4004: admission review unmarshal failed", "error", err)
		return review, false
	}
	return review, true
}

func writeReview(w http.ResponseWriter, review admissionv1.AdmissionReview) {
	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(review)
	if err != nil {
		slog.Error("NRVQ-WHK-4005: response marshal failed", "error", err)
		return
	}
}

func writeFailClosedResponse(w http.ResponseWriter, uid, message string) {
	review := admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{
			Allowed: false,
			Result:  &metav1.Status{Message: message},
		},
	}
	review.APIVersion = "admission.k8s.io/v1"
	review.Kind = "AdmissionReview"
	if uid != "" {
		review.Response.UID = types.UID(uid)
	}
	writeReview(w, review)
}

func (h *Handler) handleAdmission(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	if req.Kind.Kind != "Pod" {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}
	if systemExcludedNamespaces[req.Namespace] {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}
	pod, ok := parsePod(req)
	if !ok {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result:  &metav1.Status{Message: "invalid pod object"},
		}
	}
	if shouldSkipInjection(h.cfg, pod, req.Namespace) {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}
	return h.patchResponse(req, pod)
}

// shouldSkipInjection implements SIDE-3: the namespace opts in via the MutatingWebhookConfiguration
// namespaceSelector (norviq-injection=enabled), so every pod in a selected namespace is injected UNLESS
// it explicitly opts out (norviq-injection=disabled label or the skip annotation) or already has a
// sidecar. This makes the documented "label the namespace" workflow actually inject, instead of the old
// behavior that also silently required a per-pod enable label. Skips are logged at INFO, not DEBUG.
func shouldSkipInjection(cfg Config, pod *corev1.Pod, namespace string) bool {
	optedOut := pod.Labels[cfg.EnableLabel] == "disabled" || pod.Annotations["norviq.io/skip-injection"] == "true"
	if optedOut && cfg.AllowPodOptOut {
		slog.Info("NRVQ-WHK-4007: injection opted out for pod", "pod", pod.Name, "namespace", namespace,
			"hint", "remove label "+cfg.EnableLabel+"=disabled / annotation norviq.io/skip-injection to enable")
		return true
	}
	if optedOut && !cfg.AllowPodOptOut {
		// P3: pod-level opt-out is disabled cluster-wide — inject anyway so a pod author can't self-exempt
		// from enforcement. Logged so the denied bypass attempt is observable.
		slog.Warn("NRVQ-WHK-4009: pod-level injection opt-out is disabled (allowPodOptOut=false); injecting anyway",
			"pod", pod.Name, "namespace", namespace)
	}
	if hasSidecar(cfg, pod) {
		slog.Info("NRVQ-WHK-4008: sidecar already present, skipping", "pod", pod.Name, "namespace", namespace)
		return true
	}
	return false
}

func (h *Handler) patchResponse(req *admissionv1.AdmissionRequest, pod *corev1.Pod) *admissionv1.AdmissionResponse {
	start := time.Now()
	agentClass := pod.Labels[h.cfg.AgentClassLabel]
	if agentClass != "" && !isValidLabel(agentClass) {
		slog.Warn("NRVQ-WHK-4015: invalid agent class label, injecting with empty class", "value", agentClass, "pod", pod.Name, "namespace", req.Namespace)
		agentClass = ""
	}
	patch, err := h.injector.CreatePatch(pod, agentClass, req.Namespace)
	if err != nil {
		slog.Error("NRVQ-WHK-4009: patch creation failed", "error", err)
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result:  &metav1.Status{Message: "sidecar patch creation failed"},
		}
	}
	if req.DryRun != nil && *req.DryRun {
		slog.Info("NRVQ-WHK-4012: dry-run injection", "pod", pod.Name, "namespace", req.Namespace)
	}
	slog.Info("NRVQ-WHK-4003: sidecar injected", "pod", pod.Name, "latency_us", time.Since(start).Microseconds())
	patchType := admissionv1.PatchTypeJSONPatch
	return &admissionv1.AdmissionResponse{Allowed: true, Patch: patch, PatchType: &patchType}
}

func parsePod(req *admissionv1.AdmissionRequest) (*corev1.Pod, bool) {
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		slog.Error("NRVQ-WHK-4006: pod unmarshal failed", "error", err)
		return nil, false
	}
	return &pod, true
}

// hasSidecar reports whether the pod already carries the REAL enforcement sidecar. It must not trust
// the attacker-controllable container NAME (an attacker can add a decoy container named
// "norviq-sidecar" running anything, which previously caused the real sidecar to be silently skipped
// and the pod to run unpoliced). Instead it checks injector-controlled signals only: the container
// IMAGE matches the currently configured sidecar image (injectedAnnotation
// (norviq.io/injected=true), which the injector itself stamps on every patch it produces (handles the
// case where the configured image has since changed via NrvqConfig and an already-injected pod's
// image no longer matches the current default).
func hasSidecar(cfg Config, pod *corev1.Pod) bool {
	if pod.Annotations[injectedAnnotation] == "true" {
		return true
	}
	runtime := cfg.Runtime
	if runtime == nil {
		runtime = &RuntimeConfig{}
		runtime.SetSidecarImage(cfg.SidecarImage)
	}
	configuredImage := runtime.SidecarImage(cfg.SidecarImage)
	for _, c := range pod.Spec.Containers {
		if c.Image != "" && c.Image == configuredImage {
			return true
		}
	}
	return false
}

func hasSocketMount(container corev1.Container) bool {
	for _, mount := range container.VolumeMounts {
		if mount.Name == "norviq-socket" || mount.MountPath == socketMountPath {
			return true
		}
	}
	return false
}

func isValidLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func isClusterPriorityAdmin(groups []string) bool {
	for _, group := range groups {
		if group == "system:masters" {
			return true
		}
	}
	return false
}
