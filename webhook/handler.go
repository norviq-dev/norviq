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
	"k8s.io/apimachinery/pkg/types"
)

type Handler struct {
	cfg      Config
	injector *Injector
}

const maxAdmissionBodySize = 1 << 20

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
		writeFailOpenResponse(w, uid)
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

func writeFailOpenResponse(w http.ResponseWriter, uid string) {
	review := admissionv1.AdmissionReview{
		Response: &admissionv1.AdmissionResponse{Allowed: true},
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
		return &admissionv1.AdmissionResponse{Allowed: true}
	}
	if shouldSkipInjection(h.cfg, pod, req.Namespace) {
		return &admissionv1.AdmissionResponse{Allowed: true}
	}
	return h.patchResponse(req, pod)
}

func shouldSkipInjection(cfg Config, pod *corev1.Pod, namespace string) bool {
	if pod.Labels[cfg.EnableLabel] == "disabled" || pod.Annotations["norviq.io/skip-injection"] == "true" {
		return true
	}
	if pod.Labels[cfg.EnableLabel] != cfg.EnableValue {
		slog.Debug("NRVQ-WHK-4007: pod skipped", "pod", pod.Name, "namespace", namespace)
		return true
	}
	if hasSidecar(pod) {
		slog.Debug("NRVQ-WHK-4008: sidecar already present", "pod", pod.Name)
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
	patch, err := h.injector.CreatePatch(pod, agentClass)
	if err != nil {
		slog.Error("NRVQ-WHK-4009: patch creation failed", "error", err)
		return &admissionv1.AdmissionResponse{Allowed: true}
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

func hasSidecar(pod *corev1.Pod) bool {
	for _, c := range pod.Spec.Containers {
		if c.Name == "norviq-sidecar" {
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
