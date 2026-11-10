// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// handler.go serves the admission webhook endpoints: /mutate injects the Norviq
// enforcement sidecar into admitted pods (refusing a pod that already carries any of the
// plumbing the injector adds), and /validate-policy validates NrvqPolicy custom resources.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
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
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

type Handler struct {
	cfg      Config
	injector *Injector
}

const maxAdmissionBodySize = 1 << 20

// injectedAnnotation is stamped onto every pod the injector patches (see injector.go) as an
// operator-visible marker ("this pod was injected"). It is never evidence that a pod is governed: a pod
// author can write it on a CREATE. A pod that arrives carrying it is refused like any other copied
// injector part (injector_owned.go).
const injectedAnnotation = "norviq.io/injected"

var systemExcludedNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
	"norviq":          true,
}

func NewHandler(cfg Config) *Handler {
	inj := NewInjector(cfg)
	// Secret-backed credentials need an API client. Built here rather than in main so it is present
	// for every construction path, and best-effort: OUTSIDE a cluster (unit tests, local runs)
	// InClusterConfig fails and the writer stays nil, which is exactly the previous literal-env
	// behaviour. A webhook that refused to start without Secret write would be a worse default than
	// the exposure it closes.
	if cfg.SidecarSecretEnabled {
		if rc, err := rest.InClusterConfig(); err != nil {
			slog.Info("NRVQ-WHK-4050: no in-cluster config; sidecar credentials stay in pod env",
				"error", err)
		} else if dc, err := dynamic.NewForConfig(rc); err != nil {
			slog.Error("NRVQ-WHK-4051: dynamic client init failed; sidecar credentials stay in pod env",
				"error", err)
		} else {
			inj.SetSecretWriter(NewSecretWriter(dc))
		}
	}
	return &Handler{cfg: cfg, injector: inj}
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
	// A pod that already carries any part the injector adds is refused (injector_owned.go). The webhook
	// is registered for CREATE only, so such a pod is a written or copied spec, never the injector's own
	// output; the webhook builds the plumbing itself, so the fix is always to remove the copied parts.
	// This runs BEFORE the opt-out, so an opted-out pod cannot carry plumbing that reads as enforcement.
	if code, reason, found := injectorPlumbing(h.cfg, pod); found {
		slog.Warn(code+": pod carries injector-owned plumbing", "pod", pod.Name, "namespace", req.Namespace, "reason", reason)
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result:  &metav1.Status{Message: plumbingDenialMessage(code, reason)},
		}
	}
	// No injector-owned part: a fresh pod. Honor an explicit opt-out only when the cluster allows it.
	if optedOut(h.cfg, pod) {
		if h.cfg.AllowPodOptOut {
			slog.Info("NRVQ-WHK-4007: injection opted out for pod", "pod", pod.Name, "namespace", req.Namespace,
				"hint", "remove label "+h.cfg.EnableLabel+"=disabled / annotation norviq.io/skip-injection to enable")
			return &admissionv1.AdmissionResponse{Allowed: true}
		}
		// Pod-level opt-out is disabled cluster-wide — inject anyway so a pod author can't self-exempt.
		slog.Warn("NRVQ-WHK-4009: pod-level injection opt-out is disabled (allowPodOptOut=false); injecting anyway",
			"pod", pod.Name, "namespace", req.Namespace)
	}
	return h.patchResponse(req, pod)
}

func optedOut(cfg Config, pod *corev1.Pod) bool {
	return pod.Labels[cfg.EnableLabel] == "disabled" || pod.Annotations["norviq.io/skip-injection"] == "true"
}

// plumbingDenialMessage is what the pod author sees. It names the part and says what to do, because the
// usual cause is a spec copied from a running pod, and the copy looks correct to whoever made it.
func plumbingDenialMessage(code, reason string) string {
	if code == "NRVQ-WHK-4063" {
		return "NRVQ-WHK-4063: " + reason + ". The norviq webhook adds the sidecar, its volumes and mounts," +
			" NRVQ_SOCKET_PATH, the " + injectedAnnotation + " annotation and any MCP proxy wrapping itself" +
			" when it admits a pod, so a pod spec that already carries any of them is refused (a spec copied" +
			" from a running pod carries all of them). Remove the injected parts from the spec and create" +
			" the pod again; the webhook adds them."
	}
	return code + ": " + reason + ". That path holds the plumbing the norviq webhook adds, so a pod may not" +
		" place a volume, device or termination message file of its own there. Use another path and" +
		" create the pod again."
}

func (h *Handler) patchResponse(req *admissionv1.AdmissionRequest, pod *corev1.Pod) *admissionv1.AdmissionResponse {
	start := time.Now()
	agentClass := pod.Labels[h.cfg.AgentClassLabel]
	if agentClass != "" && !isValidLabel(agentClass) {
		slog.Warn("NRVQ-WHK-4015: invalid agent class label, injecting with empty class", "value", agentClass, "pod", pod.Name, "namespace", req.Namespace)
		agentClass = ""
	}
	dryRun := req.DryRun != nil && *req.DryRun
	patch, err := h.injector.CreatePatch(pod, agentClass, req.Namespace, PatchOptions{DryRun: dryRun})
	if err != nil {
		// A pod whose own MCP annotation cannot be honored gets the reason back: the fix is always in
		// the pod spec (a misnamed container, or one with no explicit command), and a generic failure
		// leaves the operator with nothing to act on. Other patch failures stay generic.
		var mcpErr *mcpConfigError
		if errors.As(err, &mcpErr) {
			slog.Warn("NRVQ-WHK-4041: MCP injection denial", "pod", pod.Name, "namespace", req.Namespace, "error", err)
			return &admissionv1.AdmissionResponse{
				Allowed: false,
				Result: &metav1.Status{Message: "NRVQ-WHK-4041: " + mcpErr.Error() +
					" — the pod asked for MCP governance via " + mcpServersAnnotation +
					" and it could not be applied, so admission fails closed rather than running an" +
					" MCP server unpoliced."},
			}
		}
		// SAY WHY. This returned the bare string "sidecar patch creation failed", so an operator whose
		// namespace had suddenly stopped accepting ANY pod saw a message that named no cause and no
		// fix — the real reason ("unauthorized sidecar image", with the image) was only in the
		// webhook's own logs, which is the last place someone looks when kubectl apply is failing.
		// Observed live: a cluster configured with a dev-package sidecar image the allowlist does not
		// permit refused every pod in four namespaces, and the message said none of that.
		slog.Error("NRVQ-WHK-4009: patch creation failed", "error", err)
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{Message: fmt.Sprintf(
				"sidecar patch creation failed: %v. Admission fails CLOSED rather than running this"+
					" workload unpoliced. Check the webhook's NRVQ_SIDECAR_IMAGE against the injector's"+
					" image allowlist.", err)},
		}
	}
	if dryRun {
		slog.Info("NRVQ-WHK-4012: dry-run injection", "pod", pod.Name, "namespace", req.Namespace)
	}
	// The credential could not be moved out of the pod spec and this operator asked us not to ship one
	// there. Only the handler can refuse, so the injector records the fault and the decision lives here.
	if h.cfg.SidecarSecretRequired && h.injector.lastSecretError != nil {
		slog.Error("NRVQ-WHK-4052: refusing admission — sidecar credential Secret unavailable and"+
			" NRVQ_SIDECAR_SECRET_REQUIRED=true", "namespace", req.Namespace,
			"error", h.injector.lastSecretError)
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{Message: fmt.Sprintf(
				"norviq: could not write the sidecar credential Secret (%v), and"+
					" NRVQ_SIDECAR_SECRET_REQUIRED=true forbids falling back to a literal pod-env"+
					" credential. Check the webhook's RBAC for secrets in namespace %q.",
				h.injector.lastSecretError, req.Namespace)},
		}
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

// allPodContainers is every container a pod author can place a workload in — init AND app containers.
// (Ephemeral containers are a separate subresource and cannot be set on a pod CREATE.)
func allPodContainers(pod *corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	out = append(out, pod.Spec.InitContainers...)
	out = append(out, pod.Spec.Containers...)
	return out
}

// injectedSidecarName is the container name the injector generates (`newSidecarTemplate`). A pod that
// already has a container by that name is refused (injector_owned.go); admitting it would also make the
// injector's own patch add a second container with the same name, which the API server rejects.
const injectedSidecarName = "norviq-sidecar"

func configuredSidecarImage(cfg Config) string {
	runtime := cfg.Runtime
	if runtime == nil {
		runtime = &RuntimeConfig{}
		runtime.SetSidecarImage(cfg.SidecarImage)
	}
	return runtime.SidecarImage(cfg.SidecarImage)
}

func imageName(img string) string {
	if i := strings.IndexByte(img, '@'); i >= 0 { // strip digest
		img = img[:i]
	}
	seg := img
	if slash := strings.LastIndexByte(img, '/'); slash >= 0 {
		seg = img[slash+1:]
	}
	if colon := strings.IndexByte(seg, ':'); colon >= 0 { // strip tag
		seg = seg[:colon]
	}
	return seg
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
