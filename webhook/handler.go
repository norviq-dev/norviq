// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// handler.go serves the admission webhook endpoints: /mutate injects the Norviq
// enforcement sidecar into admitted pods (fail-closed against fake/partial/pre-occupied
// enforcement plumbing), and /validate-policy validates NrvqPolicy custom resources.
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

// injectedAnnotation is stamped onto every pod the injector patches (see injector.go) purely as an
// operator-visible marker ("this pod was injected"). It is NEVER read back as a trust input — a tenant can
// self-stamp it on an unadmitted CREATE. Injection recognition is by structural wiring only (classifyPod).
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
	// Enforcement-integrity classification (the broader webhook-trust bypass class):
	// the norviq-socket volume, the socket mount, the NRVQ_SOCKET_PATH env, and the sidecar container are
	// ALL injector-owned. A fresh tenant pod carries none of them. So: SKIP only a pod that is already
	// FULLY + CORRECTLY injected (idempotent re-admission); DENY a pod that carries norviq enforcement
	// artifacts but is NOT fully injected (a decoy, a pre-occupied socket path/volume/env, or a partially
	// wired pod — the injector cannot safely wire over attacker-placed plumbing, and skipping would run the
	// pod UNPOLICED); otherwise INJECT. This runs BEFORE opt-out so a decoy/pre-occupied pod cannot combine
	// with an opt-out to bypass.
	switch verdict, reason := classifyPod(h.cfg, pod); verdict {
	case verdictDeny:
		slog.Warn("NRVQ-WHK-4034: enforcement-integrity denial", "pod", pod.Name, "namespace", req.Namespace, "reason", reason)
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{Message: "NRVQ-WHK-4034: " + reason +
				" — the norviq webhook owns the sidecar + enforcement-socket plumbing; a pod that presents a fake, partial, or pre-occupied version of it is refused fail-closed. Remove the norviq sidecar / norviq-socket volume+mount / NRVQ_SOCKET_PATH env, or run the pod in a namespace without norviq injection."},
		}
	case verdictSkip:
		slog.Info("NRVQ-WHK-4008: pod already fully injected, skipping", "pod", pod.Name, "namespace", req.Namespace)
		return &admissionv1.AdmissionResponse{Allowed: true}
	}
	// verdictInject: a fresh pod. Honor an explicit opt-out only when the cluster allows it.
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

type podVerdict int

const (
	verdictInject podVerdict = iota
	verdictSkip
	verdictDeny
)

// classifyPod decides inject/skip/deny for a CREATE pod in an injection-enabled namespace. The
// enforcement plumbing — the norviq-socket volume, the socket mount at socketMountPath, the
// NRVQ_SOCKET_PATH env, and the sidecar container — is entirely injector-owned; a fresh tenant pod has
// none of it. The `norviq.io/injected` annotation is NEVER trusted (a tenant can self-stamp it on an
// unadmitted CREATE). Order matters: a neutered decoy is denied first; a fully+correctly injected pod is
// skipped; any REMAINING norviq artifact means the pod is partially/deceptively wired → deny fail-closed;
// otherwise the pod is fresh → inject.
func classifyPod(cfg Config, pod *corev1.Pod) (podVerdict, string) {
	if reason, ok := neuteredSidecarDecoy(cfg, pod); ok {
		return verdictDeny, reason
	}
	if fullyInjected(cfg, pod) {
		return verdictSkip, ""
	}
	if reason, ok := enforcementArtifact(cfg, pod); ok {
		return verdictDeny, reason
	}
	return verdictInject, ""
}

// allPodContainers is every container an attacker can place a workload in — init AND app containers.
// (Ephemeral containers are a separate subresource, not part of a pod CREATE.)
func allPodContainers(pod *corev1.Pod) []corev1.Container {
	out := make([]corev1.Container, 0, len(pod.Spec.InitContainers)+len(pod.Spec.Containers))
	out = append(out, pod.Spec.InitContainers...)
	out = append(out, pod.Spec.Containers...)
	return out
}

// isSidecarContainer reports whether c is (or masquerades as) the enforcement sidecar by image identity:
// the configured image, or the enforcement socket mounted from a same-NAME image (a drifted tag/registry).
// UNCHANGED, and deliberately so: `fullyInjected` depends on it, and loosening the SKIP path would let a
// pod be treated as injected when it is not.
func isSidecarContainer(c corev1.Container, configuredImage string) bool {
	if configuredImage != "" && c.Image == configuredImage {
		return true
	}
	return hasSocketMount(c) && sameSidecarImageName(c.Image, configuredImage)
}

// injectedSidecarName is the container name the injector generates (`newSidecarTemplate`). A container
// that CLAIMS that name is claiming to be the sidecar regardless of what it mounts — and if it were
// admitted, the injector's own patch would add a second container with the same name, which the API
// server rejects outright.
const injectedSidecarName = "norviq-sidecar"

// occupiesEnforcementPath is the DENY-path test. A container is treated as claiming the enforcement
// sidecar's place when it presents as the sidecar AND either touches the enforcement socket or takes
// the injector's own container name.
//
// Image identity ALONE is not enough, and that was a false positive against the product's own shipped
// example: the chatbot runs three `norviq.mcp` proxy containers (`mcp-fw-kb/crm/ops`) FROM THE ENGINE
// IMAGE with their own args. Once an operator aligns image tags — which the chart's upgrade notes
// explicitly instruct — those equal NRVQ_SIDECAR_IMAGE exactly and every pod in the namespace was
// refused as a neutered decoy. The example admitted before only because it pinned a stale engine tag,
// i.e. by accident.
//
// This does not weaken the decoy defence. A socket-less, differently-named container cannot suppress
// injection: `fullyInjected` returns false unless the POD declares the norviq-socket volume, so the pod
// is never skipped — it is injected and the workload stays governed. Everything the deny paths caught
// before is still caught: the socket volume without full injection, a container mounting the socket or
// presetting NRVQ_SOCKET_PATH, and anything taking the sidecar's name. What is no longer denied is the
// one case that was never an attack — another norviq component, sharing the image, nowhere near the
// enforcement path and not pretending to be it.
func occupiesEnforcementPath(c corev1.Container, configuredImage string) bool {
	if !hasSocketMount(c) && !hasSocketPathEnv(c) && c.Name != injectedSidecarName {
		return false
	}
	return isSidecarContainer(c, configuredImage)
}

// neuteredSidecarDecoy: a sidecar-identity container that overrides command/args (the injector never
// does) — it would masquerade as the sidecar while enforcing nothing. Checked across init + app containers.
func neuteredSidecarDecoy(cfg Config, pod *corev1.Pod) (string, bool) {
	configuredImage := configuredSidecarImage(cfg)
	if configuredImage == "" {
		return "", false
	}
	for _, c := range allPodContainers(pod) {
		// The injector's OWN MCP init container is a sidecar-image container that necessarily overrides
		// command (it runs a `cp`), so it would read as a decoy on every re-admission of a pod it was
		// injected into. Exempt it only on an exact match against the spec the injector generates —
		// reproducing that means reproducing the real proxy copy, so the carve-out buys an attacker
		// nothing.
		if cfg.McpInject && isInjectorMcpInitContainer(cfg, c) {
			continue
		}
		if (len(c.Command) > 0 || len(c.Args) > 0) && occupiesEnforcementPath(c, configuredImage) {
			return "container " + c.Name + " presents as the norviq sidecar but overrides command/args (neutered decoy)", true
		}
	}
	return "", false
}

// fullyInjected reports whether the pod EXACTLY carries the injector's output: the norviq-socket volume,
// a real sidecar container (sidecar identity, no command/args override), and EVERY other container (app +
// init) wired to that socket — mounting the norviq-socket volume at socketMountPath AND carrying
// NRVQ_SOCKET_PATH == socketFilePath. Only such a pod is skipped (idempotent re-admission); a pod with a
// sidecar but an UNWIRED app container is NOT "already injected" and must not be skipped, or the app runs
// unpoliced.
func fullyInjected(cfg Config, pod *corev1.Pod) bool {
	configuredImage := configuredSidecarImage(cfg)
	if !hasNorviqSocketVolume(pod) {
		return false
	}
	sidecars := 0
	for _, c := range pod.Spec.Containers {
		// SKIP-path strictness: only a container running a TRUSTED sidecar image (the exact configured
		// image, or the injector's own registry-pinned allowlist) counts as the real sidecar. The broad
		// same-NAME match (isSidecarContainer) is used only on the DENY paths — a same-name image from an
		// attacker registry (e.g. docker.io/attacker/norviq-engine, which the injector itself would refuse
		// to inject) must NOT let a self-wired pod be treated as "already injected" and skipped unpoliced.
		if len(c.Command) == 0 && len(c.Args) == 0 && isSidecarContainer(c, configuredImage) &&
			(c.Image == configuredImage || isAllowedSidecarImage(c.Image)) &&
			sidecarRoutingTrusted(c, cfg) {
			sidecars++
			continue
		}
		if !containerWired(c) {
			return false
		}
	}
	if sidecars == 0 {
		return false
	}
	for _, c := range pod.Spec.InitContainers {
		if !containerWired(c) {
			return false
		}
	}
	// A correct sidecar does not make an MCP server governed. A pod that ASKS for MCP governance but
	// carries an unwrapped (or differently-wrapped) MCP container is not already-injected — skipping it
	// would run that server unpoliced, which is the same hole the app-container check above closes.
	return mcpFullyInjected(cfg, pod)
}

// enforcementArtifact reports any injector-owned plumbing on a pod that is NOT fully injected: a
// sidecar-identity container, a mount at the socket path (or of the norviq-socket volume), a
// NRVQ_SOCKET_PATH env, or a norviq-socket volume. Present-but-not-fully-injected == a partial or
// pre-occupied bypass (the injector can't safely wire over it) → deny fail-closed. Tenant app images use
// their own names, so ordinary workloads never match.
func enforcementArtifact(cfg Config, pod *corev1.Pod) (string, bool) {
	configuredImage := configuredSidecarImage(cfg)
	if hasNorviqSocketVolume(pod) {
		return "pod declares the injector-owned norviq-socket volume but is not fully injected", true
	}
	for _, c := range allPodContainers(pod) {
		if occupiesEnforcementPath(c, configuredImage) {
			return "container " + c.Name + " presents as the norviq sidecar but the pod is not fully injected", true
		}
		if mountsSocketPath(c) {
			return "container " + c.Name + " pre-occupies the enforcement socket mount at " + socketMountPath, true
		}
		if hasSocketPathEnv(c) {
			return "container " + c.Name + " pre-sets the injector-owned NRVQ_SOCKET_PATH env", true
		}
	}
	// MCP plumbing is injector-owned on exactly the same terms. Gated on McpInject so that with the
	// feature off the webhook's admission decisions are unchanged for every possible pod.
	if cfg.McpInject {
		if reason, ok := mcpArtifact(cfg, pod); ok {
			return reason, true
		}
	}
	return "", false
}

func containerWired(c corev1.Container) bool {
	return mountsNorviqSocketVolume(c) && hasCorrectSocketEnv(c)
}

func mountsSocketPath(c corev1.Container) bool {
	for _, m := range c.VolumeMounts {
		if m.MountPath == socketMountPath || m.Name == "norviq-socket" {
			return true
		}
	}
	return false
}

func mountsNorviqSocketVolume(c corev1.Container) bool {
	for _, m := range c.VolumeMounts {
		if m.Name == "norviq-socket" && m.MountPath == socketMountPath {
			return true
		}
	}
	return false
}

func hasSocketPathEnv(c corev1.Container) bool {
	for _, e := range c.Env {
		if e.Name == "NRVQ_SOCKET_PATH" {
			return true
		}
	}
	return false
}

// envValue returns the EFFECTIVE value of an env var — the LAST occurrence, matching Kubernetes' own
// precedence. Reading the first occurrence let an attacker append a second NRVQ_SOCKET_PATH (a valid
// first, an evil last) that passed the check but won at runtime.
func envValue(c corev1.Container, name string) (string, bool) {
	val, found := "", false
	for _, e := range c.Env {
		if e.Name == name {
			val, found = e.Value, true
		}
	}
	return val, found
}

func hasCorrectSocketEnv(c corev1.Container) bool {
	v, ok := envValue(c, "NRVQ_SOCKET_PATH")
	return ok && v == socketFilePath
}

// sidecarRoutingTrusted reports whether a sidecar container's injector-owned ROUTING env points at the
// real control plane. A same-image sidecar with NRVQ_API_URL swung to a co-located allow-all engine (or an
// embedded sidecar pointed at a foreign datastore) enforces nothing; such a pod must NOT be treated as
// already-injected and skipped. The routing env is deterministic injector output, so the skip path
// re-derives + compares it.
func sidecarRoutingTrusted(c corev1.Container, cfg Config) bool {
	mode, _ := envValue(c, "NRVQ_SIDECAR_MODE")
	if mode != sidecarMode(cfg) {
		return false
	}
	if mode == "embedded" {
		// Air-gapped: the sidecar runs its own engine off the cluster datastores; a foreign datastore = no
		// real policy. Every datastore URL the injector sets must match (empty cfg value = not injected).
		if cfg.RedisURL != "" {
			if v, _ := envValue(c, "NRVQ_REDIS_URL"); v != cfg.RedisURL {
				return false
			}
		}
		if cfg.PgURL != "" {
			if v, _ := envValue(c, "NRVQ_PG_URL"); v != cfg.PgURL {
				return false
			}
		}
		return true
	}
	// proxy (default): NRVQ_API_URL must be the injector's value — cfg.ApiURL, or the https upgrade the
	// auto-mTLS path applies (buildSidecarTLSEnv) to a plaintext cfg.ApiURL.
	url, ok := envValue(c, "NRVQ_API_URL")
	if !ok {
		return false
	}
	if url == cfg.ApiURL {
		return true
	}
	return cfg.InternalTLS && !strings.HasPrefix(cfg.ApiURL, "https://") && url == "https://norviq-api:8443"
}

func hasNorviqSocketVolume(pod *corev1.Pod) bool {
	for _, v := range pod.Spec.Volumes {
		if v.Name == "norviq-socket" {
			return true
		}
	}
	return false
}

func configuredSidecarImage(cfg Config) string {
	runtime := cfg.Runtime
	if runtime == nil {
		runtime = &RuntimeConfig{}
		runtime.SetSidecarImage(cfg.SidecarImage)
	}
	return runtime.SidecarImage(cfg.SidecarImage)
}

// sameSidecarImageName reports whether two image refs share the same repository NAME (final path
// segment), ignoring registry, tag and digest — e.g. ghcr.io/norviq-dev/norviq-engine:engine-latest and
// norviq/norviq-engine:some-old-sha both have the name "norviq-engine". Empty names never match.
func sameSidecarImageName(a, configured string) bool {
	na := imageName(a)
	return na != "" && na == imageName(configured)
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
