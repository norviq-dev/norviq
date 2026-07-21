// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

// Webhook enforcement-integrity: the norviq-socket volume, the socket mount, the
// NRVQ_SOCKET_PATH env and the sidecar container are injector-owned. A tenant with pod-create RBAC could
// otherwise run UNPOLICED by presenting a fake/partial/pre-occupied version of that plumbing so injection
// is skipped, or a genuine sidecar that leaves the app unwired. The webhook: DENIES a neutered decoy
// (command/args override), DENIES any pod that carries norviq artifacts without being FULLY injected, and
// wires initContainers too.

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func gvkPod() metav1.GroupVersionKind { return metav1.GroupVersionKind{Kind: "Pod"} }

func enabledPod(name string, spec corev1.PodSpec) corev1.Pod {
	return corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"norviq": "enabled"}}, Spec: spec}
}

// --- neutered command/args-override decoys → DENY ------------------------------------------

func TestMutateDecoyImageWithCommandOverrideIsDenied(t *testing.T) {
	cfg := LoadConfig()
	pod := enabledPod("attacker", corev1.PodSpec{Containers: []corev1.Container{
		{Name: "app", Image: "nginx"},
		{Name: "norviq-sidecar", Image: cfg.SidecarImage, Command: []string{"sleep", "infinity"}},
	}})
	resp := sendReview(t, NewHandler(cfg), makeReviewFromPod(pod, gvkPod(), "default"))
	if resp.Response.Allowed {
		t.Fatal("sidecar image + command override must be DENIED (neutered decoy)")
	}
}

func TestMutateDecoyImageWithArgsOverrideIsDenied(t *testing.T) {
	cfg := LoadConfig()
	pod := enabledPod("attacker", corev1.PodSpec{Containers: []corev1.Container{
		{Name: "norviq-sidecar", Image: cfg.SidecarImage, Args: []string{"--do-nothing"}},
	}})
	resp := sendReview(t, NewHandler(cfg), makeReviewFromPod(pod, gvkPod(), "default"))
	if resp.Response.Allowed {
		t.Fatal("sidecar image + args override must be DENIED")
	}
}

func TestMutateDecoySocketMountSameNameWithCommandIsDenied(t *testing.T) {
	pod := enabledPod("attacker", corev1.PodSpec{Containers: []corev1.Container{
		{Name: "norviq-sidecar", Image: "attacker/norviq-engine:evil", Command: []string{"sh", "-c", "sleep 1d"},
			VolumeMounts: []corev1.VolumeMount{{Name: "norviq-socket", MountPath: socketMountPath}}},
	}})
	resp := sendReview(t, NewHandler(LoadConfig()), makeReviewFromPod(pod, gvkPod(), "default"))
	if resp.Response.Allowed {
		t.Fatal("socket-mounting same-name image + command override must be DENIED")
	}
}

// --- Bypass: a bare REAL-image sidecar (no command) that leaves the app unwired → DENY ------------
// (Pre-hardening this was SKIPPED — hasSidecar matched the image and suppressed injection, app unpoliced.)

func TestMutateBareSidecarImageUnwiredAppIsDenied(t *testing.T) {
	cfg := LoadConfig()
	pod := enabledPod("attacker", corev1.PodSpec{Containers: []corev1.Container{
		{Name: "agent", Image: "attacker/agent:latest"}, // NOT wired to the socket
		{Name: "norviq-sidecar", Image: cfg.SidecarImage}, // real image, no command
	}})
	resp := sendReview(t, NewHandler(cfg), makeReviewFromPod(pod, gvkPod(), "default"))
	if resp.Response.Allowed {
		t.Fatal("a sidecar-image container with an UNWIRED app must be DENIED (was skipped → app unpoliced)")
	}
}

// --- Bypass: pre-occupying the enforcement socket mount path → DENY ------------------------------

func TestMutateAppPreoccupiesSocketMountIsDenied(t *testing.T) {
	pod := enabledPod("attacker", corev1.PodSpec{
		Volumes: []corev1.Volume{{Name: "evil-sock", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}},
		Containers: []corev1.Container{
			{Name: "agent", Image: "myrepo/agent:latest",
				VolumeMounts: []corev1.VolumeMount{{Name: "evil-sock", MountPath: socketMountPath}}},
		},
	})
	resp := sendReview(t, NewHandler(LoadConfig()), makeReviewFromPod(pod, gvkPod(), "default"))
	if resp.Response.Allowed {
		t.Fatal("an app container pre-mounting a foreign volume at the enforcement socket path must be DENIED")
	}
}

// --- Bypass: pre-setting the injector-owned NRVQ_SOCKET_PATH env → DENY --------------------------

func TestMutateAppPresetsSocketEnvIsDenied(t *testing.T) {
	pod := enabledPod("attacker", corev1.PodSpec{Containers: []corev1.Container{
		{Name: "agent", Image: "myrepo/agent:latest", Env: []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: "/tmp/evil.sock"}}},
	}})
	resp := sendReview(t, NewHandler(LoadConfig()), makeReviewFromPod(pod, gvkPod(), "default"))
	if resp.Response.Allowed {
		t.Fatal("an app container pre-setting NRVQ_SOCKET_PATH must be DENIED (suppresses the real wiring)")
	}
}

// --- Bypass: a benign image merely mounting the socket path (no command) → DENY ------------------

func TestMutateBenignSocketMountDecoyIsDenied(t *testing.T) {
	pod := enabledPod("attacker", corev1.PodSpec{Containers: []corev1.Container{
		{Name: "app", Image: "nginx"},
		{Name: "fake", Image: "busybox", VolumeMounts: []corev1.VolumeMount{{Name: "norviq-socket", MountPath: socketMountPath}}},
	}})
	resp := sendReview(t, NewHandler(LoadConfig()), makeReviewFromPod(pod, gvkPod(), "default"))
	if resp.Response.Allowed {
		t.Fatal("a benign container pre-occupying the norviq-socket mount must be DENIED")
	}
}

// --- Bypass: an agent workload hidden in an initContainer must be WIRED (injected), not ignored ---

func TestMutateInitContainerWorkloadIsWired(t *testing.T) {
	pod := enabledPod("attacker", corev1.PodSpec{
		InitContainers: []corev1.Container{{Name: "payload", Image: "attacker/agent:latest", Command: []string{"/agent", "--run"}}},
		Containers:     []corev1.Container{{Name: "pause", Image: "registry.k8s.io/pause:3.9"}},
	})
	resp := sendReview(t, NewHandler(LoadConfig()), makeReviewFromPod(pod, gvkPod(), "default"))
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("a fresh pod with an init-container workload must be injected (patch expected)")
	}
	// the patch must wire the init container (socket mount + env on /spec/initContainers/0)
	if !strings.Contains(string(resp.Response.Patch), "/spec/initContainers/0/") {
		t.Fatal("the injection patch must wire the initContainer to the enforcement socket (none found)")
	}
}

// --- FALSE-POSITIVE GUARD: a genuinely FULLY-injected pod (app with its own command, correctly wired,
// real sidecar) is recognized and skipped — NOT denied. -----------------------------------------------

func TestMutateFullyInjectedPodWithAppCommandSkips(t *testing.T) {
	cfg := LoadConfig()
	pod := enabledPod("legit", corev1.PodSpec{
		Volumes: []corev1.Volume{{Name: "norviq-socket"}},
		Containers: []corev1.Container{
			{Name: "app", Image: "mycorp/app:v1", Command: []string{"/app/server"},
				VolumeMounts: []corev1.VolumeMount{{Name: "norviq-socket", MountPath: socketMountPath}},
				Env:          []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}}},
			trustedSidecar("norviq-sidecar", cfg.SidecarImage, cfg),
		},
	})
	resp := sendReview(t, NewHandler(cfg), makeReviewFromPod(pod, gvkPod(), "default"))
	if !resp.Response.Allowed {
		t.Fatal("a fully-injected pod (wired app + real sidecar) must NOT be denied")
	}
	if resp.Response.Patch != nil {
		t.Fatal("a fully-injected pod must be recognized as already-injected (no patch)")
	}
}

// A REAL-image sidecar whose NRVQ_API_URL is swung to a co-located allow-all engine
// enforces nothing — must be DENIED, not skipped. (fullyInjected re-derives the injector's routing env.)
func TestMutateSidecarWithRogueApiUrlIsDenied(t *testing.T) {
	cfg := LoadConfig()
	pod := enabledPod("attacker", corev1.PodSpec{
		Volumes: []corev1.Volume{{Name: "norviq-socket"}},
		Containers: []corev1.Container{
			fullyInjectedContainer("agent", "mycorp/app:v1"),
			{Name: "norviq-sidecar", Image: cfg.SidecarImage, Env: []corev1.EnvVar{
				{Name: "NRVQ_SIDECAR_MODE", Value: "proxy"},
				{Name: "NRVQ_API_URL", Value: "http://127.0.0.1:9999"}, // rogue allow-all backend
			}},
		},
	})
	resp := sendReview(t, NewHandler(cfg), makeReviewFromPod(pod, gvkPod(), "default"))
	if resp.Response.Allowed {
		t.Fatal("a real-image sidecar pointed at a rogue NRVQ_API_URL must be DENIED, not skipped")
	}
}

// A duplicate NRVQ_SOCKET_PATH (valid first, evil last — K8s uses the last) on the
// app container must NOT pass containerWired. The pod is then not fully injected → DENIED.
func TestMutateDuplicateSocketEnvIsDenied(t *testing.T) {
	cfg := LoadConfig()
	pod := enabledPod("attacker", corev1.PodSpec{
		Volumes: []corev1.Volume{{Name: "norviq-socket"}},
		Containers: []corev1.Container{
			{Name: "agent", Image: "mycorp/app:v1",
				VolumeMounts: []corev1.VolumeMount{{Name: "norviq-socket", MountPath: socketMountPath}},
				Env: []corev1.EnvVar{
					{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath},   // decoy first
					{Name: "NRVQ_SOCKET_PATH", Value: "/tmp/evil.sock"}, // wins at runtime
				}},
			trustedSidecar("norviq-sidecar", cfg.SidecarImage, cfg),
		},
	})
	resp := sendReview(t, NewHandler(cfg), makeReviewFromPod(pod, gvkPod(), "default"))
	if resp.Response.Allowed {
		t.Fatal("a duplicate NRVQ_SOCKET_PATH (evil last) must be DENIED (effective value validated)")
	}
}

// A same-NAME but untrusted-REGISTRY fake sidecar (attacker/norviq-engine, which
// the injector's own allowlist would refuse) with a self-wired app must be DENIED — not accepted as
// "already injected" and skipped. The skip path enforces the registry-pinned allowlist; the broad
// same-name match is only safe on the deny paths.
func TestMutateSameNameUntrustedRegistrySidecarIsDenied(t *testing.T) {
	cfg := LoadConfig()
	// trusted routing env on the fake sidecar isolates the check: only the REGISTRY allowlist denies it.
	fake := trustedSidecar("norviq-sidecar", "attacker/norviq-engine:evil", cfg,
		corev1.VolumeMount{Name: "norviq-socket", MountPath: socketMountPath})
	pod := enabledPod("attacker", corev1.PodSpec{
		Volumes:    []corev1.Volume{{Name: "norviq-socket"}},
		Containers: []corev1.Container{fullyInjectedContainer("agent", "mycorp/app:v1"), fake},
	})
	resp := sendReview(t, NewHandler(cfg), makeReviewFromPod(pod, gvkPod(), "default"))
	if resp.Response.Allowed {
		t.Fatal("a same-name but untrusted-registry fake sidecar must be DENIED (registry allowlist on the skip path)")
	}
}

// A completely fresh pod still injects normally (baseline sanity).
func TestMutateFreshPodInjects(t *testing.T) {
	pod := enabledPod("fresh", corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "nginx"}}})
	resp := sendReview(t, NewHandler(LoadConfig()), makeReviewFromPod(pod, gvkPod(), "default"))
	if !resp.Response.Allowed || resp.Response.Patch == nil {
		t.Fatal("a fresh pod must be injected (patch expected)")
	}
}
