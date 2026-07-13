// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"encoding/json"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestCreatePatchWithVolumes(t *testing.T) {
	inj := NewInjector(LoadConfig())
	pod := testPodWithContainers([]corev1.Volume{{Name: "existing"}}, []corev1.Container{{Name: "app", VolumeMounts: []corev1.VolumeMount{{Name: "a", MountPath: "/a"}}, Env: []corev1.EnvVar{{Name: "X", Value: "Y"}}}})
	patch, err := inj.CreatePatch(pod, "sales", "default")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	if len(ops) != 5 || ops[1].Path != "/spec/volumes/-" || ops[2].Path != "/spec/containers/0/volumeMounts/-" || ops[3].Path != "/spec/containers/0/env/-" {
		t.Fatal("expected append volume patch when volumes exist")
	}
}

func TestCreatePatchWithoutVolumes(t *testing.T) {
	inj := NewInjector(LoadConfig())
	pod := testPodWithContainers(nil, []corev1.Container{{Name: "app"}})
	patch, err := inj.CreatePatch(pod, "sales", "default")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	if len(ops) != 5 || ops[1].Path != "/spec/volumes" || ops[2].Path != "/spec/containers/0/volumeMounts" || ops[3].Path != "/spec/containers/0/env" {
		t.Fatal("expected volumes initialization patch when no volumes exist")
	}
}

func TestCreatePatchSkipsDuplicateMountAndEnv(t *testing.T) {
	inj := NewInjector(LoadConfig())
	pod := testPodWithContainers([]corev1.Volume{{Name: "existing"}}, []corev1.Container{{
		Name:         "app",
		VolumeMounts: []corev1.VolumeMount{{Name: "norviq-socket", MountPath: socketMountPath}},
		Env:          []corev1.EnvVar{{Name: "NRVQ_SOCKET_PATH", Value: socketFilePath}},
	}})
	patch, err := inj.CreatePatch(pod, "sales", "default")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	if len(ops) != 3 {
		t.Fatalf("expected only sidecar+volume+annotation ops, got %d", len(ops))
	}
}

func TestMutate_EmptyVolumes(t *testing.T) {
	inj := NewInjector(LoadConfig())
	patch, err := inj.CreatePatch(testPodWithContainers(nil, []corev1.Container{{Name: "app"}}), "sales", "default")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	if len(ops) < 2 || ops[1].Path != "/spec/volumes" {
		t.Fatal("expected initial volumes array patch")
	}
}

func TestMutate_ExistingVolumes(t *testing.T) {
	inj := NewInjector(LoadConfig())
	patch, err := inj.CreatePatch(testPodWithContainers([]corev1.Volume{{Name: "existing"}}, []corev1.Container{{Name: "app"}}), "sales", "default")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	if len(ops) < 2 || ops[1].Path != "/spec/volumes/-" {
		t.Fatal("expected append volumes patch")
	}
}

func TestInjector_SecurityContext(t *testing.T) {
	inj := NewInjector(LoadConfig())
	sidecar := inj.buildSidecar("sales", "default")
	sec := sidecar["securityContext"].(map[string]interface{})
	if sec["runAsNonRoot"] != true {
		t.Fatal("expected runAsNonRoot true")
	}
	drop := sec["capabilities"].(map[string]interface{})["drop"].([]string)
	if len(drop) == 0 || drop[0] != "ALL" {
		t.Fatal("expected drop ALL capabilities")
	}
}

func TestInjector_ResourceLimits(t *testing.T) {
	inj := NewInjector(LoadConfig())
	sidecar := inj.buildSidecar("sales", "default")
	resources := sidecar["resources"].(map[string]interface{})
	requests := resources["requests"].(map[string]string)
	limits := resources["limits"].(map[string]string)
	if requests["cpu"] == "" || requests["memory"] == "" || limits["cpu"] == "" || limits["memory"] == "" {
		t.Fatal("expected cpu/memory requests and limits")
	}
}

func TestInjector_VolumeSizeLimit(t *testing.T) {
	inj := NewInjector(LoadConfig())
	volume := inj.sharedVolume
	emptyDir := volume["emptyDir"].(map[string]interface{})
	if emptyDir["sizeLimit"] != "10Mi" {
		t.Fatalf("expected sizeLimit 10Mi, got %v", emptyDir["sizeLimit"])
	}
}

func TestInjector_ValidateImage(t *testing.T) {
	inj := NewInjector(LoadConfig())
	if !inj.validateImage("norviq/norviq-engine:engine-latest") {
		t.Fatal("expected official image to be allowed")
	}
	if !inj.validateImage("docker.io/norviq/norviq-engine:engine-latest") {
		t.Fatal("expected docker.io official image to be allowed")
	}
	if inj.validateImage("attacker/malware:latest") {
		t.Fatal("expected unauthorized image to be rejected")
	}
}

func TestCreatePatchSpiffeInject(t *testing.T) {
	// B3: with SpiffeInject on, injected pods also get the SPIFFE CSI volume + mount + env.
	cfg := LoadConfig()
	cfg.SpiffeInject = true
	cfg.SpiffeMode = "workload-api"
	cfg.SpiffeSocket = "/spiffe-workload-api/spire-agent.sock"
	inj := NewInjector(cfg)
	pod := testPodWithContainers(nil, []corev1.Container{{Name: "app"}})
	patch, err := inj.CreatePatch(pod, "sales", "default")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	s := string(patch)
	for _, want := range []string{"csi.spiffe.io", "spiffe-workload-api", "NRVQ_SPIFFE_MODE", "workload-api", "NRVQ_SPIFFE_SOCKET"} {
		if !strings.Contains(s, want) {
			t.Fatalf("expected injected patch to contain %q; got %s", want, s)
		}
	}
	// Sidecar (first container patch) must mount the spiffe volume too.
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	sidecar, _ := json.Marshal(ops[0].Value)
	if !strings.Contains(string(sidecar), "spiffe-workload-api") {
		t.Fatalf("expected sidecar to mount spiffe-workload-api; got %s", sidecar)
	}
}

func TestCreatePatchSpiffeInjectOffByDefault(t *testing.T) {
	// Default config (SpiffeInject=false) must NOT add any SPIFFE volume/env -> injection unchanged.
	inj := NewInjector(LoadConfig())
	patch, _ := inj.CreatePatch(testPodWithContainers(nil, []corev1.Container{{Name: "app"}}), "sales", "default")
	if strings.Contains(string(patch), "spiffe") {
		t.Fatalf("default injection must not reference spiffe; got %s", patch)
	}
}

// FIX 4: the injector must stamp injectedAnnotation on every patch it produces so hasSidecar
// (handler.go) can positively identify a real prior injection independent of the attacker-controllable
// container name.
func TestCreatePatchStampsInjectedAnnotation(t *testing.T) {
	inj := NewInjector(LoadConfig())
	pod := testPodWithContainers(nil, []corev1.Container{{Name: "app"}})
	patch, err := inj.CreatePatch(pod, "sales", "default")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	last := ops[len(ops)-1]
	if last.Path != "/metadata/annotations" {
		t.Fatalf("expected initial annotations map patch, got path %q", last.Path)
	}
	value, ok := last.Value.(map[string]interface{})
	if !ok || value[injectedAnnotation] != "true" {
		t.Fatalf("expected %s=true annotation, got %+v", injectedAnnotation, last.Value)
	}
}

func TestCreatePatchStampsInjectedAnnotationWhenAnnotationsExist(t *testing.T) {
	inj := NewInjector(LoadConfig())
	pod := testPodWithContainers(nil, []corev1.Container{{Name: "app"}})
	pod.Annotations = map[string]string{"other": "value"}
	patch, err := inj.CreatePatch(pod, "sales", "default")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	last := ops[len(ops)-1]
	if last.Path != "/metadata/annotations/norviq.io~1injected" || last.Value != "true" {
		t.Fatalf("expected single-key annotation add patch, got %+v", last)
	}
}

func testPodWithContainers(volumes []corev1.Volume, containers []corev1.Container) *corev1.Pod {
	return &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes:    volumes,
			Containers: containers,
		},
	}
}

// SIDE-2/SIDE-1/SIDE-4: proxy-mode sidecar env wiring (default). Asserts the thin-proxy sidecar gets
// the central API URL, a minted service token, the pod namespace, proxy mode, and NO embedded datastore
// wiring — and that embedded mode instead wires Redis/PG/OPA.
func TestSidecarEnvProxyModeWiring(t *testing.T) {
	cfg := LoadConfig()
	cfg.SidecarMode = "proxy"
	cfg.ApiURL = "http://norviq-api:8080"
	cfg.ApiSecret = "test-secret"
	env := sidecarEnv("customer-support", "tenant-b", cfg)
	got := map[string]string{}
	for _, e := range env {
		got[e["name"].(string)] = e["value"].(string)
	}
	if got["NRVQ_SIDECAR_MODE"] != "proxy" {
		t.Fatalf("expected proxy mode, got %q", got["NRVQ_SIDECAR_MODE"])
	}
	if got["NRVQ_NAMESPACE"] != "tenant-b" {
		t.Fatalf("SIDE-4: expected pod namespace tenant-b, got %q", got["NRVQ_NAMESPACE"])
	}
	if got["NRVQ_API_URL"] != "http://norviq-api:8080" {
		t.Fatalf("expected central API URL, got %q", got["NRVQ_API_URL"])
	}
	if got["NRVQ_API_TOKEN"] == "" {
		t.Fatal("expected a minted service token in proxy mode")
	}
	if _, ok := got["NRVQ_REDIS_URL"]; ok {
		t.Fatal("proxy mode must NOT wire NRVQ_REDIS_URL")
	}
}

func TestSidecarEnvEmbeddedModeWiring(t *testing.T) {
	cfg := LoadConfig()
	cfg.SidecarMode = "embedded"
	cfg.RedisURL = "redis://norviq-redis:6379"
	cfg.PgURL = "postgresql://norviq:pw@norviq-postgresql:5432/norviq"
	cfg.OpaMode = "subprocess"
	env := sidecarEnv("customer-support", "default", cfg)
	got := map[string]string{}
	for _, e := range env {
		got[e["name"].(string)] = e["value"].(string)
	}
	if got["NRVQ_SIDECAR_MODE"] != "embedded" {
		t.Fatalf("expected embedded mode, got %q", got["NRVQ_SIDECAR_MODE"])
	}
	if got["NRVQ_REDIS_URL"] == "" || got["NRVQ_PG_URL"] == "" {
		t.Fatal("embedded mode must wire NRVQ_REDIS_URL + NRVQ_PG_URL")
	}
	if got["NRVQ_OPA_MODE"] != "subprocess" {
		t.Fatalf("embedded sidecar OPA should be subprocess, got %q", got["NRVQ_OPA_MODE"])
	}
	if _, ok := got["NRVQ_API_TOKEN"]; ok {
		t.Fatal("embedded mode must NOT mint an API token")
	}
}
