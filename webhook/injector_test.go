// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestCreatePatchWithVolumes(t *testing.T) {
	inj := NewInjector(LoadConfig())
	pod := testPodWithContainers([]corev1.Volume{{Name: "existing"}}, []corev1.Container{{Name: "app", VolumeMounts: []corev1.VolumeMount{{Name: "a", MountPath: "/a"}}, Env: []corev1.EnvVar{{Name: "X", Value: "Y"}}}})
	patch, err := inj.CreatePatch(pod, "sales")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	if len(ops) != 4 || ops[1].Path != "/spec/volumes/-" || ops[2].Path != "/spec/containers/0/volumeMounts/-" || ops[3].Path != "/spec/containers/0/env/-" {
		t.Fatal("expected append volume patch when volumes exist")
	}
}

func TestCreatePatchWithoutVolumes(t *testing.T) {
	inj := NewInjector(LoadConfig())
	pod := testPodWithContainers(nil, []corev1.Container{{Name: "app"}})
	patch, err := inj.CreatePatch(pod, "sales")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	if len(ops) != 4 || ops[1].Path != "/spec/volumes" || ops[2].Path != "/spec/containers/0/volumeMounts" || ops[3].Path != "/spec/containers/0/env" {
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
	patch, err := inj.CreatePatch(pod, "sales")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	_ = json.Unmarshal(patch, &ops)
	if len(ops) != 2 {
		t.Fatalf("expected only sidecar+volume ops, got %d", len(ops))
	}
}

func TestMutate_EmptyVolumes(t *testing.T) {
	inj := NewInjector(LoadConfig())
	patch, err := inj.CreatePatch(testPodWithContainers(nil, []corev1.Container{{Name: "app"}}), "sales")
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
	patch, err := inj.CreatePatch(testPodWithContainers([]corev1.Volume{{Name: "existing"}}, []corev1.Container{{Name: "app"}}), "sales")
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
	sidecar := inj.buildSidecar("sales")
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
	sidecar := inj.buildSidecar("sales")
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
	if !inj.validateImage("sanman97/norviq-engine:engine-latest") {
		t.Fatal("expected official image to be allowed")
	}
	if !inj.validateImage("docker.io/sanman97/norviq-engine:engine-latest") {
		t.Fatal("expected docker.io official image to be allowed")
	}
	if inj.validateImage("attacker/malware:latest") {
		t.Fatal("expected unauthorized image to be rejected")
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
