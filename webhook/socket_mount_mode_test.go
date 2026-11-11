// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

// The enforcement socket directory is writable only by the injected sidecar.
//
// The sidecar binds the socket into the shared norviq-socket volume, and every other container the
// injector wires reaches it there. Connecting to a unix socket needs no write access to the directory
// holding it, so every injected socket mount is readOnly except the sidecar's own.

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// assertOnlyTheSidecarWritesTheSocketDir checks every container of an admitted pod: the sidecar mounts
// norviq-socket read-write, every other container mounts it readOnly, and every container has it.
func assertOnlyTheSidecarWritesTheSocketDir(t *testing.T, pod corev1.Pod) {
	t.Helper()
	all := append(append([]corev1.Container{}, pod.Spec.InitContainers...), pod.Spec.Containers...)
	sawSidecar := false
	for _, c := range all {
		var mounts []corev1.VolumeMount
		for _, m := range c.VolumeMounts {
			if m.Name == socketVolumeName {
				mounts = append(mounts, m)
			}
		}
		if len(mounts) != 1 {
			t.Fatalf("container %s has %d norviq-socket mounts, want 1: %+v", c.Name, len(mounts), c.VolumeMounts)
		}
		if c.Name == injectedSidecarName {
			sawSidecar = true
			if mounts[0].ReadOnly {
				t.Fatalf("the sidecar's socket mount is readOnly; it could not bind the socket: %+v", mounts[0])
			}
			continue
		}
		if !mounts[0].ReadOnly {
			t.Fatalf("container %s mounts the socket directory read-write; only the sidecar may: %+v", c.Name, mounts[0])
		}
	}
	if !sawSidecar {
		t.Fatal("the admitted pod has no injected sidecar")
	}
}

func TestInjectedSocketMountIsReadOnlyExceptForTheSidecar(t *testing.T) {
	always := corev1.ContainerRestartPolicyAlways
	withInitAndNativeSidecar := func() corev1.Pod {
		p := integrityPod()
		p.Spec.InitContainers = []corev1.Container{
			{Name: "migrate", Image: "mycorp/migrate:v1"},
			{Name: "guard", Image: "python:3.12-slim", RestartPolicy: &always,
				Command: []string{"python", "-c", "import time; time.sleep(3600)"}},
		}
		p.Spec.Containers = append(p.Spec.Containers, corev1.Container{Name: "worker", Image: "mycorp/worker:v1"})
		return p
	}
	withOwnMounts := func() corev1.Pod {
		p := integrityPod()
		p.Spec.Volumes = []corev1.Volume{{Name: "data", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
		p.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: "data", MountPath: "/data"}}
		return p
	}
	cases := map[string]struct {
		cfg func() Config
		pod func() corev1.Pod
	}{
		"single app container":                            {integrityConfig, integrityPod},
		"init container, native init sidecar, two apps":   {integrityConfig, withInitAndNativeSidecar},
		"app container with mounts of its own":            {integrityConfig, withOwnMounts},
		"SPIFFE injection":                                {spiffeIntegrityConfig, withInitAndNativeSidecar},
		"MCP injection, delivery init container included": {mcpIntegrityConfig, mcpIntegrityPod},
		"opt-out disallowed: an opted-out pod is injected": {func() Config {
			cfg := integrityConfig()
			cfg.AllowPodOptOut = false
			return cfg
		}, func() corev1.Pod {
			p := withInitAndNativeSidecar()
			p.Labels["norviq-injection"] = "disabled"
			return p
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			assertOnlyTheSidecarWritesTheSocketDir(t, assertInjected(t, tc.cfg(), tc.pod()))
		})
	}
}
