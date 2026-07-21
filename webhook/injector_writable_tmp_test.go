// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
package main

import (
	"encoding/json"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// The injected sidecar runs with readOnlyRootFilesystem, but the internal-mTLS client must briefly
// materialize its cert/key as files (stdlib load_cert_chain reads files only). Ship those two facts
// without a writable temp dir and EVERY injected pod crash-loops at start with
// "No usable temporary directory found in ['/tmp','/var/tmp','/usr/tmp','/app']" — the PEP data plane
// never comes up, and the readiness gate holds the workload NotReady forever.
//
// The two halves used to be tested separately (Go asserted the hardened spec; Python asserted the cert
// code against a host that happened to have a writable /tmp), so nothing caught the combination. These
// guards assert the PAIR: hardened root filesystem AND a writable scratch path, sidecar-private.
func TestSidecarHasWritableTempDespiteReadOnlyRoot(t *testing.T) {
	inj := NewInjector(LoadConfig())
	sidecar := inj.buildSidecar("sales", "default")

	sec := sidecar["securityContext"].(map[string]interface{})
	if sec["readOnlyRootFilesystem"] != true {
		t.Fatal("readOnlyRootFilesystem must stay true — do not fix the temp-dir crash by unhardening the sidecar")
	}

	mounts, _ := sidecar["volumeMounts"].([]map[string]interface{})
	var mountPath string
	for _, m := range mounts {
		if m["name"] == tmpVolumeName {
			mountPath, _ = m["mountPath"].(string)
		}
	}
	if mountPath != tmpMountPath {
		t.Fatalf("sidecar has no writable scratch mount %q at %q (mounts=%v); the mTLS cert load will fail closed at startup",
			tmpVolumeName, tmpMountPath, mounts)
	}
}

// The scratch volume must be an in-memory emptyDir: the client private key is written there (0600,
// unlinked immediately), so it must never land on a real disk.
func TestSidecarTempVolumeIsTmpfs(t *testing.T) {
	vol := tmpVolumeTemplate()
	if vol["name"] != tmpVolumeName {
		t.Fatalf("unexpected scratch volume name: %v", vol["name"])
	}
	ed, ok := vol["emptyDir"].(map[string]interface{})
	if !ok {
		t.Fatalf("scratch volume must be an emptyDir, got %v", vol)
	}
	if ed["medium"] != "Memory" {
		t.Fatalf("scratch volume must be tmpfs (medium: Memory) so the mTLS key never hits disk, got %v", ed["medium"])
	}
}

// Key isolation: the scratch volume is mounted into the SIDECAR only. If it were ever added to the app
// container (or to the shared norviq-socket volume the app mounts), the workload could read the
// sidecar's mTLS client key — i.e. impersonate the PEP to the control plane.
func TestSidecarTempVolumeNotMountedIntoAppContainer(t *testing.T) {
	inj := NewInjector(LoadConfig())
	pod := testPodWithContainers(nil, []corev1.Container{{Name: "app"}})
	patch, err := inj.CreatePatch(pod, "sales", "default")
	if err != nil {
		t.Fatalf("create patch failed: %v", err)
	}
	var ops []patchOp
	if err := json.Unmarshal(patch, &ops); err != nil {
		t.Fatalf("unmarshal patch: %v", err)
	}
	for _, op := range ops {
		// Any patch targeting an app/init container's volumeMounts must not reference the scratch volume.
		if op.Path == "/spec/containers/0/volumeMounts" || op.Path == "/spec/containers/0/volumeMounts/-" {
			if blob, _ := json.Marshal(op.Value); containsName(blob, tmpVolumeName) {
				t.Fatalf("scratch volume %q must never be mounted into the app container: %s", tmpVolumeName, blob)
			}
		}
	}
}

func containsName(blob []byte, name string) bool {
	var probe interface{}
	if err := json.Unmarshal(blob, &probe); err != nil {
		return false
	}
	return jsonHasString(probe, name)
}

func jsonHasString(v interface{}, want string) bool {
	switch t := v.(type) {
	case string:
		return t == want
	case []interface{}:
		for _, e := range t {
			if jsonHasString(e, want) {
				return true
			}
		}
	case map[string]interface{}:
		for _, e := range t {
			if jsonHasString(e, want) {
				return true
			}
		}
	}
	return false
}
