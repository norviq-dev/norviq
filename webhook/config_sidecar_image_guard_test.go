// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

package main

import (
	"os"
	"testing"
)

// A sidecar image outside the allowlist must be caught where it is CONFIGURED, not where a pod is
// admitted. CreatePatch refuses such an image and admission fails closed on the refusal — correct for
// a security control, and catastrophic as a first symptom: every pod in every injection-enabled
// namespace is denied, with the reason only in the webhook's logs.
//
// Observed live: a cluster deployed from the dev image package
// (ghcr.io/norviq-dev/norviq-engine-dev:engine-<sha>) stopped accepting workloads in four namespaces.
// The allowlist permits ghcr.io/norviq-dev/norviq-engine; it does not permit ...-engine-dev. The
// deploy that caused it reported success.
func TestConfiguredSidecarImageOutsideAllowlistFallsBackInsteadOfDenyingEveryPod(t *testing.T) {
	t.Setenv("NRVQ_SIDECAR_IMAGE", "ghcr.io/norviq-dev/norviq-engine-dev:engine-deadbeef")
	cfg := LoadConfig()
	if !isAllowedSidecarImage(cfg.SidecarImage) {
		t.Fatalf("config kept a non-allowlisted sidecar image %q; every pod in an injection-enabled "+
			"namespace would be denied at admission", cfg.SidecarImage)
	}
}

// The inverse: a legitimate override must survive untouched. A guard that clobbers valid config is
// its own outage — an operator pinning a specific released digest must get that digest.
func TestAllowlistedSidecarImageOverrideIsKept(t *testing.T) {
	const want = "ghcr.io/norviq-dev/norviq-engine:engine-1234567890abcdef"
	t.Setenv("NRVQ_SIDECAR_IMAGE", want)
	if got := LoadConfig().SidecarImage; got != want {
		t.Fatalf("a valid, allowlisted override was replaced: got %q, want %q", got, want)
	}
}

func TestDefaultSidecarImageIsItselfAllowlisted(t *testing.T) {
	// If the built-in default were not allowlisted, the fallback above would hand back something
	// CreatePatch also refuses — the guard would swap one cluster-wide denial for another.
	os.Unsetenv("NRVQ_SIDECAR_IMAGE")
	if got := LoadConfig().SidecarImage; !isAllowedSidecarImage(got) {
		t.Fatalf("the built-in default sidecar image %q is not allowlisted", got)
	}
}
