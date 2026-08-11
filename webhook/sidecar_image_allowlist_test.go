// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

package main

import "testing"

// The allow-list had no test at all, which is how it shipped rejecting the sidecar image every
// release actually pins. release_stamp.py writes NRVQ_SIDECAR_IMAGE as an immutable
// `...@sha256:<64 hex>` digest; the pattern only accepted `:tag`, so on a published chart the
// webhook refused to build a patch and — under failurePolicy Fail — the agent pod was DENIED.
// The checked-in chart's `-latest` tags passed, so nothing local ever reproduced it.
func TestIsAllowedSidecarImage(t *testing.T) {
	const digest = "@sha256:305f35742c675a455416ca01086b8174f5999ecf3704ed26591b8dc157a3d381"

	allowed := []string{
		// what a RELEASE injects — the case that was broken
		"ghcr.io/norviq-dev/norviq-engine" + digest,
		"norviq/norviq-engine" + digest,
		"docker.io/norviq/norviq-engine" + digest,
		// what a checkout injects
		"ghcr.io/norviq-dev/norviq-engine:engine-latest",
		"ghcr.io/norviq-dev/norviq-engine:engine-0.1.6",
		// what a RELEASE CANDIDATE injects. Excluding the -dev package meant a candidate sidecar
		// could never run on a cluster: the injector rejected it, silently substituted
		// norviq-engine:engine-latest (NRVQ-WHK-4062), and "injection validated on AKS" covered
		// main's sidecar rather than the one under test. Observed live before this was widened.
		"ghcr.io/norviq-dev/norviq-engine-dev:engine-latest",
		"ghcr.io/norviq-dev/norviq-engine-dev" + digest,
		"ghcr.io/norviq-dev/norviq-engine-dev:engine-87e893c30be7c83e18e7bd6c34da84922547c3ee",
	}
	for _, img := range allowed {
		if !isAllowedSidecarImage(img) {
			t.Errorf("must allow %q", img)
		}
	}

	denied := []string{
		"evil.example.com/norviq/norviq-engine:engine-0.1.6",        // foreign registry
		"ghcr.io/norviq-dev/norviq-engine",                          // no tag and no digest
		"ghcr.io/norviq-dev/other-image" + digest,                   // right registry, wrong image
		"ghcr.io/norviq-dev/norviq-engine@sha256:tooshort",          // malformed digest
		"ghcr.io/norviq-dev/norviq-engine@md5:" + digest[8:],        // wrong algorithm
		"ghcr.io/norviq-dev/norviq-engine:tag@sha256:" + digest[8:], // tag AND digest
		// Widening for -dev must not have opened a prefix match. These are the lookalikes that a
		// naive `strings.HasPrefix` or an unanchored regex would now let through.
		"ghcr.io/norviq-dev/norviq-engine-dev-evil:engine-latest",
		"ghcr.io/norviq-dev/norviq-engine-devil:engine-latest",
		"evil.example.com/norviq-dev/norviq-engine-dev:engine-latest",
		"ghcr.io/other-org/norviq-engine-dev:engine-latest",
	}
	for _, img := range denied {
		if isAllowedSidecarImage(img) {
			t.Errorf("must deny %q", img)
		}
	}
}

// A digest is immutable, so it must not be mistaken for a mutable tag and refused by the override
// guard — the two checks run back to back on the NrvqConfig path.
func TestIsMutableTagTreatsDigestAsImmutable(t *testing.T) {
	pinned := "ghcr.io/norviq-dev/norviq-engine@sha256:" +
		"305f35742c675a455416ca01086b8174f5999ecf3704ed26591b8dc157a3d381"
	if isMutableTag(pinned) {
		t.Errorf("a sha256 digest is immutable, got isMutableTag(%q) = true", pinned)
	}
	for _, img := range []string{
		"ghcr.io/norviq-dev/norviq-engine:latest",
		"ghcr.io/norviq-dev/norviq-engine:engine-latest",
		"ghcr.io/norviq-dev/norviq-engine",
	} {
		if !isMutableTag(img) {
			t.Errorf("expected %q to be treated as mutable", img)
		}
	}
}
