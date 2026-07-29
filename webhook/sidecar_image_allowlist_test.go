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
