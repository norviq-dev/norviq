// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

package main

import (
	"os"
	"strings"
	"testing"
)

// readSourceFile reads a repo file relative to the webhook package directory. These assertions are on
// SOURCE rather than behaviour deliberately: the fix is the ABSENCE of a write, and there is no way to
// observe an absent field through a fake client without also asserting the whole status-update path.
func readSourceFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// updatePolicyStatus used to write matchingWorkloads and blockCount24h as a hard-coded int64(0) on
// EVERY status update, while the CRD advertised blockCount24h as a printer column named "Blocks-24h".
// So `kubectl get nrvqpolicy` reported a confident 0 for a policy that had been blocking all day, and
// an operator reading it concludes the policy has caught nothing. On a security product a fabricated
// metric is worse than an absent one.
//
// Neither field is computed here (nothing in the controller knows the count, and there is no
// per-policy block-count endpoint to ask), so the honest behaviour is to not write them at all:
// kubectl then prints "<none>". These pin that, and that the column stays gone.
func TestPolicyStatusDoesNotFabricateCounts(t *testing.T) {
	src := readSourceFile(t, "controller.go")
	start := strings.Index(src, "func (c *Controller) updatePolicyStatus(")
	if start < 0 {
		t.Fatal("updatePolicyStatus not found")
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		t.Fatal("could not bound updatePolicyStatus")
	}
	body := src[start : start+end]

	for _, field := range []string{`"matchingWorkloads"`, `"blockCount24h"`} {
		if strings.Contains(body, field) {
			t.Errorf("updatePolicyStatus writes %s again — if it is now genuinely computed, replace "+
				"this test with one asserting the real value; do not restore a constant.", field)
		}
	}
	if !strings.Contains(body, `"phase"`) || !strings.Contains(body, `"lastApplied"`) {
		t.Error("updatePolicyStatus no longer writes the fields it legitimately owns")
	}
}

func TestCrdNoLongerAdvertisesTheUncomputedBlocksColumn(t *testing.T) {
	crd := readSourceFile(t, "../helm/norviq/crds/norviq.io_nrvqpolicies.yaml")
	if strings.Contains(crd, "- name: Blocks-24h") {
		t.Error("the Blocks-24h printer column is back, but nothing computes blockCount24h — " +
			"kubectl would report 0 blocks for a policy that is blocking")
	}
	// The schema field itself is deliberately retained (removing it from a published CRD is a
	// breaking change for any existing consumer) and marked RESERVED.
	if !strings.Contains(crd, "blockCount24h:") {
		t.Error("blockCount24h was removed from the CRD schema — that is a breaking API change; " +
			"it should remain, documented as unpopulated")
	}
	if !strings.Contains(crd, "RESERVED, not populated") {
		t.Error("the RESERVED wording that tells operators the field is not computed is gone")
	}
}
