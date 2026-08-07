// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

package main

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// The create path lets the API resolve a loader key from spec.target (resolve_policy_key); the delete
// path builds the key itself. They MUST agree, and they did not: delete used metadata.name, so once
// targeted policies were fixed to key on their target, deleting the CR issued
// DELETE /policies/<ns>/<metadata.name> against a row that does not exist. kubectl reported the CR
// gone and the policy KEPT ENFORCING with no supported way to remove it.
//
// Found on a live cluster, not by these tests — the two test CRs used to prove targeted enforcement
// were deleted and their policies survived in the API. Consistently-wrong (both on metadata.name) was
// survivable; half-fixed was worse than either.
func policyCR(namespace, name string, spec map[string]interface{}) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("norviq.io/v1alpha1")
	u.SetKind("NrvqPolicy")
	u.SetNamespace(namespace)
	u.SetName(name)
	if spec != nil {
		_ = unstructured.SetNestedMap(u.Object, spec, "spec")
	}
	return u
}

func TestPolicyStorageKeyMatchesWhereTheApiStoresIt(t *testing.T) {
	cases := []struct {
		desc      string
		spec      map[string]interface{}
		wantNs    string
		wantClass string
	}{
		{
			desc:      "workload target keys on the workload, not metadata.name",
			spec:      map[string]interface{}{"target": map[string]interface{}{"kind": "Deployment", "name": "finance-agent"}},
			wantNs:    "analytics",
			wantClass: "deployment:finance-agent",
		},
		{
			desc:      "workload kind is lower-cased, matching resolve_policy_key",
			spec:      map[string]interface{}{"target": map[string]interface{}{"kind": "DEPLOYMENT", "name": "finance-agent"}},
			wantNs:    "analytics",
			wantClass: "deployment:finance-agent",
		},
		{
			desc:      "namespace target keys on namespace:<ns>",
			spec:      map[string]interface{}{"target": map[string]interface{}{"namespace": "analytics"}},
			wantNs:    "analytics",
			wantClass: "namespace:analytics",
		},
		{
			desc:      "agentClass outranks everything else in the target",
			spec:      map[string]interface{}{"target": map[string]interface{}{"agentClass": "finance-ops", "kind": "Deployment", "name": "x"}},
			wantNs:    "analytics",
			wantClass: "finance-ops",
		},
		{
			desc:      "no target at all falls back to metadata.name",
			spec:      map[string]interface{}{},
			wantNs:    "analytics",
			wantClass: "named-policy",
		},
		{
			desc:      "half-specified workload target falls through to the namespace branch",
			spec:      map[string]interface{}{"target": map[string]interface{}{"kind": "Deployment", "namespace": "analytics"}},
			wantNs:    "analytics",
			wantClass: "namespace:analytics",
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			ns, class := policyStorageKey(policyCR("analytics", "named-policy", tc.spec))
			if ns != tc.wantNs || class != tc.wantClass {
				t.Fatalf("got %s/%s, want %s/%s", ns, class, tc.wantNs, tc.wantClass)
			}
		})
	}
}

// A cluster-priority namespace baseline is re-keyed to <targetNs>:__baseline__ on the way in, so the
// delete must follow it there rather than to the CR's own namespace.
func TestPolicyStorageKeyFollowsTheClusterBaselineRekey(t *testing.T) {
	u := policyCR("norviq", "baseline-cluster-guard-analytics", map[string]interface{}{
		"clusterPriority": int64(10),
		"target":          map[string]interface{}{"namespace": "analytics"},
	})
	ns, class := policyStorageKey(u)
	if ns != "analytics" || class != "__baseline__" {
		t.Fatalf("got %s/%s, want analytics/__baseline__", ns, class)
	}
}

// The regression guard proper: whatever key a CR is stored under, the delete path must ask for that
// exact key. Asserted on source so it holds for every shape, not just the ones enumerated above.
func TestDeletePathsUseTheSharedResolver(t *testing.T) {
	src := readSourceFile(t, "controller.go")
	if n := countOccurrences(src, "delNs, delClass := policyStorageKey(u)"); n != 2 {
		t.Fatalf("expected both delete sites to use policyStorageKey, found %d", n)
	}
	if countOccurrences(src, "delNs, delClass := namespace, name") != 0 {
		t.Fatal("a delete site is keying on metadata.name again — a targeted policy deleted that way " +
			"stays in the API and keeps enforcing after its CR is gone")
	}
}

func countOccurrences(haystack, needle string) int {
	n, idx := 0, 0
	for {
		i := indexFrom(haystack, needle, idx)
		if i < 0 {
			return n
		}
		n++
		idx = i + len(needle)
	}
}

func indexFrom(s, sub string, from int) int {
	if from >= len(s) {
		return -1
	}
	i := len(s)
	for j := from; j+len(sub) <= len(s); j++ {
		if s[j:j+len(sub)] == sub {
			i = j
			return i
		}
	}
	return -1
}
