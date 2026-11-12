// SPDX-License-Identifier: Apache-2.0
/**
 * Framework tags the product's own fabricated traffic carries (red-team runs, Attack Graph Simulate,
 * probes). A copy of SYNTHETIC_FRAMEWORKS in norviq/api/synthetic.py, which is the source of truth;
 * tests/api/test_synthetic_traffic_class.py fails if the two differ.
 *
 * The console only needs this to know when a `framework=<tag>` filter and "Real traffic only" have
 * an empty intersection. Whether a ROW is real traffic is the server's call (`non_real` on every
 * audit record), never re-derived here.
 */
export const SYNTHETIC_FRAMEWORKS: readonly string[] = ["attack-graph", "policy-tester", "probe", "red-team", "redteam"];

export function isSyntheticFramework(framework: string | null | undefined): boolean {
  return SYNTHETIC_FRAMEWORKS.includes(String(framework ?? "").trim().toLowerCase());
}
