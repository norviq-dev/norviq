// SPDX-License-Identifier: Apache-2.0
//
// Attack Graph — the enriched kill-chain contract the backend serves at
// GET /api/v1/threats/attack-paths. Every field is real data derived server-side from the asset-graph
// snapshot + audit decision history (see norviq/api/routers/threats.py). No mock.

export type Severity = "critical" | "high" | "medium" | "low";
export type PathStatus = "exploitable" | "blocked" | "unsimulated";
// "would_block": the hop has Monitor-mode would-block history — a policy covers it but the namespace
// logs instead of enforcing. Distinct from "block" (enforced) and from "allow" (nothing would stop it).
export type StepDecision = "allow" | "mixed" | "block" | "would_block";
export type NodeKind = "agent" | "tool" | "data";

/** One asset in a path's blast radius; s=1 marks a sensitive (data / high-sensitivity) asset. */
export interface ReachAsset {
  n: string;
  s: 0 | 1;
}

/** One hop of a kill-chain, joined to its edge's real 24h decision counts. */
export interface ThreatStep {
  from: string;
  to: string;
  verb: string; // "calls" | "reaches"
  dec: StepDecision;
  kind: NodeKind;
  deny: number;
  allow: number;
  would_block?: number; // Monitor-mode would-block count on this hop (logged, not enforced)
  // The actual data operation on a tool→data hop (read/write/delete/send) + its risk, from the
  // source-capability registry. Absent (null) when the source/verb isn't in the registry.
  op?: "read" | "write" | "delete" | "send" | null;
  op_risk?: Severity | null;
  // Classification lifecycle: "learned" = admin-promoted verb, "registry" = name/token classifier; and
  // for a still-unclassified TOOL hop, the observation evidence ("observing · {verb} n/m").
  op_src?: "learned" | "registry" | null;
  inferred_verb?: "read" | "write" | "delete" | "send" | null;
  inferred_count?: number;
  observed_calls?: number;
}

export interface ThreatPath {
  id: string;
  sev: Severity;
  src: string;
  tgt: string;
  ns: string;
  cls: string;
  mitre: string;
  hops: number;
  trust: number;
  blast: number;
  status: PathStatus;
  tool: string; // chokepoint tool
  reach: ReachAsset[];
  steps: ThreatStep[];
  verdict: string;
  fix: string;
  // An applied intent/capability policy denies this chokepoint. status is audit-derived so it can still
  // read "exploitable" right after a defense is applied — this says "a defense is in place; Simulate to confirm".
  governed_by?: "" | "intent" | "capability";
}

export interface ThreatPathsResponse {
  paths: ThreatPath[];
  namespaces: string[];
  // Count of probe-rooted kill-chains hidden (drives the "N test/probe hidden — Show" chip).
  synthetic_hidden?: number;
}

/** The four positive-security intent toggles. */
export interface IntentToggles {
  readonly: boolean;
  scope: boolean;
  rate: boolean;
  egress: boolean;
}

/** One OBSERVED tool for an agent class (allowlist-builder checklist row). tag flags the tool's
 *  role in the attack surface: "chokepoint" reached an attack target, "egress" is an external sink. */
export interface IntentSuggestTool {
  name: string;
  allow: number;
  block: number;
  tag: "normal" | "chokepoint" | "egress";
  target: string | null;
  in_attack_path: boolean;
  // The tool's inferred operation + risk (read/write/delete/send), so the operator sees what it DOES —
  // resolved even for cloud/opensource tools (aws_s3_delete, azure_blob_read). null = unclassified.
  op?: "read" | "write" | "delete" | "send" | null;
  op_risk?: "low" | "medium" | "high" | "critical" | null;
  // Where the op came from: "learned" = admin-promoted verb override, "registry" = name/token classifier.
  op_src?: "learned" | "registry" | null;
  // OBSERVATION-phase evidence for a still-unclassified tool (verb-promotion lifecycle): total evidenced
  // calls + the verb the observed params suggest most often — drives the "Promote as {verb}" affordance.
  observed_calls?: number;
  inferred_verb?: "read" | "write" | "delete" | "send" | null;
  inferred_count?: number;
}

/** The class's observed tool surface — the source list for the allowlist builder. */
export interface IntentSuggest {
  ns: string;
  cls: string;
  tools: IntentSuggestTool[];
}

export interface IntentCoverage {
  rego: string;
  covered: string[]; // path ids the generated policy DENIES
  residual: string[]; // path ids still exploitable
  covered_count: number;
  total: number;
}

export interface IntentDraft {
  draft_id: string;
  policy: string;
  ns: string;
  cls: string;
  deeplink: string;
  enforcement: string; // always "draft" — never enforces on its own
  valid: boolean;
  errors: string[];
  would_block: number;
  would_allow: number;
  covered_count: number;
  total: number;
}
