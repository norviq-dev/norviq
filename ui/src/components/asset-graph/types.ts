// SPDX-License-Identifier: Apache-2.0

// CAP-1 (source capability model): what verbs a data SOURCE exposes, classified server-side against
// the join of grants / observed traffic / policy coverage. See norviq/engine/capability.
export type CapabilityVerb = "read" | "write" | "delete" | "send" | "unknown";
export type CapabilityStatus = "undefended" | "dormant_grant" | "defended" | "latent" | "not_exposed";

export interface CapabilityFinding {
  verb: CapabilityVerb;
  risk: "low" | "medium" | "high" | "critical";
  technique: string | null; // a REAL ATLAS id, or null = tactic-level (never a fabricated code)
  label: string;
  status: CapabilityStatus;
  granted: boolean;
  observed: boolean;
  defended: boolean;
  recommendation: string;
  // CAP→POLICY: the agent-classes exercising this verb — the targets a one-click "Defend" policy applies to.
  agent_classes?: string[];
}

export interface SourceCapability {
  source_type?: string; // registry key (e.g. "elasticsearch") — for the defend call
  source_class: "datastore" | "egress" | "object_store" | "unknown";
  source_display: string;
  findings: CapabilityFinding[];
  worst: CapabilityFinding | null; // highest-risk OPEN verb (undefended/dormant), null = nothing actionable
}

export interface AssetNode {
  id: string;
  type: "agent" | "tool" | "data" | "namespace";
  name: string;
  properties: {
    namespace?: string;
    agent_class?: string;
    spiffe_id?: string;
    trust_score?: number;
    risk_level?: "low" | "medium" | "high" | "critical";
    tool_call_count?: number;
    last_seen?: string;
    // Multi-namespace view: deployed (policy/registry) but no observed traffic yet — rendered dimmed/dashed.
    awaiting?: boolean;
    // Identity sub-grouping: >1 agent_class under one SPIFFE id -> a parent identity node (is_identity)
    // plus one sub-node per class. spiffe_id carries the shared identity; agent_classes lists all classes.
    is_identity?: boolean;
    agent_classes?: string[];
    // CAP-1: present on DATA nodes whose source type is in the registry (ES/Postgres wave 1).
    capability?: SourceCapability;
  };
}

export interface AssetEdge {
  source: string;
  target: string;
  type: "calls" | "accesses" | "belongs_to" | "owns";
  weight: number;
  properties: {
    last_call?: string;
    decision_history?: { allow: number; block: number; escalate: number; would_block?: number };
    // CAP-1: the resolved operation of an accesses-edge (tool → data), from the capability registry.
    verb?: CapabilityVerb;
  };
}

export interface AssetGraphResponse {
  nodes: AssetNode[];
  edges: AssetEdge[];
  // Namespaces represented in the response (multi-namespace union); may be absent on older servers.
  namespaces?: string[];
  // A1: count of synthetic/probe agents hidden from this response (drives the "N test/probe hidden — Show" chip).
  synthetic_hidden?: number;
  // A2: count of real-but-awaiting agents hidden by default (drives the "Awaiting (N) — Show" chip).
  awaiting_hidden?: number;
}
