// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Attack Graph shared palette + copy. Severity + decision colors match
// the handoff verbatim; decision reuses DECISION_COLORS from d3-helpers (allow/mixed/blocked).

import { DECISION_COLORS } from "../../lib/d3-helpers";
import type { PathStatus, Severity, StepDecision } from "./types";

/** Severity dot / chip color — handoff SEV map. */
export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#FF3B5C",
  high: "#FF7A45",
  medium: "#FFB020",
  low: "#6e6e6e"
};

/** Per-hop decision color — reuse d3-helpers so nothing is hardcoded twice. An unmapped decision
 *  renders stroke:undefined (an INVISIBLE edge), so every StepDecision MUST have an entry here. */
export const STEP_DECISION_COLORS: Record<StepDecision, string> = {
  allow: DECISION_COLORS.allow, // #00E5A0
  mixed: DECISION_COLORS.mixed, // #FFB020
  block: DECISION_COLORS.blocked, // #FF3B5C
  // Monitor-mode would-block: covered by policy but logged, not enforced — amber (dashed on the canvas).
  would_block: DECISION_COLORS.mixed // #FFB020
};

/** Node kind color — handoff KIND map (agent/tool/data). */
export const KIND_COLORS = {
  agent: "#7C5CFC",
  tool: "#00E5A0",
  data: "#FFB020"
} as const;

/** Status chip label + colors. */
export const STATUS_META: Record<PathStatus, { label: string; bg: string; color: string }> = {
  exploitable: { label: "EXPLOITABLE", bg: "#3a1414", color: "#ff8fa3" },
  blocked: { label: "BLOCKED", bg: "#0d2a1c", color: "#6ee7b7" },
  unsimulated: { label: "NOT SIMULATED", bg: "#1b2436", color: "#8397b6" }
};

/** The four positive-security intent toggles (label + description). */
export const INTENT_CONTROLS: Array<{ key: "readonly" | "scope" | "rate" | "egress"; label: string; desc: string }> = [
  { key: "readonly", label: "Read-only", desc: "Deny write / mutate verbs" },
  { key: "scope", label: "Namespace-scoped", desc: "Resource must be in the agent's namespace" },
  { key: "rate", label: "Rate limit ≤ 60/min", desc: "Throttle call volume" },
  { key: "egress", label: "No external egress", desc: "Deny object-store / SMTP / internet sinks" }
];
