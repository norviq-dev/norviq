// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// A single shared predicate for "reserved / managed" policy scopes, so the console never offers a destructive
// affordance (delete) or a create target for a scope the operator does not own directly. Managed scopes are the
// per-namespace baseline (`__baseline__`), the pack overlays (`__pack__` / `__pack_override__` / `__pack_weaken__`)
// and operator guardrails (`__guardrail__`) — every managed agent-class is prefixed `__`. The `__cluster__`
// namespace is the cluster-wide baseline and is likewise reserved. This mirrors the server-side DELETE guard
// (B-3, norviq/api/routers/policies.py `_RESERVED_DELETE_CLASSES` / `_RESERVED_NAMESPACES`).

/** True when the given policy scope is a reserved/managed one that must not be deleted or authored via the
 * generic policy UI. Any agent-class starting with `__`, or the reserved `__cluster__` namespace, is reserved. */
export function isReservedScope(agentClass?: string | null, namespace?: string | null): boolean {
  if (namespace === "__cluster__") return true;
  return !!agentClass && agentClass.startsWith("__");
}

// COMP-GEN-01: a per-class compliance remediation overlay lands at the compound key "<real_class>__remediation__"
// (norviq/engine/evaluator.py `_collect_candidates`/`_is_overlay`) — NOT a `__`-prefixed name, so it is
// intentionally NOT caught by `isReservedScope` above: it follows the `__guardrail__` precedent and stays
// directly authorable/deletable via the generic policy UI (server-side revert still requires confirm_managed).
const REMEDIATION_OVERLAY_SUFFIX = "__remediation__";

/** True when `agentClass` is a per-class compliance remediation overlay key, e.g. "report-gen__remediation__". */
export function isRemediationOverlayClass(agentClass?: string | null): boolean {
  return !!agentClass && agentClass.endsWith(REMEDIATION_OVERLAY_SUFFIX) && agentClass !== REMEDIATION_OVERLAY_SUFFIX;
}

/** The real agent class a remediation overlay key affects, stripping the "__remediation__" suffix. Returns
 * `agentClass` unchanged when it is not an overlay key. */
export function baseClassOfOverlay(agentClass: string): string {
  return isRemediationOverlayClass(agentClass) ? agentClass.slice(0, -REMEDIATION_OVERLAY_SUFFIX.length) : agentClass;
}

/** Human label for a policy-catalog row: the real class name + a "compliance overlay" tag for a remediation
 * overlay key, else the class name unchanged. `affectedClass` (from the API, when known) is preferred over
 * stripping the suffix client-side. */
export function overlayDisplayLabel(agentClass?: string | null, affectedClass?: string | null): string {
  if (!agentClass) return "";
  if (!isRemediationOverlayClass(agentClass)) return agentClass;
  return `${affectedClass || baseClassOfOverlay(agentClass)} · compliance overlay`;
}
