// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// What the ENGINE does with a policy block in one namespace, read from GET /settings?namespace=.
//
// Every surface that says "enforcing", "ENFORCED" or "call is blocked" is making this claim, and most of
// them used to make it from a literal: the Compliance pill, the apply-result badge, the policy cards and
// the baseline strip all read the same in a Monitor namespace as in one that blocks. They ask here.
//
// Three answers, because "not Monitor" is not the same as "blocking":
//   enforcing — policy blocks and escalates act on the call.
//   monitor   — the namespace sets enforcement_mode=audit itself, so the evaluator turns every policy
//               block or escalate into an `audit` would-block row and lets the call through.
//   unknown   — not read yet, the read failed, it answered for another scope, or the scope is "all"
//               (each namespace has its own posture). Never drawn as either of the other two.
//
// An "audit" that the namespace INHERITS from the cluster-wide default is `enforcing`: the evaluator
// relaxes policy blocks only on the namespace's own override (`_resolve_posture`), and the global mode
// reaches only the no-policy default. /settings merges the two into one `enforcement_mode`, so it also
// reports `enforcement_mode_source` to tell them apart.

import { fetchSettings, type RuntimeSettings } from "../api/client";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";

export type EnforcementVerdict = "enforcing" | "monitor" | "unknown";

type SettingsLike = Pick<RuntimeSettings, "namespace" | "enforcement_mode" | "enforcement_mode_source">;

function concrete(ns: string | null | undefined): string | null {
  const scope = (ns ?? "").trim();
  return scope && scope !== "all" ? scope : null;
}

/** Pure: the verdict a /settings read gives for `ns`. A read about any other namespace is not an answer. */
export function verdictFromSettings(s: SettingsLike | null | undefined, ns: string | null | undefined): EnforcementVerdict {
  const scope = concrete(ns);
  if (!scope || !s || s.namespace !== scope) return "unknown";
  if (s.enforcement_mode === "block") return "enforcing";
  if (s.enforcement_mode === "audit") {
    // An API that predates the source field gets the reading every page used before it existed.
    return s.enforcement_mode_source === "cluster_default" ? "enforcing" : "monitor";
  }
  return "unknown";
}

type PostureLike = {
  namespace: string;
  mode: RuntimeSettings["enforcement_mode"] | null;
  modeSource: RuntimeSettings["enforcement_mode_source"] | null;
  loading: boolean;
};

/** Pure: the verdict the app's posture (AppContext) gives for `ns`. Unknown while it loads or describes
 *  another scope. For pages that hold the posture already and must not re-read `posture.mode` themselves. */
export function verdictFromPosture(p: PostureLike | null | undefined, ns: string | null | undefined): EnforcementVerdict {
  if (!p || p.loading || p.mode == null) return "unknown";
  return verdictFromSettings({ namespace: p.namespace, enforcement_mode: p.mode, enforcement_mode_source: p.modeSource ?? undefined }, ns);
}

// ---- One policy, not the namespace -------------------------------------------------------------------
// The namespace verdict is not the whole answer for a single policy. The evaluator also softens a block or
// escalate to an `audit` when the winning policy is SAVED in audit mode (`_apply_policy_mode`), whatever the
// namespace does. It honours that mode on base and floor policies only: an overlay is tighten-only, so its
// stored mode is ignored (policies.py `_OVERLAY_SCOPES`, `_is_overlay_scope`).

const OVERLAY_SCOPES = new Set(["__pack__", "__pack_override__", "__pack_weaken__", "__guardrail__", "__egress__", "__controls__", "__mcp__"]);

/** True for a loader key the evaluator collects as a tighten-only overlay, whose own mode it ignores. */
export function isOverlayScope(agentClass: string | null | undefined): boolean {
  const ac = agentClass ?? "";
  return OVERLAY_SCOPES.has(ac) || (ac.endsWith("__remediation__") && ac !== "__remediation__");
}

/** `policy_audit`: the policy is saved in audit mode, so its matches are logged, never blocked. */
export type PolicyVerdict = EnforcementVerdict | "policy_audit";

/**
 * Pure: what ONE policy does with a match. Monitor in the namespace softens every policy, so it wins. Then a
 * base policy saved in audit mode is softened by its own mode, in any namespace (unknown included: it cannot
 * block either way). Otherwise the policy does what its namespace does.
 */
export function policyVerdict(
  ns: EnforcementVerdict,
  policyMode: string | null | undefined,
  agentClass: string | null | undefined
): PolicyVerdict {
  if (ns === "monitor") return "monitor";
  if (policyMode === "audit" && !isOverlayScope(agentClass)) return "policy_audit";
  return ns;
}

// ---- "Enforced" on the Compliance page ------------------------------------------------------------------
// The coverage API's `enforced` status means RULES PRESENT (mitre.py `basis: "rules_present"`): the mapped rule
// is defined in the loaded rego. It is an enforcement claim only where the namespace enforces. `proven` is the
// separate fact that the rule blocked or escalated real traffic in the window.

/** What a technique whose mapped rule is loaded is called in this posture. Lower-case; callers upper-case it. */
export function rulesPresentWord(v: EnforcementVerdict): string {
  if (v === "enforcing") return "enforced";
  if (v === "monitor") return "rules present · monitor";
  return "rules present";
}

const SETTINGS_STALE_MS = 15_000;

/** The app context, or null outside an AppProvider. Shared components (the apply-result panel, the
 *  baseline panel) also render standalone, and then read the posture over HTTP instead. useApp always
 *  calls useContext before it throws, so the hook order is the same either way. */
function useAppOrNull(): ReturnType<typeof useApp> | null {
  try {
    return useApp();
  } catch {
    return null;
  }
}

/**
 * The verdict for one namespace. Uses the app's posture when it already describes `ns` (so a Monitor
 * flip on Target Settings shows up live), and otherwise reads /settings for `ns` under the same cache key
 * AppContext primes. Works outside an AppProvider, where it always reads.
 */
export function useEnforcementVerdict(ns: string | null | undefined): EnforcementVerdict {
  const app = useAppOrNull();
  const scope = concrete(ns);
  const posture = app?.posture;
  const fromContext = !!scope && !!posture && posture.namespace === scope;
  const needRead = !!scope && !fromContext;
  const read = useApi<RuntimeSettings | null>(
    // async, so a read that throws becomes a rejection (unknown) rather than an exception in render.
    async () => (needRead && scope ? fetchSettings(scope) : null),
    [needRead, scope],
    { cacheKey: needRead && scope ? `settings:${scope}` : undefined, staleTimeMs: SETTINGS_STALE_MS }
  );
  if (!scope) return "unknown";
  if (fromContext && posture) return verdictFromPosture(posture, scope);
  if (read.error || read.stale || read.loading) return "unknown";
  return verdictFromSettings(read.data, scope);
}

/** The verdict for each of several namespaces (a list that spans namespaces, e.g. the catalog under
 *  "All namespaces"). One read per namespace the app posture does not already cover. */
export function useEnforcementVerdicts(namespaces: Array<string | null | undefined>): Record<string, EnforcementVerdict> {
  const app = useAppOrNull();
  const posture = app?.posture;
  const scopes = [...new Set(namespaces.map(concrete).filter((n): n is string => !!n))].sort();
  const toRead = scopes.filter((n) => !(posture && posture.namespace === n));
  const key = toRead.join(",");
  const reads = useApi<Record<string, RuntimeSettings | null>>(
    async () => {
      const out: Record<string, RuntimeSettings | null> = {};
      await Promise.all(
        toRead.map(async (n) => {
          try {
            out[n] = await fetchSettings(n);
          } catch {
            out[n] = null; // this namespace stays unknown; the others still answer
          }
        })
      );
      return out;
    },
    [key]
  );
  const result: Record<string, EnforcementVerdict> = {};
  for (const n of scopes) {
    if (posture && posture.namespace === n) {
      result[n] = verdictFromPosture(posture, n);
    } else {
      result[n] = reads.stale || reads.loading ? "unknown" : verdictFromSettings(reads.data?.[n], n);
    }
  }
  return result;
}
