// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors
//
// Intents — what an agent class is FOR. Everything it does not state is denied.
//
// This screen exists because deny-by-default is easy to ship and hard to adopt. A policy that
// refuses everything it was not told about will refuse something legitimate on day one, and if the
// operator cannot see WHICH call and WHY, the policy gets switched off. So the screen is built
// around the diff, not the editor: propose a candidate from traffic the class actually produced,
// replay it against that traffic, and put the would-block list — each with the rule that came
// closest and the single clause that failed — in front of the operator BEFORE anything is saved.
//
// Nothing here enforces. "Save as draft" writes to the drafts table the evaluator never reads;
// applying stays the gated Policies flow, so there is exactly one place where enforcement begins.

import { useCallback, useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, FileText, PencilLine, Play, Wand2 } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { apiSend, fetchMe } from "../api/client";
import { InlineDisabledReason } from "../components/common/InlineDisabledReason";
import { KitButton } from "../components/common/KitButton";
import { NearMissCard, type BlockedCallDetail } from "../components/common/NearMissCard";
import { PageHead } from "../components/common/PageHead";
import { Panel } from "../components/common/Panel";
import { RuleCard } from "../components/common/RuleCard";
import { StatTile } from "../components/common/StatTile";
import { useToast } from "../components/common/Toast";
import { useApi } from "../hooks/useApi";
import { useApp } from "../store/AppContext";
import { commonTerms, lookalikeOf, predicateSentence, type Lookalike } from "../lib/predicateSentence";
import { intentToBuilderGraph, type IntentLike } from "../lib/intentToGraph";
import type { BuilderGraph } from "../lib/builderGraph";

export type IntentRule = {
  id: string;
  server?: string;
  match?: Record<string, unknown>;
  require?: Record<string, unknown>;
};

export type Intent = { name: string; class: string; call?: IntentRule[] };

/**
 * How much of the traffic's ARGUMENT detail this proposal could actually see.
 *
 * Three states because two were not enough, and the missing one is where operators got hurt. The old
 * boolean `params_available` answered "were masked VALUES recorded?" — and when the answer was no,
 * this screen said "tool names only" and showed nothing else. But the audit row always could have
 * carried the argument KEY NAMES (masking preserves keys), and a name is all you need to notice that
 * the rule you are about to save says nothing about `amount`.
 *
 *   none   — nothing was captured. NOT "the calls carried no arguments"; we do not know that.
 *   keys   — the argument PATH NAMES each call carried, and no values. Existence is assertable;
 *            what a value contained is not.
 *   masked — names plus masked values.
 */
export type ParamsDetail = "none" | "keys" | "masked";

/** Argument paths observed for one tool. `keys` are ATTACKER-CONTROLLED text — see `ArgName`. */
export type ObservedArgSet = {
  /**
   * THIS TOOL's capture state, which is not the proposal's.
   *
   * A sample routinely straddles the moment argument-name capture was switched on: `issue_refund`
   * has rows carrying `param_keys`, `list_matters` only has rows written before the field existed.
   * The API reports that per tool — `detail: "none"` with an empty key list — and an empty key list
   * means two opposite things depending on it: under `"keys"` the calls genuinely carried no
   * arguments; under `"none"` nobody ever looked. Collapsing the two into "the list is empty" is the
   * exact defect this work exists to close, one level down from where it was closed.
   */
  detail: ParamsDetail;
  /** Sorted, de-duplicated argument paths, exactly as the traffic spelled them. */
  keys: string[];
  /**
   * Paths the engine itself derived and vouches for — the only ones a VALUE clause can ever hold on.
   * `null` when the response did not say, which is not the same as the empty set.
   *
   * Authoritative under `"keys"` as well as `"masked"`, and that is the whole point: the capture
   * writes `param_keys_pinnable` from the type of each leaf, which it knows without storing a single
   * value. `amount: 25.0` is a number, so the engine never derives a `param_paths` entry for it, so
   * no clause can ever hold on it — knowable on a default install that stores nothing. Excluded only
   * under `"none"`, where nobody looked and `keys - pinnable` is a blind spot rather than a finding.
   * That is exactly the boundary norviq/api/routers/intents.py draws when it builds the same list.
   */
  pinnable: Set<string> | null;
  /**
   * Paths another route through the payload can also reach, so a caller chooses which value lands
   * there. The API ships these precisely so they are shown and never asserted.
   */
  ambiguous: Set<string>;
  /** The set was cut short by the capture bound, so absence from `keys` proves nothing. */
  truncated: boolean;
  /**
   * How many of the sampled calls went to THIS TOOL — `_ToolEvidence.as_dict()`'s `calls`.
   *
   * The evidence base behind every sentence this screen writes about one tool, and it is not the
   * proposal's `sampled`. A multi-tool rule replayed over 500 calls may have seen `list_matters` on
   * two of them; "carried no arguments at all across the 500 sampled calls" then offers a 500-call
   * denominator for a two-call observation, and a strong negative with a large denominator is where
   * an operator stops looking.
   *
   * `null` when the response did not say, which is the one case where borrowing the sample-wide
   * number would be inventing evidence — so the sentence drops the number instead.
   */
  calls: number | null;
};

export type ProposeResponse = {
  intent: Intent;
  sampled: number;
  /** UNCHANGED MEANING: masked argument VALUES are present. `params_detail` is the richer signal. */
  params_available: boolean;
  params_detail?: ParamsDetail;
  /** tool name -> the argument paths that tool's calls carried. A MISSING entry is not an empty one. */
  observed_params?: Record<string, unknown>;
  observed_params_truncated?: boolean | string[];
};

const DETAIL_RANK: Record<ParamsDetail, number> = { none: 0, keys: 1, masked: 2 };

function isDetail(v: unknown): v is ParamsDetail {
  return typeof v === "string" && v in DETAIL_RANK;
}

/**
 * The capture state, from a response that may be older than this field or may contradict itself.
 *
 * Two rules, both fail-closed:
 *
 *   1. A `params_detail` we do not recognise is UNKNOWN, and unknown is not spelled the same way as
 *      "we saw everything" — it collapses to `none`, the state that warns loudest. A future value we
 *      cannot interpret must never render as a quieter screen than the one operators have today.
 *   2. Where the two fields disagree, the WEAKER claim wins. `params_available: false` means masked
 *      values were not recorded, so a `params_detail: "masked"` beside it is a claim the response has
 *      already contradicted; it is read as `keys`. Believing the stronger half of a contradiction is
 *      how a screen ends up asserting a value-level check that never happened.
 */
export function paramsDetailOf(
  res: { params_available?: boolean; params_detail?: unknown } | null | undefined
): ParamsDetail {
  if (!res) return "none";
  if (res.params_detail !== undefined && !isDetail(res.params_detail)) return "none";
  // Absent `params_detail` — a server predating this field. `params_available` is then the only
  // witness, and it means exactly what it always meant.
  const declared: ParamsDetail = isDetail(res.params_detail)
    ? res.params_detail
    : res.params_available === true
      ? "masked"
      : "none";
  const cap: ParamsDetail = res.params_available === true ? "masked" : "keys";
  return DETAIL_RANK[declared] <= DETAIL_RANK[cap] ? declared : cap;
}

/** A list of names off the wire, as a set — non-strings dropped and counted. */
function nameSet(value: unknown): { names: string[]; dropped: number } | null {
  if (!Array.isArray(value)) return null;
  const names = value.filter((k): k is string => typeof k === "string" && k.length > 0);
  return { names: [...new Set(names)].sort(), dropped: value.length - names.length };
}

/**
 * One tool's evidence, from `{detail, keys, pinnable, ambiguous, truncated}` or a bare `[...]`.
 *
 * The bare-list form is a legacy/hand-written shape, and the one thing it cannot express is the
 * difference an empty list turns on. So an empty bare list is read as `detail: "none"` — "nothing
 * was reported" — never as the positive claim "this tool carries no arguments". A shape that cannot
 * say which of two things it means must be read as the one that asserts less.
 */
function readArgSet(value: unknown): ObservedArgSet | null {
  if (Array.isArray(value)) {
    const list = nameSet(value)!;
    return {
      detail: list.names.length > 0 ? "keys" : "none",
      keys: list.names,
      pinnable: null,
      ambiguous: new Set(),
      // A dropped entry is a name the operator will not be shown. Reported as truncation rather than
      // silently filtered: the whole point of this surface is that a partial list must not pass for a
      // complete one.
      truncated: list.dropped > 0,
      // The bare-list form cannot carry a per-tool call count, and a shape that cannot say a thing
      // must not be read as having said it.
      calls: null
    };
  }
  if (value && typeof value === "object") {
    const o = value as Record<string, unknown>;
    const list = nameSet(o.keys ?? o.param_keys);
    if (!list) return null;
    const pinnable = nameSet(o.pinnable);
    const ambiguous = nameSet(o.ambiguous);
    return {
      // An unrecognised rung is UNKNOWN, and unknown is spelled `none` — the reading that claims
      // least — rather than being rounded up to the nearest state we do understand.
      detail: isDetail(o.detail) ? o.detail : list.names.length > 0 ? "keys" : "none",
      keys: list.names,
      pinnable: pinnable ? new Set(pinnable.names) : null,
      ambiguous: new Set(ambiguous?.names ?? []),
      truncated:
        Boolean(o.truncated ?? o.param_keys_truncated) ||
        list.dropped > 0 ||
        Number(o.dropped ?? 0) > 0,
      // Only a finite, non-negative integer is a call count. Anything else is read as "not reported"
      // rather than coerced — a NaN or a negative rendered into a sentence is worse than no number.
      calls:
        typeof o.calls === "number" && Number.isFinite(o.calls) && o.calls >= 0 ? Math.floor(o.calls) : null
    };
  }
  return null;
}

// Field names this reader will accept for the per-tool observed set. Deliberately tolerant: the
// audit row calls the key-set `param_keys`, and the proposal aggregates it per tool. A response that
// uses none of these reads as NOT REPORTED, which renders as its own state — never as "captured, and
// there are none".
const OBSERVED_FIELDS = ["observed_params", "param_keys", "observed_param_keys", "params_observed"];
const TRUNCATED_FIELDS = [
  "observed_params_truncated",
  "param_keys_truncated",
  "observed_param_keys_truncated"
];

/**
 * The observed argument paths, per tool.
 *
 * `present` is the distinction this project keeps failing to draw. `present: false` means the server
 * told us nothing about arguments; an empty map with `present: true` means it told us there were
 * none. Those are different sentences on screen, and conflating them is how an operator concludes a
 * tool takes no arguments when nobody ever looked.
 */
export function readObservedParams(res: unknown): { byTool: Map<string, ObservedArgSet>; present: boolean } {
  const obj = (res ?? {}) as Record<string, unknown>;
  const raw = OBSERVED_FIELDS.map((f) => obj[f]).find(
    (v): v is Record<string, unknown> => Boolean(v) && typeof v === "object" && !Array.isArray(v)
  );
  const byTool = new Map<string, ObservedArgSet>();
  if (!raw) return { byTool, present: false };

  let allTruncated = false;
  const truncatedTools = new Set<string>();
  for (const f of TRUNCATED_FIELDS) {
    const v = obj[f];
    if (v === true) allTruncated = true;
    else if (Array.isArray(v)) for (const t of v) if (typeof t === "string") truncatedTools.add(t);
  }

  for (const [tool, value] of Object.entries(raw)) {
    const set = readArgSet(value);
    // An entry we cannot read is left ABSENT rather than recorded as empty, so it renders as "not
    // reported" rather than as a positive claim that the tool carried nothing.
    if (!set) continue;
    byTool.set(tool, { ...set, truncated: set.truncated || allTruncated || truncatedTools.has(tool) });
  }
  return { byTool, present: true };
}

/** The tool names a rule scopes itself to, deduped and in the order the rule states them. */
export function toolsOfRule(rule: IntentRule): string[] {
  const tn = (rule.match as Record<string, unknown> | undefined)?.tool_name;
  const raw: unknown[] = Array.isArray(tn)
    ? tn
    : typeof tn === "string"
      ? [tn]
      : tn && typeof tn === "object"
        ? [
            ...((tn as { in?: unknown[] }).in ?? []),
            ...((tn as { anyOf?: unknown[] }).anyOf ?? []),
            ...((tn as { equals?: unknown }).equals !== undefined ? [(tn as { equals: unknown }).equals] : [])
          ]
        : [];
  const out: string[] = [];
  for (const v of raw) if (typeof v === "string" && v && !out.includes(v)) out.push(v);
  return out;
}

/**
 * The argument paths a rule already says something about.
 *
 * Compared VERBATIM against what traffic carried, because that is how the engine compares them:
 * `input.derived.param_paths` keeps the keys exactly as the payload spelled them, and `_fold_path`
 * (norviq/engine/evaluator.py) folds only for collision DETECTION. So an argument whose name differs
 * by one invisible codepoint is a different argument, and must be flagged as one.
 */
export function scopedArgsOfRule(rule: IntentRule): Set<string> {
  return new Set(scopedArgDetail(rule).keys());
}

/**
 * Patterns that constrain NOTHING. `_add_existence_predicates` writes literally
 * `require["param_paths.amount"] = {"matches": ".*"}` — deliberately, because a name-only capture
 * cannot support a value claim. It is a real and useful clause: it makes the rule refuse a call that
 * OMITS the argument. It is not a constraint on what the argument contains.
 */
const ANY_VALUE_PATTERNS = new Set([".*", "^.*$", "^.*", ".*$", "(?s).*", ""]);

/**
 * Each argument path the rule mentions, and WHETHER IT SAYS ANYTHING ABOUT THE VALUE.
 *
 * A rule that pins `param_paths.amount` to `.*` mentions `amount` and still allows `amount: 999999`.
 * Rendering that beside a rule that pins `^[0-9]{1,3}$` with the same words retires the operator's
 * only flag in exchange for nothing — the same class of mistake as the one this work exists to fix,
 * one rung quieter. Classification is deliberately asymmetric: anything not provably vacuous is
 * called a value constraint only when it is not in the vacuous set, so an unfamiliar predicate
 * shape errs toward being reported as a constraint rather than being silently dropped from the list.
 */
export function scopedArgDetail(rule: IntentRule): Map<string, "value" | "presence"> {
  const out = new Map<string, "value" | "presence">();
  for (const block of [rule.match, rule.require]) {
    for (const [field, spec] of Object.entries((block ?? {}) as Record<string, unknown>)) {
      if (!field.startsWith("param_paths.")) continue;
      const name = field.slice("param_paths.".length);
      const o = (spec ?? {}) as Record<string, unknown>;
      const vacuous =
        (typeof o.matches === "string" && ANY_VALUE_PATTERNS.has(o.matches)) ||
        (Object.keys(o).length === 1 && o.exists === true);
      // `value` wins over `presence` when a path is mentioned twice: the stronger clause is the one
      // actually enforced, and understating it here would be noise rather than safety.
      if (!vacuous || !out.has(name)) out.set(name, vacuous ? "presence" : "value");
    }
  }
  return out;
}

/**
 * THE DELIVERABLE: argument names the traffic carried that this rule does not mention.
 *
 * The failure this exists for, in the reporter's own words: a rule for `issue_refund` was written and
 * enforced correctly, the model emitted `{"amount": 25.0}`, no predicate named `amount`, and the call
 * was allowed. Nothing on the authoring surface had ever shown that `amount` was a thing traffic
 * carried, so there was no point at which the gap was visible before it mattered.
 */
export function unscopedArgs(
  rule: IntentRule,
  byTool: Map<string, ObservedArgSet>
): Array<{ name: string; tools: string[] }> {
  const scoped = scopedArgsOfRule(rule);
  // ONE ENTRY PER DISTINCT NAME, not per (tool, name) pair.
  //
  // Argument paths are matched VERBATIM and tool-independently (`scopedArgsOfRule` above), so one
  // `param_paths.to` clause closes `to` on `send_email` AND on `send_sms`. The number of distinct
  // names is therefore the number of clauses the operator has to write, which is what the headline
  // count is for. Keyed per pair, a rule scoping `tool_name in [send_email, send_sms]` where both
  // carry `to` announced "2 arguments in traffic that no rule mentions" over a bullet that printed
  // the identical name twice with a comma between — on the one screen whose whole design teaches the
  // reader that two pixel-identical argument names may be two DIFFERENT verbatim paths. The tool list
  // beside it was already deduped; only this half was not.
  const order: string[] = [];
  const tools = new Map<string, string[]>();
  for (const tool of toolsOfRule(rule)) {
    for (const name of byTool.get(tool)?.keys ?? []) {
      if (scoped.has(name)) continue;
      if (!tools.has(name)) {
        order.push(name);
        tools.set(name, []);
      }
      const seen = tools.get(name)!;
      if (!seen.includes(tool)) seen.push(tool);
    }
  }
  return order.map((name) => ({ name, tools: tools.get(name)! }));
}

/** The near miss, decomposed by the API so the clause list can reconcile with `met M of N`. The
 *  optional fields are absent when the reason could not be decomposed; the card then shows the raw
 *  sentence rather than a tick-list that contradicts its own heading. */
export type BlockedCall = BlockedCallDetail & { [key: string]: unknown };

export type DryRunResponse = {
  total: number;
  would_allow: number;
  would_block: number;
  coverage: Record<string, number>;
  unused_rules: string[];
  blocked: BlockedCall[];
  params_available?: boolean;
};

/**
 * Group identical refusals.
 *
 * The dry run replays every recorded call, so 1,241 `run_query` calls refused for one reason produce
 * 1,241 rows. The operator has ONE decision to make there, not 1,241 — and a list that long buries
 * the single `execute_sql` refusal that is actually interesting.
 */
export function groupBlocked(blocked: BlockedCall[]): Array<{ call: BlockedCall; occurrences: number }> {
  const groups = new Map<string, { call: BlockedCall; occurrences: number }>();
  for (const b of blocked) {
    const key = [b.tool_name, b.closest_rule ?? "", (b.failed ?? []).join("|"), b.reason].join("\u241F");
    const existing = groups.get(key);
    if (existing) existing.occurrences += 1;
    else groups.set(key, { call: b, occurrences: 1 });
  }
  return [...groups.values()].sort((a, b) => b.occurrences - a.occurrences);
}

// The amber band this page already uses for "read this before you save" (see `handoff-blocked` and
// the params warning). Same two values, so the argument bands sit in the same visual register rather
// than inventing a third one.
const ESCALATE_BORDER = "#FFB02030";
const ESCALATE_WASH = "#FFB02015";

const BAND_LABEL = {
  fontSize: 11,
  fontWeight: 600,
  letterSpacing: "0.08em",
  textTransform: "uppercase" as const,
  color: "var(--text-muted)",
  marginBottom: 5
};

/**
 * An argument or tool name, rendered so it cannot lie about which name it is.
 *
 * These names come off the wire, which is to say from whoever the agent is taking instructions from.
 * Three separate ways a name can impersonate another one, all closed here:
 *
 *  1. NON-ASCII. `аmount` (U+0430) is pixel-identical to `amount` in this console's font, and U+202E
 *     alone silently reverses the rest of the line it sits in. `lookalikeOf` is the repo's existing
 *     detector — the same one behind the tool-name `LookalikeNote` — and its `masked` form puts a `·`
 *     at the offending position, so WHERE the difference is stays visible.
 *  2. ASCII CONTROL CHARACTERS, which `lookalikeOf` does not cover because they are not lookalikes:
 *     they are invisible outright, and `builderCompile.ts` already carries a scar from one escaping a
 *     generated policy's header comment. Masked the same way. The API drops these, but this screen
 *     reads whatever the wire hands it and must not depend on a filter it does not own.
 *  3. WHITESPACE, the cheapest of the three and the one nothing else catches. `" amount"` is plain
 *     ASCII and HTML collapses the leading space, so it prints as `amount` — indistinguishable from
 *     the `amount` the rule DOES constrain, one row above. The quotation marks bound the name so its
 *     own edges are visible, `pre-wrap` stops the collapse, and together they also stop a name
 *     containing `, ` from reading as the separator between two names in a comma-joined list.
 */
/**
 * `OPAEvaluator._MAX_PATH_KEY_LEN`. A name longer than this is a name the engine never derived under
 * that spelling, so rendering it whole buys nothing and hands an unbounded string to the layout. Cut
 * names carry their true length so two of them cannot silently become one on screen.
 */
const MAX_NAME_LEN = 256;

function displayName(name: string): string {
  const shown = [...name].slice(0, MAX_NAME_LEN);
  const masked = shown
    .map((ch) => {
      const cp = ch.codePointAt(0)!;
      return cp > 0x7f || cp < 0x20 || cp === 0x7f ? "·" : ch;
    })
    .join("");
  return shown.length < [...name].length ? `${masked}… (${[...name].length} characters)` : masked;
}

function ArgName({ name }: { name: string }) {
  return (
    <code
      className="mono"
      data-testid="arg-name"
      style={{ fontSize: 12, wordBreak: "break-word", whiteSpace: "pre-wrap" }}
    >
      {"“"}
      {displayName(name)}
      {"”"}
    </code>
  );
}

/**
 * Why a lookalike ARGUMENT name is not the lookalike TOOL name, and why this cannot reuse
 * `LookalikeNote`'s sentence.
 *
 * `LookalikeNote` states the tool-name consequence: the generated allowlist matches
 * evasion-normalised, so a rule proposed from a homoglyph tool grants the lookalike AND the ASCII
 * tool. For an ARGUMENT the consequence is the exact opposite. `input.derived.param_paths` carries
 * verbatim keys (`_fold_path` folds only for collision detection), so a clause written on the ASCII
 * spelling does NOT cover the homoglyph path — the operator scopes a name the traffic never used and
 * the call they were worried about walks through unconstrained. Reusing the other note's copy here
 * would be a misstatement of what the engine does, which this codebase treats as worse than no copy.
 */
function ArgLookalikeNote({ lookalikes, testId }: { lookalikes: Lookalike[]; testId: string }) {
  if (lookalikes.length === 0) return null;
  return (
    <div
      data-testid={testId}
      style={{
        marginTop: 5,
        padding: "7px 9px",
        borderRadius: 8,
        border: "1px solid #ff3b5c30",
        background: "#ff3b5c12",
        fontSize: 12,
        lineHeight: 1.5,
        color: "var(--text-secondary)"
      }}
    >
      <span
        className="pill"
        style={{ background: "#ff3b5c15", color: "#ff3b5c", borderColor: "#ff3b5c30", marginRight: 7 }}
      >
        Lookalike argument
      </span>
      {lookalikes.map((l) => (
        <span key={l.value} style={{ display: "block", marginTop: 5 }}>
          {/* `l.masked` covers non-ASCII only; `ArgName` also masks the control characters that are
              invisible rather than merely confusable, so the two renderings cannot disagree. */}
          <ArgName name={l.value} /> carries {l.codepoints.join(", ")} where an ASCII letter appears to
          be.
        </span>
      ))}
      <span style={{ display: "block", marginTop: 5 }}>
        Argument paths are matched <strong>verbatim</strong>, so a clause written on the plain-ASCII
        spelling does not cover this one. Scoping the name you can read would leave the name the traffic
        actually carried unconstrained.
      </span>
    </div>
  );
}

/**
 * What one rule's tools were seen carrying, and what the rule says nothing about.
 *
 * Rendered beside the rule rather than inside `RuleCard`, because the card renders the rule as
 * WRITTEN and this is the traffic it will meet — two different sources, and the gap between them is
 * the whole point.
 */
function RuleArguments({
  rule,
  byTool,
  sampled
}: {
  rule: IntentRule;
  byTool: Map<string, ObservedArgSet>;
  sampled: number;
}) {
  const tools = toolsOfRule(rule);
  const scoped = scopedArgDetail(rule);
  const unscoped = unscopedArgs(rule, byTool);
  const flagged = unscoped.length > 0;

  return (
    <div
      data-testid={`observed-args-${rule.id}`}
      style={{
        marginTop: -4,
        marginLeft: 10,
        padding: "9px 11px",
        borderRadius: 10,
        fontSize: 12.5,
        lineHeight: 1.6,
        border: flagged ? `1px solid ${ESCALATE_BORDER}` : "1px solid var(--border)",
        background: flagged ? ESCALATE_WASH : "var(--bg-elevated)",
        color: "var(--text-secondary)"
      }}
    >
      <div style={BAND_LABEL}>Arguments seen in traffic</div>
      {tools.length === 0 ? (
        <div style={{ color: "var(--text-muted)" }}>
          This rule names no tool, so recorded calls cannot be attributed to it — it is scoped by the
          clauses above alone.
        </div>
      ) : (
        tools.map((tool) => {
          const set = byTool.get(tool);
          // TWO ways to know nothing, and they are the same sentence: the response never mentioned
          // this tool, or it mentioned it and said `detail: "none"` — no capture on any of its rows.
          // Neither is "it carried no arguments". Distinguishing THAT from an observed empty set is
          // the clause-3 requirement, and it turns on the per-tool state, not on list length.
          if (!set || set.detail === "none") {
            return (
              <div key={tool} data-testid={`observed-args-${rule.id}-unknown-${tool}`} style={{ marginTop: 4 }}>
                <ArgName name={tool} /> —{" "}
                <strong style={{ color: "var(--escalate)" }}>no argument names were recorded</strong> for this
                tool. That is not evidence it takes none.
                {set && set.keys.length > 0 && (
                  <> Some names did arrive and are listed below, but the set is not a complete one.</>
                )}
              </div>
            );
          }
          if (set.keys.length === 0) {
            // Only reachable with a POSITIVE capture state. This is an observation, not an absence.
            //
            // THE DENOMINATOR IS THIS TOOL'S OWN. `sampled` is the whole replay sample; the server
            // saw this tool on `set.calls` of them. Attributing a strong negative to all 500 when the
            // basis is 2 offers an evidence base the observation does not have, on a page whose every
            // other sentence is careful not to overstate what was seen.
            return (
              <div key={tool} data-testid={`observed-args-${rule.id}-empty-${tool}`} style={{ marginTop: 4 }}>
                <ArgName name={tool} /> — captured, and carried <strong>no arguments at all</strong>{" "}
                {set.calls != null ? (
                  <>
                    across the {set.calls} call{set.calls === 1 ? "" : "s"} to this tool in the {sampled} sampled.
                  </>
                ) : (
                  <>across the calls to this tool in the {sampled} sampled.</>
                )}
                {set.truncated && " (The capture bound was hit, so treat this as incomplete.)"}
              </div>
            );
          }
          // A path the ENGINE derived is the only kind a value clause can hold on. Pinnability is a
          // fact about the leaf's TYPE, which the capture knows without storing any value, so a
          // key-only sample answers it just as well as a masked one — and a key-only sample is what
          // a default install has. Gating this on `masked` (as it briefly was) hid `amount` on
          // precisely the install this feature was built for.
          //
          // `none` needs no clause here: a tool at `none` reports no keys, so the branch above has
          // already returned and `detail` is narrowed to `"keys" | "masked"` by the time we reach
          // this line — tsc rejects a `!== "none"` test as provably dead. That narrowing is the
          // guarantee that this never speaks for a tool nobody looked at, which is the boundary
          // norviq/api/routers/intents.py draws when it builds the same list.
          const authoritative = set.pinnable !== null;
          const ambiguous = set.keys.filter((k) => set.ambiguous.has(k));
          // An ambiguous path is excluded from `pinnable` by construction, so without this it would
          // ALSO be reported here — under the wrong explanation. `filters.id` is a perfectly good
          // string path; it is unusable because a caller can mint it, not because the engine could not
          // derive it. Two reasons for one name, one of them false, is worse than one.
          const unpinnable = authoritative
            ? set.keys.filter((k) => !set.pinnable!.has(k) && !set.ambiguous.has(k))
            : [];
          return (
            <div key={tool} style={{ marginTop: 6 }}>
              <ArgName name={tool} /> carried
              {/* This tool's own share of the sample, so the list below is read against the evidence
                  base it actually has rather than against the whole replay. */}
              {set.calls != null && (
                <span style={{ color: "var(--text-muted)" }}>
                  {" "}
                  (on {set.calls} of the {sampled} sampled calls)
                </span>
              )}
              :
              <div
                data-testid={`arg-carried-${rule.id}`}
                style={{ display: "flex", flexDirection: "column", gap: 3, marginTop: 3 }}
              >
                {set.keys.map((name) => {
                  const mention = scoped.get(name);
                  const look = lookalikeOf(name);
                  return (
                    <div key={name}>
                      <ArgName name={name} />{" "}
                      {mention === undefined ? (
                        <span
                          className="pill"
                          data-testid={`unscoped-arg-${rule.id}`}
                          style={{ background: ESCALATE_WASH, color: "var(--escalate)", borderColor: ESCALATE_BORDER }}
                        >
                          Not in this rule
                        </span>
                      ) : mention === "presence" ? (
                        // Mentioned, and still unconstrained. `{"matches": ".*"}` requires the
                        // argument to BE THERE and permits every value it could hold.
                        <span
                          className="pill"
                          data-testid={`presence-only-arg-${rule.id}`}
                          style={{ background: ESCALATE_WASH, color: "var(--escalate)", borderColor: ESCALATE_BORDER }}
                        >
                          Only required to be present, not what it contains
                        </span>
                      ) : (
                        <span style={{ color: "var(--text-muted)" }}>· this rule constrains its value</span>
                      )}
                      {look && (
                        <ArgLookalikeNote lookalikes={[look]} testId={`arg-lookalike-${rule.id}`} />
                      )}
                    </div>
                  );
                })}
              </div>
              {ambiguous.length > 0 && (
                // The API flags these and refuses to assert them; saying nothing here would leave the
                // console recommending the one clause the API deliberately declined to write.
                <div
                  data-testid={`arg-ambiguous-${rule.id}`}
                  style={{ marginTop: 5, color: "var(--escalate)" }}
                >
                  {ambiguous.map((n, i) => (
                    <span key={n}>
                      {i > 0 && ", "}
                      <ArgName name={n} />
                    </span>
                  ))}{" "}
                  can be reached by more than one route through the payload, so the caller chooses
                  which value lands there. A clause pinned on {ambiguous.length === 1 ? "it" : "them"}{" "}
                  constrains whichever the caller ordered last — the compiler refuses these for the
                  same reason, so this is a gap to close upstream, not here.
                </div>
              )}
              {unpinnable.length > 0 && (
                // The fintech payload exactly: `{"txn_id": "TXN-8891", "amount": 25.0}`. `amount` is
                // in the key set and NOT in `param_paths` at enforcement time, because that document
                // carries string leaves only. A `param_paths.amount` clause can therefore never be
                // satisfied, the rule then matches nothing, and under `default decision = "block"`
                // every refund is refused. Telling the operator to "add a clause" without this is
                // handing them an outage.
                <div
                  data-testid={`arg-unpinnable-${rule.id}`}
                  style={{ marginTop: 5, color: "var(--escalate)" }}
                >
                  {unpinnable.map((n, i) => (
                    <span key={n}>
                      {i > 0 && ", "}
                      <ArgName name={n} />
                    </span>
                  ))}{" "}
                  {unpinnable.length === 1 ? "was" : "were"} carried but never derived as a matchable
                  path — a numeric or structured value has a name and no string the engine can test. A
                  clause here <strong>never matches</strong>, which would refuse every call to this
                  tool rather than narrow it. Constrain a sibling path, or a data class, instead.
                </div>
              )}
              {set.truncated && (
                <div data-testid={`observed-args-${rule.id}-truncated-${tool}`} style={{ marginTop: 5, color: "var(--escalate)" }}>
                  This list was cut short at the capture bound — there are argument names this screen
                  is not showing you, so an argument missing from it has NOT been ruled out.
                </div>
              )}
            </div>
          );
        })
      )}
      {flagged && (
        <div style={{ marginTop: 7, color: "var(--text-muted)" }}>
          The rule says nothing about{" "}
          {unscoped.length === 1 ? "that argument" : `those ${unscoped.length} arguments`}, so it allows
          the call whatever they contain.
        </div>
      )}
    </div>
  );
}

export function Intents() {
  const { namespace } = useApp();
  const { push } = useToast();
  const navigate = useNavigate();
  const [agentClass, setAgentClass] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [proposal, setProposal] = useState<ProposeResponse | null>(null);
  // The namespace this proposal was built from. The response carries the CLASS it describes but not
  // the namespace, and nothing on this page remounts when the header scope changes (React Router
  // keeps the route), so without recording it the proposal silently re-targets: propose in payments,
  // switch to default, and Save writes payments' allowlist into default — where this page's own
  // subtitle, "Anything an intent does not state is denied", then denies every tool default uses.
  const [proposedNs, setProposedNs] = useState<string | null>(null);
  const [report, setReport] = useState<DryRunResponse | null>(null);
  const [savedDraft, setSavedDraft] = useState<string | null>(null);

  const ns = namespace || "all";
  // Saving a draft is admin-only server-side (`require_admin` in the intents router). Asking who we
  // are lets the button say WHY rather than going grey for an unstated reason.
  const me = useApi(() => fetchMe(), []);
  // Blocked only when we POSITIVELY know the caller is not an admin. An unreachable `/api/v1/me` is
  // not evidence of anything, and treating it as "viewer" made an unrelated endpoint being down
  // present as a permanently dead button with no way to find out why. The real gate is server-side
  // (`require_admin`), so the worst case of being permissive here is an honest 403.
  const notAdmin = Boolean(me.data) && me.data?.role !== "admin";

  // Convert eagerly so the button can state, BEFORE it is pressed, whether the handoff would lose a
  // restriction. `dropped` non-empty means the resulting graph would be MORE PERMISSIVE than the
  // intent that was just dry-run and approved — so the button refuses rather than warning. A warning
  // that can be clicked through is how the permissive version gets saved.
  // Keyed on the PROPOSAL's class, never the input box. Typing in the box after proposing used to
  // re-seed the builder graph with a class the rules were not proposed from — a policy scoped to an
  // agent class that never made those calls.
  const handoff = useMemo(
    () =>
      proposal?.intent
        ? intentToBuilderGraph(proposal.intent as IntentLike, proposal.intent.class)
        : { graph: null as BuilderGraph | null, dropped: [] as string[] },
    [proposal]
  );

  /** The box has been edited since this proposal was made, so the two no longer describe one class. */
  const classStale = Boolean(proposal && agentClass.trim() && proposal.intent.class !== agentClass.trim());
  /** The header scope moved since this proposal was made. Same failure as the class drift above and
   *  strictly more dangerous — the class is at least visible in the box, whereas nothing on this page
   *  echoes the namespace a proposal came from. */
  const nsStale = Boolean(proposal && proposedNs && ns !== proposedNs);
  const stale = classStale || nsStale;

  const openInBuilder = useCallback(() => {
    // Belt and braces: the button is disabled when a restriction would be lost, but the refusal
    // stays here too. A guard that lives only in a `disabled` attribute is one keyboard shortcut or
    // one refactor away from being gone, and what it protects is the weaker policy being saved.
    if (!handoff.graph || handoff.dropped.length) return;
    // The builder owns authoring and the gated save; nothing here enforces. Carrying the graph in
    // router state (not a query string) keeps a policy body out of browser history and access logs.
    // `/policies/catalog`, NOT `/policies`. App.tsx routes `/policies` through
    // `<Navigate to="/policies/catalog" replace />`, and a redirect does not carry router state — so
    // targeting the shorthand delivered the operator to the catalog with `location.state` null and the
    // builder never opened. Found only by walking the flow in a browser: the unit tests covered the
    // converter and the seeding separately and rendered BuilderSheet directly, so nothing exercised
    // navigate -> redirect -> catalog. Deep-link to the real route.
    navigate("/policies/catalog", { state: { builderGraph: handoff.graph, fromIntent: proposal?.intent?.name ?? "" } });
  }, [handoff, navigate, proposal, push]);

  const reset = () => {
    setReport(null);
    setSavedDraft(null);
  };

  const propose = useCallback(async () => {
    if (!agentClass.trim()) return;
    setBusy("propose");
    reset();
    try {
      const res = await apiSend<ProposeResponse>("/api/v1/intents/propose", "POST", {
        ns,
        cls: agentClass.trim(),
        name: `${agentClass.trim()}-intent`.toLowerCase().replace(/[^a-z0-9-]+/g, "-").slice(0, 63)
      });
      setProposal(res);
      setProposedNs(ns);
      push({ kind: "success", message: `Proposed ${res.intent.call?.length ?? 0} rules from ${res.sampled} calls` });
    } catch (err) {
      setProposal(null);
      setProposedNs(null);
      push({ kind: "error", message: (err as Error).message || "Could not propose an intent" });
    } finally {
      setBusy(null);
    }
  }, [agentClass, ns, push]);

  const dryRun = useCallback(async () => {
    if (!proposal) return;
    setBusy("dryrun");
    try {
      const res = await apiSend<DryRunResponse>("/api/v1/intents/dry-run", "POST", {
        ns,
        cls: proposal.intent.class,
        intent: proposal.intent
      });
      setReport(res);
    } catch (err) {
      push({ kind: "error", message: (err as Error).message || "Dry run failed" });
    } finally {
      setBusy(null);
    }
  }, [proposal, ns, push]);

  const saveDraft = useCallback(async () => {
    if (!proposal) return;
    setBusy("draft");
    try {
      const res = await apiSend<{ draft_id: string }>("/api/v1/intents/drafts", "POST", {
        // A draft is stored against ONE namespace; "All namespaces" is a view, not a target.
        ns,
        cls: proposal.intent.class,
        intent: proposal.intent
      });
      setSavedDraft(res.draft_id);
      push({ kind: "success", message: "Saved as a non-enforcing draft — apply it from Policy Catalog" });
    } catch (err) {
      push({ kind: "error", message: (err as Error).message || "Could not save the draft" });
    } finally {
      setBusy(null);
    }
  }, [proposal, ns, push]);

  const rules = proposal?.intent.call ?? [];
  // Clauses every rule repeats, stated once above the set instead of on each card. The proposer
  // attaches `data_classes noneOf ['secret']` to everything it emits, so repeating it buries the
  // clauses that actually differ — which is what an operator comparing rules is reading for.
  const hoisted = useMemo(() => commonTerms(rules), [rules]);
  // DISTINCT tools across every rule. Deduped, because two rules may legitimately name the same tool
  // under different operations, and a total that double-counts is worse than no total — it would fail
  // to reconcile with the Attack Graph in the other direction.
  const ruleToolCount = useMemo(() => {
    const tools = new Set<string>();
    for (const r of rules) for (const t of toolsOfRule(r)) tools.add(t);
    return tools.size;
  }, [rules]);
  const grouped = useMemo(() => (report ? groupBlocked(report.blocked) : []), [report]);

  // How much this proposal could see of the arguments its traffic carried, and what those arguments
  // were called. Both derived defensively: an unreadable or self-contradicting response reads as
  // "we saw nothing", never as "we saw everything".
  const detail = useMemo(() => paramsDetailOf(proposal), [proposal]);
  const observed = useMemo(() => readObservedParams(proposal), [proposal]);
  // A rung this console cannot interpret. `paramsDetailOf` already collapses it to `none` so no
  // value-level claim is made from it — but it must not then be SPELLED as `none`, because "nothing
  // was captured" is a definite statement and this is the absence of one. A future server sending a
  // richer rung would otherwise be reported as having captured nothing, while its evidence sat in
  // `observed_params` unrendered.
  const detailUnknown = useMemo(
    () => proposal?.params_detail !== undefined && !isDetail(proposal.params_detail),
    [proposal]
  );
  // Comparable whenever the response actually reported per-tool argument evidence. The top-level rung
  // governs what may be said about VALUES; it does not get to hide NAMES the server sent, and each
  // tool's own `detail` already states what its own list means.
  const canCompare = observed.present;
  const unscopedByRule = useMemo(
    () =>
      canCompare
        ? rules.map((r) => ({ rule: r, args: unscopedArgs(r, observed.byTool) })).filter((x) => x.args.length > 0)
        : [],
    [canCompare, rules, observed]
  );
  const unscopedCount = unscopedByRule.reduce((n, x) => n + x.args.length, 0);
  // Whether any key-set that could have fed that count was cut short. If one was, the count is a
  // FLOOR — and a floor printed as a total is the "12 of 400" failure, one level up from the per-tool
  // list where it was already stated.
  //
  // EVERY TOOL IN THE RULE, not only the tools that contributed an entry. A truncated tool whose
  // visible keys all happen to be scoped contributes nothing to `args`, so keying the check on `args`
  // never consulted it — and that tool is exactly where the unseen names are. It is not an exotic
  // state: the server sets `truncated` whenever `dropped > 0` and `_declared_keys` drops any name
  // carrying a control character, so ONE hostile argument name truncates a two-key tool; and
  // `_add_existence_predicates` scopes the always-present paths, which is precisely how a tool ends
  // up with every visible key already mentioned.
  const truncatedToolsOfRule = useCallback(
    (rule: IntentRule) => toolsOfRule(rule).filter((t) => observed.byTool.get(t)?.truncated),
    [observed]
  );
  /**
   * EVERY RULE, not only the rules that contributed an entry.
   *
   * `unscopedByRule` is already filtered to `args.length > 0`, so asking it whether anything was cut
   * short repeats — one level up — the very mistake this guard was rewritten to fix. A proposal with
   * two rules where the FIRST contributes the only unmentioned argument and the SECOND had its
   * capture cut short printed "1 argument in traffic that no rule mentions" as a definite total: the
   * rule holding the unseen names was excluded from the check by the same predicate that excluded it
   * from the list. The headline counts across all rules, so a bound hit anywhere makes it a floor.
   */
  const truncatedRules = useMemo(
    () => (canCompare ? rules.filter((r) => truncatedToolsOfRule(r).length > 0) : []),
    [canCompare, rules, truncatedToolsOfRule]
  );
  const unscopedPartial = truncatedRules.length > 0;
  // The rules whose capture was cut short and which the bullet list above does NOT name — either
  // because nothing was flagged at all (a screen that says nothing where an operator expects a
  // verdict reads as "there is no gap"), or because the flagged rules are different rules, which
  // leaves "this count is a floor" true but unattributable to anything on screen.
  const truncatedUnnamed = useMemo(() => {
    const named = new Set(unscopedByRule.map(({ rule }) => rule.id));
    return truncatedRules.filter((r) => !named.has(r.id));
  }, [truncatedRules, unscopedByRule]);

  // KEEP THESE SHORT. The reason renders in the Panel's action row, right-aligned to its own column —
  // whose right edge sits MID-ROW, so a long reason extends leftward underneath the neighbouring
  // button and reads as text floating between the two controls rather than as belonging to either.
  //
  // The dry-run case was also saying the same thing twice: this string and `dryrun-hint` below were
  // near-identical sentences on screen simultaneously. The full explanation belongs in the body hint,
  // which is full-width and left-aligned; the button gets the pointer.
  const draftBlocker = ns === "all"
    ? "Pick one namespace first."
    : nsStale
      // Refuse rather than warn: saving here writes another namespace's allowlist into this one.
      ? `This proposal was built from ${proposedNs} — propose again for ${ns}.`
      : !report
        ? "Dry run it first."
        : notAdmin
          ? "Needs admin — you are a viewer."
          : undefined;

  const builderBlocker = ns === "all"
    ? "Pick one namespace first."
    : handoff.dropped.length > 0
      // The detail is in the `handoff-blocked` band above, which names each lost restriction. This
      // only has to say the button is refusing and point at it.
      ? `${handoff.dropped.length} restriction${handoff.dropped.length === 1 ? "" : "s"} can't carry across — see above.`
      : undefined;

  return (
    // `page-enter stack` is what every other page uses: the fade-in plus a 16px gap between panels.
    // This file previously said `page`, which is not a defined class — so the panels below sat flush
    // against each other with no rhythm. Several classes here were in the same state; see the header.
    <div className="page-enter stack">
      <PageHead
        // Matches the sidebar entry. The two disagreed ("Intents" here, "Propose from traffic" in the
        // nav), which left the page looking like a different destination from the one just clicked.
        title="Propose from traffic"
        subtitle="What each agent class is FOR. Anything an intent does not state is denied."
      />

      <Panel
        title="Start from what it actually did"
        sub="An allowlist written from memory is both too wide and missing the one tool that matters."
      >
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-end" }}>
          <label style={{ display: "flex", flexDirection: "column", gap: 6, minWidth: 240 }}>
            <span className="field-label">Agent class</span>
            <input
              className="input"
              placeholder="support-bot"
              value={agentClass}
              aria-label="Agent class"
              // Editing the box no longer DESTROYS the proposal. It used to clear it on every
              // keystroke, so correcting a typo threw away a dry run that had just taken a minute
              // over 1,284 replayed calls. The proposal names its own class; when the two diverge
              // the page says so and offers to propose again.
              onChange={(e) => setAgentClass(e.target.value)}
            />
          </label>
          <KitButton icon={Wand2} onClick={propose} disabled={!agentClass.trim() || busy !== null}>
            {busy === "propose" ? "Proposing…" : "Propose intent"}
          </KitButton>
        </div>
      </Panel>

      {stale && (
        <Panel data-testid="proposal-stale">
          <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
            <AlertTriangle size={16} style={{ color: "var(--escalate)", flex: "none", marginTop: 2 }} />
            <div style={{ fontSize: 13, lineHeight: 1.6 }}>
              {nsStale ? (
                <>
                  This proposal was built from namespace <code className="mono">{proposedNs}</code>, not{" "}
                  <code className="mono">{ns}</code>. Saving it here would write{" "}
                  <code className="mono">{proposedNs}</code>&rsquo;s allowlist into{" "}
                  <code className="mono">{ns}</code> — and anything an intent does not state is denied, so
                  every tool <code className="mono">{ns}</code> actually uses would be refused. Propose again.
                </>
              ) : (
                <>
                  This proposal is for <code className="mono">{proposal?.intent.class}</code>, not{" "}
                  <code className="mono">{agentClass.trim()}</code>. It is still shown because a dry run over
                  recorded traffic is not cheap to redo — but propose again before saving anything.
                </>
              )}
            </div>
          </div>
        </Panel>
      )}

      {proposal && (
        <>
          {detailUnknown && (
            // NOT `params-warning`. That band asserts "nothing was captured", and here the response
            // said something this console does not understand — which is a different fact and needs a
            // different sentence. No value-level claim is made either way; the names the response DID
            // send are still rendered below, because hiding evidence is not a safe default, and each
            // tool's own state is stated on its own row.
            <Panel data-testid="params-unrecognised" title="Capture state not recognised">
              <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <AlertTriangle size={16} style={{ color: "var(--escalate)", flex: "none", marginTop: 2 }} />
                <div style={{ fontSize: 13, lineHeight: 1.65 }}>
                  This API reported an argument-capture state this console does not know how to read, so
                  it is treated as <strong>unverified</strong> — not as an assurance and not as an
                  absence. Nothing on this screen may be relied on as a statement about argument{" "}
                  <strong>values</strong>; upgrade the console before drafting a rule on the strength of
                  what it shows.
                </div>
              </div>
            </Panel>
          )}

          {detail === "none" && !detailUnknown && (
            // A PRIMARY state, not a footnote. With no recorded arguments this proposal can only name
            // tools, and every argument-level affordance below is suppressed rather than shown empty —
            // an empty ALLOWED IF band would read as "nothing is required here", when the truth is
            // "nothing could be checked".
            <Panel data-testid="params-warning" title="Proposed from tool names only">
              <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <AlertTriangle size={16} style={{ color: "var(--escalate)", flex: "none", marginTop: 2 }} />
                <div style={{ fontSize: 13, lineHeight: 1.65 }}>
                  No call arguments were recorded for this class, so these rules can only name tools and
                  the operation they perform — not recipients, data classes or SQL tables. A rule here
                  grants a tool outright.
                  <div style={{ marginTop: 8, color: "var(--text-secondary)" }}>
                    Nothing was captured — which is <strong>not</strong> the same as the calls having
                    carried no arguments. Turn on argument-name capture, or supply sample calls, before
                    relying on a destination-level rule.
                  </div>
                </div>
              </div>
            </Panel>
          )}

          {detail === "keys" && (
            // The state that did not exist before: names without values. Worth its own band rather
            // than being folded into either neighbour — "tool names only" understates it, and silence
            // (what a `masked` proposal gets) would let an operator read an existence check as a
            // value check.
            <Panel data-testid="params-keys" title="Argument names recorded, values not">
              <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <AlertTriangle size={16} style={{ color: "var(--escalate)", flex: "none", marginTop: 2 }} />
                <div style={{ fontSize: 13, lineHeight: 1.65 }}>
                  This class's traffic was captured with argument <strong>names</strong> only — no values,
                  masked or otherwise. So a rule proposed here can require that an argument was{" "}
                  <strong>present</strong>, but nothing about what it contained: no recipient domain, no
                  amount, no SQL table.
                  <div style={{ marginTop: 8, color: "var(--text-secondary)" }}>
                    The names below are still the useful part — they are what the traffic actually
                    carried, and a rule that does not mention one is a rule that does not constrain it.
                  </div>
                </div>
              </div>
            </Panel>
          )}

          {detail !== "none" && !detailUnknown && !observed.present && (
            // Arguments were captured, but this response did not say WHICH — an older API. Stated
            // rather than rendered as an empty list, because an empty list reads as "there are none".
            <Panel data-testid="observed-args-unavailable">
              <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <AlertTriangle size={16} style={{ color: "var(--escalate)", flex: "none", marginTop: 2 }} />
                <div style={{ fontSize: 13, lineHeight: 1.65 }}>
                  Arguments were captured for this class, but this API did not report{" "}
                  <strong>which</strong> — so the rules below cannot be checked against the argument names
                  the traffic carried. Treat the absence of an argument-level clause as unknown, not as
                  nothing to constrain.
                </div>
              </div>
            </Panel>
          )}

          {unscopedCount > 0 && (
            // THE MOMENT. The rule was authored against a schema's argument names; the traffic carried
            // these. Both operators who reported this described the same dead end — the surface named
            // the tool and never the arguments, so the gap was invisible until a call went through it.
            <Panel
              data-testid="unscoped-args"
              // "2 arguments" reads as the total. When a key-set feeding it was cut short at the
              // capture bound it is a FLOOR, and a floor printed as a total is the same 12-of-400
              // failure the per-tool lists already guard against — an operator who closes the two
              // named here believes they are done.
              title={
                unscopedPartial
                  ? `At least ${unscopedCount} argument${unscopedCount === 1 ? "" : "s"} in traffic that no rule mentions`
                  : unscopedCount === 1
                    ? "1 argument in traffic that no rule mentions"
                    : `${unscopedCount} arguments in traffic that no rule mentions`
              }
              sub={
                unscopedPartial
                  ? "A rule that does not name an argument allows the call whatever that argument contains — and this count is a floor, because capture hit its bound."
                  : "A rule that does not name an argument allows the call whatever that argument contains."
              }
            >
              {/* Announced, like `handoff-blocked`: this band appears after the proposal returns, and
                  a warning that only exists visually is not a warning for everyone who has to act on it. */}
              <div role="status" style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <AlertTriangle size={16} style={{ color: "var(--escalate)", flex: "none", marginTop: 2 }} />
                <div style={{ fontSize: 13, lineHeight: 1.65 }}>
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {unscopedByRule.map(({ rule, args }) => (
                      <li key={rule.id} style={{ marginBottom: 4 }}>
                        <code className="mono" style={{ fontSize: 12 }}>
                          {rule.id}
                        </code>{" "}
                        does not mention{" "}
                        {args.map((a, i) => (
                          <span key={a.name}>
                            {i > 0 && ", "}
                            <ArgName name={a.name} />
                          </span>
                        ))}{" "}
                        — seen on{" "}
                        {[...new Set(args.flatMap((a) => a.tools))].map((t, i) => (
                          <span key={t}>
                            {i > 0 && ", "}
                            <ArgName name={t} />
                          </span>
                        ))}
                        .
                      </li>
                    ))}
                  </ul>
                  <div style={{ marginTop: 8, color: "var(--text-secondary)" }}>
                    Each rule below lists what its tools were seen carrying. Add a clause for the ones
                    that matter before saving — this proposal cannot invent one, because it never saw the
                    values.
                  </div>
                </div>
              </div>
            </Panel>
          )}

          {truncatedUnnamed.length > 0 && (
            // A rule whose capture ran out and which the list above does not name. Two shapes, one
            // sentence: nothing was flagged at all (silence reads as "there is no gap"), or something
            // was flagged on OTHER rules and the headline's "at least" would otherwise point at
            // nothing on screen.
            <Panel
              data-testid="unscoped-args-truncated"
              title={
                unscopedCount === 0
                  ? "Every argument seen is mentioned — but the list was cut short"
                  : "Another rule’s argument capture was cut short"
              }
              sub="The capture bound was hit, so there are argument names this screen was never shown. Absence from it rules nothing out."
            >
              <div role="status" style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
                <AlertTriangle size={16} style={{ color: "var(--escalate)", flex: "none", marginTop: 2 }} />
                <div style={{ fontSize: 13, lineHeight: 1.65 }}>
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {truncatedUnnamed.map((rule) => (
                      <li key={rule.id} style={{ marginBottom: 4 }}>
                        <code className="mono" style={{ fontSize: 12 }}>
                          {rule.id}
                        </code>{" "}
                        — capture was cut short on{" "}
                        {truncatedToolsOfRule(rule).map((t, i) => (
                          <span key={t}>
                            {i > 0 && ", "}
                            <ArgName name={t} />
                          </span>
                        ))}
                        .
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </Panel>
          )}

          {/* `stat-row` was undefined, so these stacked vertically instead of forming a KPI row. The
              rest of the app uses a Tailwind grid for exactly this (see McpServers' five tiles). */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-5">
            {/* The unit, stated. A rule is one OPERATION over one or more tools, so this count is
                smaller than the tool count every other surface reports — see StatTile's `sub`. */}
            <StatTile
              label="Rules"
              value={rules.length}
              sub={`covering ${ruleToolCount} tool${ruleToolCount === 1 ? "" : "s"}, grouped by operation`}
            />
            <StatTile label="Calls sampled" value={proposal.sampled} />
            {report && <StatTile label="Would allow" value={report.would_allow} color="var(--allow)" />}
            {report && (
              <StatTile label="Would block" value={report.would_block} color={report.would_block ? "var(--block)" : undefined} />
            )}
          </div>

          <Panel
            title="Proposed intent"
            sub="Every rule is an ALLOW. There is no deny list — deny is the absence of a match."
            action={
              <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "flex-start" }}>
                <KitButton variant="secondary" icon={Play} onClick={dryRun} disabled={busy !== null}>
                  {busy === "dryrun" ? "Replaying…" : "Dry run"}
                </KitButton>
                {/* WHY AN ACTION IS UNAVAILABLE, as text beside the control. These were `title`
                    tooltips: `.btn:disabled` sets `pointer-events: none`, so a disabled button never
                    receives the hover that would show its own explanation. */}
                <InlineDisabledReason reason={draftBlocker} tone={notAdmin ? "muted" : "escalate"} data-testid="draft-gate">
                  <KitButton
                    variant="secondary"
                    icon={FileText}
                    onClick={saveDraft}
                    data-testid="save-draft"
                    disabled={busy !== null || Boolean(draftBlocker)}
                  >
                    {busy === "draft" ? "Saving…" : "Save as draft"}
                  </KitButton>
                </InlineDisabledReason>
                {/* The handoff. This screen proposes from RECORDED TRAFFIC and replays it — the two
                    things the builder structurally cannot do. Editing belongs in the builder, so
                    this hands the proposal over rather than growing a second editor here.

                    DISABLED when a restriction would be lost. The banner below has said so since
                    9ecd610, but the button stayed live: clicking it fired a toast showing only the
                    first reason and went nowhere, so the page both refused and looked broken. */}
                <InlineDisabledReason
                  reason={builderBlocker}
                  tone={handoff.dropped.length > 0 ? "block" : "escalate"}
                  data-testid="builder-gate"
                >
                  <KitButton
                    variant="secondary"
                    icon={PencilLine}
                    data-testid="open-in-builder"
                    onClick={openInBuilder}
                    disabled={busy !== null || !proposal || Boolean(builderBlocker)}
                  >
                    Open in Visual Builder
                  </KitButton>
                </InlineDisabledReason>
              </div>
            }
          >
            {/* The handoff REFUSES rather than warns when a restriction cannot be carried across,
                because a warning that can be clicked through is how the weaker policy gets saved.
                Naming each lost restriction is what makes the refusal actionable — the operator can
                re-add them by hand in the builder, or keep the stronger intent as a draft. */}
            {handoff.dropped.length > 0 && (
              <div
                data-testid="handoff-blocked"
                role="status"
                style={{
                  fontSize: 12.5,
                  lineHeight: 1.6,
                  marginBottom: 12,
                  padding: "10px 12px",
                  borderRadius: 10,
                  border: "1px solid #FFB02030",
                  background: "#FFB02015",
                  color: "var(--text-secondary)"
                }}
              >
                <strong style={{ color: "var(--escalate)" }}>
                  This proposal cannot be opened in the builder.
                </strong>{" "}
                {handoff.dropped.length === 1 ? "One restriction has" : `${handoff.dropped.length} restrictions have`}{" "}
                no allowlist equivalent.
                <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                  {handoff.dropped.map((d) => (
                    <li key={d}>{d}</li>
                  ))}
                </ul>
                <div style={{ marginTop: 6, color: "var(--text-muted)" }}>
                  Save it as a draft and apply it from Policy Catalog, or re-add these by hand in the builder.
                </div>
              </div>
            )}
            {!report && (
              // The single home for WHY the dry run comes first. The Save-as-draft button carries only
              // the short pointer ("Dry run it first."), so the two are no longer near-identical
              // sentences competing on the same screen.
              <div className="muted" style={{ fontSize: 12, marginBottom: 10 }} data-testid="dryrun-hint">
                Dry run this against recorded traffic before saving — the draft is only worth having once
                you know what it would have refused. <strong>Save as draft stays disabled until it has run.</strong>
              </div>
            )}
            {hoisted.length > 0 && (
              <div
                data-testid="hoisted-clauses"
                style={{
                  fontSize: 12.5,
                  lineHeight: 1.6,
                  padding: "9px 11px",
                  borderRadius: 10,
                  background: "var(--bg-elevated)",
                  color: "var(--text-secondary)",
                  marginBottom: 10
                }}
              >
                <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>Applied to every rule:</span>{" "}
                {hoisted.map((t) => predicateSentence(t).prose).join("; ")} — stated once here instead of repeated
                on all {rules.length}.
              </div>
            )}
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {rules.map((rule) => (
                <div key={rule.id} style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  <RuleCard
                    rule={rule}
                    calls={report ? (report.coverage?.[rule.id] ?? 0) : null}
                    unused={Boolean(report?.unused_rules?.includes(rule.id))}
                    hoisted={hoisted.map((t) => t.raw)}
                  />
                  {/* The rule as WRITTEN is above; this is the traffic it will meet. Directly beneath
                      it, because the comparison is the point and a band elsewhere on the page is a
                      comparison the operator has to do from memory. */}
                  {canCompare && <RuleArguments rule={rule} byTool={observed.byTool} sampled={proposal.sampled} />}
                </div>
              ))}
            </div>
          </Panel>
        </>
      )}

      {report && (
        <Panel
          title={report.would_block ? "What this would have refused" : "Nothing legitimate would break"}
          sub={
            report.would_block
              ? "The closest rule and the clause that failed — tighten the rule, or accept the denial."
              : "Every recorded call is covered by a rule. That is the point at which this is safe to draft."
          }
        >
          {report.would_block === 0 ? (
            <div style={{ display: "flex", gap: 10, alignItems: "center" }} data-testid="no-blocks">
              <CheckCircle2 size={16} /> {report.total} recorded calls replayed, none refused.
            </div>
          ) : (
            <div data-testid="near-misses">
              {/* Grouped: replaying 1,284 calls produces one row per call, and 1,241 identical
                  `run_query` refusals bury the single interesting one. The operator has one decision
                  per distinct reason, not one per call. */}
              {grouped.map(({ call, occurrences }) => (
                <NearMissCard key={call.index} call={call} occurrences={occurrences} />
              ))}
            </div>
          )}
        </Panel>
      )}

      {savedDraft && (
        <Panel data-testid="draft-saved">
          <div style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
            <FileText size={16} style={{ flex: "none", marginTop: 2 }} />
            <div>
              Draft <code>{savedDraft}</code> saved and <strong>not enforcing</strong>. Review and apply it
              from Policy Catalog — that is the only place enforcement begins.
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}

export default Intents;
