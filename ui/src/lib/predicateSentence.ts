// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * One vocabulary for predicates, used by every surface that shows one.
 *
 * The rule cards read a structured intent; the near-miss card reads the compiler's own label strings.
 * Rendering those separately produced two dialects for the same clause — the card saying "the SQL
 * touches only tickets, customers" beside a near-miss saying `sql_tables subsetOf ['customers',
 * 'tickets']` — and an operator comparing them cannot tell whether they are the same restriction.
 * So labels are parsed BACK into a term and both surfaces humanise from there.
 *
 * WHAT THIS DELIBERATELY WILL NOT DO. Humanisation only fires for shapes whose meaning can be read
 * off the predicate itself. `^[^@]+@acme\.com$` becomes "an address at acme.com" because that regex
 * says exactly that; anything else keeps its raw form. Prose that overstates a predicate is worse
 * than no prose, because the operator approves the sentence and the engine enforces the regex.
 */

/** A predicate as both surfaces understand it. `raw` is always the engine's own words. */
export type PredicateTerm = {
  field: string;
  op: string;
  /** Scalar for equals/matches, list for the collection operators. */
  value: string | string[] | number | null;
  raw: string;
  /** Emitted by the compiler rather than authored by the operator. */
  implicit: boolean;
};

/** `['a', 'b']` — a Python list repr, which is what the compiler's labels carry. */
function parsePyList(text: string): string[] | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith("[") || !trimmed.endsWith("]")) return null;
  const inner = trimmed.slice(1, -1).trim();
  if (!inner) return [];
  const out: string[] = [];
  // Split on commas that sit outside quotes: a value may legitimately contain one.
  let cur = "";
  let quote: string | null = null;
  for (const ch of inner) {
    if (quote) {
      if (ch === quote) quote = null;
      else cur += ch;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === ",") {
      out.push(cur.trim());
      cur = "";
      continue;
    }
    cur += ch;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

const COLLECTION_OPS = new Set(["in", "subsetOf", "noneOf", "anyOf"]);

/**
 * Turn a compiler label back into a term.
 *
 * The label grammar is `<field> <op> <value>`, with three shapes that do not fit it: the plane
 * predicate, the availability guards, and `count(<field>) <= n`. Anything unrecognised comes back as
 * an opaque term whose prose IS the raw label — degraded, never wrong.
 */
export function parsePredicateLabel(label: string): PredicateTerm {
  const opaque: PredicateTerm = { field: "", op: "", value: null, raw: label, implicit: false };

  const published = /^(\S+) is published by this engine$/.exec(label);
  if (published) return { field: published[1], op: "isPublished", value: null, raw: label, implicit: true };

  const direction = /^direction == (\S+)$/.exec(label);
  if (direction) return { field: "direction", op: "==", value: direction[1], raw: label, implicit: true };

  const counted = /^count\((\S+)\) <= (\d+)$/.exec(label);
  if (counted) return { field: counted[1], op: "maxCount", value: Number(counted[2]), raw: label, implicit: false };

  const m = /^(\S+) (==|!matches|matches|in|subsetOf|noneOf|anyOf|<=|>=) (.*)$/.exec(label);
  if (!m) return opaque;
  const [, field, op, rest] = m;
  if (COLLECTION_OPS.has(op)) {
    const list = parsePyList(rest);
    return { field, op, value: list ?? rest, raw: label, implicit: false };
  }
  if (op === "<=" || op === ">=") {
    const n = Number(rest);
    return { field, op, value: Number.isFinite(n) ? n : rest, raw: label, implicit: false };
  }
  return { field, op, value: rest, raw: label, implicit: false };
}

/** Build a term from the structured intent, using the SAME label grammar the compiler emits. */
export function termFrom(field: string, op: string, value: PredicateTerm["value"]): PredicateTerm {
  const rendered = Array.isArray(value)
    ? `[${value.map((v) => `'${v}'`).join(", ")}]`
    : String(value);
  const raw = op === "==" ? `${field} == ${rendered}` : `${field} ${op} ${rendered}`;
  return { field, op, value, raw, implicit: false };
}

function list(values: string[]): string {
  return values.join(", ");
}

/**
 * The domain a `^[^@]+@example\.com$`-shaped regex pins an address to.
 *
 * Narrow by design: it matches only the exact anchored shape the proposer emits. A regex that is
 * merely similar keeps its raw form, because "an address at acme.com" is a claim about what the
 * policy enforces and a near-miss regex is not something to paraphrase optimistically.
 */
export function addressDomainOf(regex: string): string | null {
  const m = /^\^\[\^@\]\+@([A-Za-z0-9.-]+?)\\?\.([A-Za-z]{2,})\$$/.exec(regex);
  return m ? `${m[1]}.${m[2]}` : null;
}

const FIELD_NOUN: Record<string, string> = {
  tool_name: "the tool",
  verb: "the operation",
  "mcp.server": "the MCP server",
  "mcp.pin_status": "the pin status",
  "mcp.scan_severity": "the scan severity",
  data_classes: "the payload",
  sql_tables: "the SQL",
  "destinations.hosts": "the destination host",
  trust: "the caller's trust",
  direction: "the plane"
};

export type Sentence = {
  /** What the operator reads. Falls back to `raw` when the shape is not one we can state safely. */
  prose: string;
  /** The engine's own words — always available behind `Show raw`. */
  raw: string;
  /** False when `prose === raw`, so a caller can avoid offering a pointless toggle. */
  humanised: boolean;
  implicit: boolean;
};

/**
 * A predicate as a sentence.
 *
 * The subject is stated in every case. "is slack" is only readable next to the field name; on its own
 * in a near-miss list it reads as a fragment, and a list of fragments is what made the old reason
 * string unreadable in the first place.
 */
export function predicateSentence(term: PredicateTerm): Sentence {
  const { field, op, value, raw, implicit } = term;
  const done = (prose: string): Sentence => ({ prose, raw, humanised: prose !== raw, implicit });

  if (op === "isPublished") {
    // Named, not hidden: an operator told "data_classes is published by this engine failed" can
    // diagnose a version skew. Told nothing, they disable the policy.
    return { prose: `this engine publishes ${field}`, raw, humanised: true, implicit: true };
  }
  if (field === "direction") return { prose: `it is a ${String(value)}, not a response`, raw, humanised: true, implicit: true };

  const values = Array.isArray(value) ? value : null;

  if (field === "tool_name") {
    if (op === "==") return done(`calls to ${String(value)}`);
    if (op === "in" && values) return done(values.length === 1 ? `calls to ${values[0]}` : `calls to ${list(values)}`);
  }
  if (field === "verb" && op === "==") return done(`the operation is ${String(value)}`);
  if (field === "mcp.server" && op === "==") return done(`it came through the ${String(value)} server`);
  if (field === "mcp.server" && op === "in" && values) return done(`it came through ${list(values)}`);

  if (field === "data_classes" && op === "noneOf" && values) return done(`it carries none of ${list(values)}`);
  if (field === "data_classes" && op === "anyOf" && values) return done(`it carries one of ${list(values)}`);
  if (field === "sql_tables" && op === "subsetOf" && values) return done(`the SQL touches only ${list(values)}`);
  if (field === "destinations.hosts" && op === "anyOf" && values) return done(`it reaches only ${list(values)}`);
  if (field === "trust" && op === ">=") return done(`the caller's trust is at least ${String(value)}`);

  if (field.startsWith("param_paths.")) {
    const arg = field.slice("param_paths.".length);
    if (op === "matches") {
      const domain = addressDomainOf(String(value));
      if (domain) return done(`the ${arg} is an address at ${domain}`);
      return done(`the ${arg} matches ${String(value)}`);
    }
    if (op === "!matches") return done(`the ${arg} does not match ${String(value)}`);
    if (op === "==") return done(`the ${arg} is ${String(value)}`);
    if (op === "in" && values) return done(`the ${arg} is one of ${list(values)}`);
  }

  if (op === "maxCount") return done(`${FIELD_NOUN[field] ?? field} has at most ${String(value)}`);

  // Nothing safe to say. The raw predicate IS the sentence — less friendly, never a misstatement.
  return { prose: raw, raw, humanised: false, implicit };
}

/** Convenience: label string straight to sentence. */
export function sentenceOf(label: string): Sentence {
  return predicateSentence(parsePredicateLabel(label));
}

/**
 * Terms for one proposed rule, in the order the cards read them.
 *
 * `match` narrows WHICH calls the rule is about; `require` states what must additionally hold. The
 * design splits them into APPLIES TO and ALLOWED IF for that reason: an operator scanning a list of
 * rules is looking for the one that governs a call, and mixing the two bands makes every rule look
 * like it might.
 */
export function termsOfRule(rule: {
  server?: string;
  match?: Record<string, unknown>;
  require?: Record<string, unknown>;
}): { appliesTo: PredicateTerm[]; allowedIf: PredicateTerm[] } {
  const walk = (block?: Record<string, unknown>): PredicateTerm[] => {
    const out: PredicateTerm[] = [];
    Object.entries(block ?? {}).forEach(([field, spec]) => {
      if (typeof spec === "string") {
        out.push(termFrom(field, "==", spec));
        return;
      }
      Object.entries((spec ?? {}) as Record<string, unknown>).forEach(([op, value]) => {
        out.push(termFrom(field, op === "equals" ? "==" : op, value as PredicateTerm["value"]));
      });
    });
    return out;
  };
  const appliesTo = walk(rule.match);
  if (rule.server) appliesTo.unshift(termFrom("mcp.server", "==", rule.server));
  return { appliesTo, allowedIf: walk(rule.require) };
}

/**
 * Predicates every rule in the set asserts identically.
 *
 * The proposer attaches `data_classes noneOf ['secret']` to every rule it emits. Repeating it on each
 * card costs a line per rule and, worse, buries the clauses that actually differ — the operator is
 * comparing rules, and identical text on all of them is noise. Hoisted to one line above the set.
 */
export function commonTerms(rules: Array<{ require?: Record<string, unknown> }>): PredicateTerm[] {
  if (rules.length < 2) return [];
  const sets = rules.map((r) => new Map(termsOfRule(r).allowedIf.map((t) => [t.raw, t])));
  const [first, ...rest] = sets;
  return [...first.values()].filter((t) => rest.every((s) => s.has(t.raw)));
}
