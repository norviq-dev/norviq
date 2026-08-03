// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Norviq Contributors

/**
 * The predicate vocabulary. Two properties matter more than any individual phrasing:
 *
 *  1. a shape we cannot state safely keeps its RAW form, so prose never overstates the policy;
 *  2. a label and the structured rule it came from produce the SAME sentence, because the README
 *     forbids two dialects for one clause and an operator comparing a rule card to a near-miss
 *     cannot tell whether differently-worded text is the same restriction.
 */

import { describe, expect, it } from "vitest";
import {
  addressDomainOf,
  commonTerms,
  parsePredicateLabel,
  sentenceOf,
  termsOfRule
} from "./predicateSentence";

describe("parsePredicateLabel", () => {
  it("parses a Python list repr, commas inside values included", () => {
    // The label grammar carries `['a', 'b']`, so a naive split on ", " both shreds the list and
    // breaks the near-miss reconciliation that depends on labels staying whole.
    const t = parsePredicateLabel("sql_tables subsetOf ['customers', 'tickets']");
    expect(t.field).toBe("sql_tables");
    expect(t.op).toBe("subsetOf");
    expect(t.value).toEqual(["customers", "tickets"]);
  });

  it("recognises the compiler's own predicates as implicit", () => {
    expect(parsePredicateLabel("direction == call").implicit).toBe(true);
    expect(parsePredicateLabel("data_classes is published by this engine").implicit).toBe(true);
    expect(parsePredicateLabel("verb == read").implicit).toBe(false);
  });

  it("keeps a regex whole — it contains spaces, brackets and operators of its own", () => {
    const t = parsePredicateLabel("param_paths.to matches ^[^@]+@acme\\.com$");
    expect(t.op).toBe("matches");
    expect(t.value).toBe("^[^@]+@acme\\.com$");
  });

  it("returns an opaque term for a label it does not recognise", () => {
    const t = parsePredicateLabel("something the compiler has not emitted before");
    expect(t.field).toBe("");
    expect(t.raw).toBe("something the compiler has not emitted before");
  });
});

describe("predicateSentence", () => {
  it("states the subject, never a fragment", () => {
    // "is slack" reads as a fragment in a list; the near-miss card is exactly such a list.
    expect(sentenceOf("mcp.server == slack").prose).toBe("it came through the slack server");
    expect(sentenceOf("tool_name == send_email").prose).toBe("calls to send_email");
    expect(sentenceOf("verb == read").prose).toBe("the operation is read");
    expect(sentenceOf("data_classes noneOf ['secret']").prose).toBe("it carries none of secret");
    expect(sentenceOf("sql_tables subsetOf ['customers', 'tickets']").prose).toBe(
      "the SQL touches only customers, tickets"
    );
  });

  it("names an anchored address regex as the domain it pins", () => {
    expect(addressDomainOf("^[^@]+@acme\\.com$")).toBe("acme.com");
    expect(sentenceOf("param_paths.to matches ^[^@]+@acme\\.com$").prose).toBe(
      "the to is an address at acme.com"
    );
  });

  it("refuses to paraphrase a regex it cannot read, and says so by falling back", () => {
    // The operator approves the sentence; the engine enforces the regex. Prose that overstates the
    // predicate is the one failure mode worth being conservative about.
    expect(addressDomainOf("^.*@.*$")).toBeNull();
    const s = sentenceOf("param_paths.to matches ^(a|b)+c$");
    expect(s.prose).toContain("^(a|b)+c$");
  });

  it("explains the availability guard rather than hiding it", () => {
    // Without this predicate an intent FAILS OPEN on an older engine. Named, the operator diagnoses
    // a version skew; unnamed, they conclude the policy is broken and switch it off.
    const s = sentenceOf("data_classes is published by this engine");
    expect(s.prose).toBe("this engine publishes data_classes");
    expect(s.implicit).toBe(true);
  });

  it("keeps an unrecognised predicate as its raw self and marks it un-humanised", () => {
    const s = sentenceOf("weird_field someOp 42");
    expect(s.prose).toBe(s.raw);
    expect(s.humanised).toBe(false);
  });
});

describe("termsOfRule", () => {
  it("splits match from require, because they answer different questions", () => {
    const { appliesTo, allowedIf } = termsOfRule({
      server: "slack",
      match: { tool_name: "send_email" },
      require: { "param_paths.to": { matches: "^[^@]+@acme\\.com$" } }
    });
    expect(appliesTo.map((t) => t.raw)).toEqual(["mcp.server == slack", "tool_name == send_email"]);
    expect(allowedIf.map((t) => t.raw)).toEqual(["param_paths.to matches ^[^@]+@acme\\.com$"]);
  });

  it("produces the SAME sentence from a rule as from the compiler's label", () => {
    // The one-vocabulary requirement, asserted rather than assumed. If these diverge, an operator
    // comparing a rule card with a near-miss cannot tell whether it is the same restriction.
    const { allowedIf } = termsOfRule({ require: { data_classes: { noneOf: ["secret"] } } });
    expect(allowedIf[0].raw).toBe("data_classes noneOf ['secret']");
    expect(sentenceOf(allowedIf[0].raw).prose).toBe("it carries none of secret");
  });

  it("normalises `equals` to the compiler's `==`", () => {
    const { appliesTo } = termsOfRule({ match: { verb: { equals: "read" } } });
    expect(appliesTo[0].raw).toBe("verb == read");
  });
});

describe("commonTerms", () => {
  it("finds the clause every rule repeats, so it can be stated once", () => {
    // The proposer attaches `data_classes noneOf ['secret']` to every rule. Repeating it on each
    // card buries the clauses that actually differ, which is what the operator is comparing.
    const rules = [
      { require: { data_classes: { noneOf: ["secret"] } } },
      { require: { data_classes: { noneOf: ["secret"] }, sql_tables: { subsetOf: ["t"] } } },
      { require: { data_classes: { noneOf: ["secret"] } } }
    ];
    expect(commonTerms(rules).map((t) => t.raw)).toEqual(["data_classes noneOf ['secret']"]);
  });

  it("hoists nothing when a rule differs — a clause on two of three rules is not common", () => {
    const rules = [
      { require: { data_classes: { noneOf: ["secret"] } } },
      { require: {} },
      { require: { data_classes: { noneOf: ["secret"] } } }
    ];
    expect(commonTerms(rules)).toEqual([]);
  });

  it("hoists nothing from a single rule — there is no repetition to remove", () => {
    expect(commonTerms([{ require: { data_classes: { noneOf: ["secret"] } } }])).toEqual([]);
  });
});
