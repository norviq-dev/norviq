# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Replay recorded traffic against a candidate intent, before it can enforce anything.

Deny-by-default that is switched on cold gets switched off in week one. The only honest way to
propose one is to show the operator, from their own traffic, exactly which calls it would have
refused and why — which is also why `IntentDraft` is a dedicated table the evaluator never reads.

The replay evaluates the REAL generated Rego through the caller's evaluator. It deliberately does not
reimplement predicate semantics in Python: a second implementation would drift from the first, and
the drifted one would be the one the operator was shown before they approved.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from norviq.engine.intent.compiler import CompiledIntent, compile_intent

_PACKAGE_RE = re.compile(r"(?m)^\s*package\s+([A-Za-z0-9_.]+)\s*$")


def _declared_package(rego: str) -> str:
    """The package the module actually declares.

    Read from the module rather than hardcoded. The previous hardcode (`data.norviq.custom.<key>`)
    was silently coupled to the compiler's package name: moving the compiler to
    `norviq.intent.<class>` made every `opa eval` here return no result, and `dry_run` reads a missing
    decision as a BLOCK — so a perfectly good intent would have been reported as blocking 100% of
    recorded traffic, which is the single most likely reason an operator abandons deny-by-default.
    Parsing keeps this evaluator package-agnostic, matching what the API-side evaluator already does
    via `rewrite_package`.
    """
    match = _PACKAGE_RE.search(rego or "")
    return match.group(1) if match else "norviq.custom"

# (rego_source, policy_input) -> {"decision": ..., "rule_id": ..., "reason": ...}
Evaluator = Callable[[str, dict], dict]


_NEAR_MISS_RE = re.compile(
    r"^no intent rule matched; closest (?P<rule>.+?) met (?P<met>\d+)/(?P<total>\d+), failed: (?P<failed>.*)$"
)


def split_failed_labels(candidates: Sequence[str], joined: str) -> list[str]:
    """Recover the failed-predicate LIST from the `", "`-joined tail of a near-miss reason.

    A plain `joined.split(", ")` is wrong, and quietly so. Predicate labels are generated from Python
    reprs — `tool_name in ['send_email', 'run_query']` — so a single label routinely CONTAINS `", "`.
    Splitting on it shreds one clause into three, which then neither matches a real predicate nor adds
    up against the `met M/N` in the same sentence.

    Knowing the candidate labels makes it unambiguous: the compiler emits `sort([...])`, so the tail is
    the sorted candidates joined in order. Walk it, matching the LONGEST candidate that is a prefix at
    each position — longest-first because one label may prefix another (`x in [1]` prefixes
    `x in [1, 2]`).

    Returns `[]` when the tail cannot be accounted for exactly. A partial parse is worse than none:
    the caller uses this to tick clauses as passed, and a clause wrongly shown as passed is a
    restriction the operator believes is in force when it is not.
    """
    remaining = joined.strip()
    if not remaining:
        return []
    by_length = sorted(candidates, key=len, reverse=True)
    out: list[str] = []
    while remaining:
        for label in by_length:
            if remaining == label:
                out.append(label)
                return out
            if remaining.startswith(label + ", "):
                out.append(label)
                remaining = remaining[len(label) + 2:]
                break
        else:
            return []  # unaccounted-for text — report nothing rather than something wrong
    return out


@dataclass
class CallOutcome:
    """One recorded call replayed against the candidate intent."""

    index: int
    decision: str
    rule_id: str
    reason: str
    tool_name: str = ""
    # The near miss, decomposed. The reason STRING already carries all of this, but only a console
    # willing to re-implement the compiler's label rules in another language could take it apart —
    # and that second implementation would drift from this one, which is the whole reason
    # `CompiledIntent.labels` exists. Empty when the call was allowed or the reason did not parse.
    closest_rule: str = ""
    met: int = 0
    predicates: tuple[str, ...] = ()
    failed: tuple[str, ...] = ()

    @property
    def would_block(self) -> bool:
        return self.decision != "allow"


@dataclass
class DryRunReport:
    """What the operator is shown before they are asked to approve."""

    total: int = 0
    would_allow: int = 0
    would_block: int = 0
    # Rule id -> how many calls it permitted. A rule covering ZERO recorded calls is the interesting
    # one: either the traffic does not exercise it, or it is written wrongly and never matches.
    coverage: dict = field(default_factory=dict)
    # The calls that would newly break, with the near-miss for each. This is the list the operator
    # actually reads, so it is kept whole rather than summarised to a count.
    blocked: list = field(default_factory=list)

    @property
    def unused_rules(self) -> list:
        return sorted(rid for rid, n in self.coverage.items() if n == 0)

    def as_dict(self) -> dict:
        return {
            "total": self.total,
            "would_allow": self.would_allow,
            "would_block": self.would_block,
            "coverage": dict(sorted(self.coverage.items())),
            "unused_rules": self.unused_rules,
            "blocked": [
                {
                    "index": o.index,
                    "tool_name": o.tool_name,
                    "reason": o.reason,
                    # The near miss as data. `predicates` is EVERY clause the closest rule asserts,
                    # including the ones the compiler adds itself (the plane, and the availability
                    # guards for version-gated roots). Rendering only the operator-authored clauses
                    # is what makes "met 3 of 4" fail to add up against a list of two.
                    "closest_rule": o.closest_rule,
                    "met": o.met,
                    "predicates": list(o.predicates),
                    "failed": list(o.failed),
                }
                for o in self.blocked
            ],
        }


def opa_subprocess_evaluator(rego: str, payload: dict) -> dict:
    """Evaluate via the `opa` binary. Suitable for offline use and tests.

    In the API, pass an evaluator backed by the running OPA server instead — this spawns a process
    per call, which is fine for an operator-initiated replay over a sample and wrong for anything on
    a hot path.
    """
    if shutil.which("opa") is None:  # pragma: no cover - environment guard
        raise RuntimeError("opa binary not found; pass an explicit evaluator")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "intent.rego"
        path.write_text(rego, encoding="utf-8")
        out: dict = {}
        for key in ("decision", "rule_id", "reason"):
            proc = subprocess.run(
                ["opa", "eval", "--v0-compatible", "-d", str(path), "-I",
                 f"data.{_declared_package(rego)}.{key}"],
                input=json.dumps(payload), capture_output=True, text=True, check=True,
            )
            result = json.loads(proc.stdout).get("result") or []
            out[key] = result[0]["expressions"][0]["value"] if result else None
        return out


def dry_run(
    intent: dict | CompiledIntent,
    calls: Sequence[dict] | Iterable[dict],
    evaluator: Evaluator | None = None,
) -> DryRunReport:
    """Replay `calls` (policy input documents) against `intent` without enforcing anything.

    Returns a report, never a decision: nothing here writes to `policies`, and applying a draft stays
    an explicit operator action through the gated Policies flow.
    """
    compiled = intent if isinstance(intent, CompiledIntent) else compile_intent(intent)
    evaluate = evaluator or opa_subprocess_evaluator

    report = DryRunReport()
    # Seed every rule at zero so a rule that matches nothing is visible as 0 rather than absent.
    counts: Counter = Counter({rid: 0 for rid in compiled.rule_ids})

    for index, payload in enumerate(calls):
        result = evaluate(compiled.rego, payload) or {}
        decision = result.get("decision") or "block"
        rule_id = result.get("rule_id") or "intent_no_match"
        reason = result.get("reason") or "no intent rule matched this call"
        outcome = CallOutcome(
            index=index,
            decision=decision,
            rule_id=rule_id,
            reason=reason,
            tool_name=str(payload.get("tool_name", "")),
        )
        # Decompose the near miss HERE, next to the compiler that formats it, rather than leaving a
        # console to do it. `compiled.labels` is the authority on what a rule asserts; anything that
        # reconstructs the list from the intent document alone will miss the clauses the compiler
        # adds and will disagree with the `met M/N` in the same sentence.
        if outcome.would_block:
            match = _NEAR_MISS_RE.match(reason)
            if match:
                rid = match.group("rule")
                candidates = tuple(compiled.labels.get(rid, ()))
                failed = tuple(split_failed_labels(candidates, match.group("failed")))
                met = int(match.group("met"))
                total = int(match.group("total"))
                # Publish only a set that RECONCILES. If the parse and the compiler disagree the
                # honest output is the raw sentence, not a tick-list that quietly contradicts it.
                if len(candidates) == total and len(failed) == total - met:
                    outcome.closest_rule = rid
                    outcome.met = met
                    outcome.predicates = candidates
                    outcome.failed = failed
        report.total += 1
        if outcome.would_block:
            report.would_block += 1
            report.blocked.append(outcome)
        else:
            report.would_allow += 1
            counts[rule_id] += 1

    report.coverage = dict(counts)
    return report
