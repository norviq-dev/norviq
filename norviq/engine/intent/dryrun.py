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
import shutil
import subprocess
import tempfile
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from norviq.engine.intent.compiler import CompiledIntent, compile_intent

# (rego_source, policy_input) -> {"decision": ..., "rule_id": ..., "reason": ...}
Evaluator = Callable[[str, dict], dict]


@dataclass
class CallOutcome:
    """One recorded call replayed against the candidate intent."""

    index: int
    decision: str
    rule_id: str
    reason: str
    tool_name: str = ""

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
                {"index": o.index, "tool_name": o.tool_name, "reason": o.reason}
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
                 f"data.norviq.custom.{key}"],
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
        report.total += 1
        if outcome.would_block:
            report.would_block += 1
            report.blocked.append(outcome)
        else:
            report.would_allow += 1
            counts[rule_id] += 1

    report.coverage = dict(counts)
    return report
