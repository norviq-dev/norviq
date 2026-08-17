# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Per-control false-positive measurement over the benign corpus.

`ATTACKS` answers "did we catch it". This answers "what else did we catch", which is the number that
decides whether a control can ship at `deny`. Both are needed: a control that blocks everything scores
perfectly on recall.

The corpus is evaluated against the REAL compiled baseline module — `baseline.compile(preset, effects)`
with every control at `deny` — rather than against the rules in isolation, because what an operator
ships is the compiled module and that is where a head can be dropped or mis-registered. Attribution
comes from the module's own `rule_id`, so the report names the control an operator would see in the
audit log, not one this file guessed at.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from norviq.redteam.benign import BENIGN, BenignDefinition

#: Query the compiled baseline for the rule that decided the call.
_QUERY_RULE = "data.norviq.presets.strict.rule_id"
_QUERY_DECISION = "data.norviq.presets.strict.decision"


@dataclass(slots=True)
class ControlPrecision:
    """What one control did to legitimate traffic."""

    control_id: str
    fired_on: list[str] = field(default_factory=list)          # benign ids it blocked UNEXPECTEDLY
    regressions: list[str] = field(default_factory=list)       # ids it was already fixed for
    by_design: list[str] = field(default_factory=list)         # ids it is SUPPOSED to refuse

    @property
    def false_positives(self) -> int:
        return len(self.fired_on)


@dataclass(slots=True)
class PrecisionReport:
    """The corpus-wide result."""

    total: int
    clean: int
    by_control: dict[str, ControlPrecision]
    #: Cases a control refuses by design. Counted out of the rate — a deliberate posture refusal is
    #: not a precision failure, and folding it in would make the number unactionable.
    expected_refusals: int = 0
    #: benign id -> the control that blocked it, for the ones that were not clean.
    blocked: dict[str, str] = field(default_factory=dict)

    @property
    def measured(self) -> int:
        """Cases where an allow was actually expected — the real denominator."""
        return self.total - self.expected_refusals

    @property
    def false_positive_rate(self) -> float:
        return 0.0 if not self.measured else round(1.0 - (self.clean / self.measured), 4)

    def controls_with_zero_false_positives(self, candidates: list[str]) -> list[str]:
        """Of `candidates`, the ones that touched nothing legitimate — the promotable set."""
        return [c for c in candidates if c not in self.by_control]

    def as_table(self) -> str:
        """Human-readable, for a commit message or a design note."""
        lines = [f"benign corpus: {self.total} cases "
                 f"({self.expected_refusals} refused by design, {self.measured} measured), "
                 f"{self.clean} clean, {self.measured - self.clean} false positives "
                 f"(rate {self.false_positive_rate:.1%})", ""]
        if not self.by_control:
            lines.append("  no control fired on legitimate traffic")
            return "\n".join(lines)
        width = max(len(c) for c in self.by_control)
        for cid in sorted(self.by_control, key=lambda c: (-len(self.by_control[c].fired_on), c)):
            entry = self.by_control[cid]
            flag = "  REGRESSION" if entry.regressions else ""
            lines.append(f"  {cid:<{width}}  {entry.false_positives:>2} FP  "
                         f"{', '.join(entry.fired_on)}{flag}")
        return "\n".join(lines)


def _eval(module: Path, query: str, case: BenignDefinition) -> str:
    """One `opa eval` against the compiled module, returning the raw scalar."""
    payload = {
        "tool_name": case.tool_name,
        "tool_params": case.tool_params,
        "agent": {"namespace": "default", "agent_class": case.agent_class},
        "call_depth": case.call_depth,
        "derived": {},
    }
    if case.mcp_context:
        payload["mcp"] = case.mcp_context
    out = subprocess.run(  # noqa: S603 - fixed argv, opa resolved from PATH
        ["opa", "eval", "--v0-compatible", "-d", str(module), "-I", "--format", "raw", query],
        input=json.dumps(payload), capture_output=True, text=True, check=False,
    )
    return out.stdout.strip()


def measure(preset: str = "strict", cases: list[BenignDefinition] | None = None) -> PrecisionReport:
    """Run the corpus through the compiled baseline with EVERY control enforcing.

    All-`deny` on purpose: the question is what each control WOULD do if promoted, and a control left
    at `monitor` returns `audit` — which is not a block and would silently score as clean.

    Raises if `opa` is absent rather than returning an empty report: a precision number that quietly
    means "nothing was measured" is the kind of false green this corpus exists to prevent.
    """
    if shutil.which("opa") is None:
        raise RuntimeError("opa is required to measure precision; a skipped run must not read as 0 FPs")

    from norviq.api import baseline  # local import: redteam must not require the API package at import

    corpus = list(cases if cases is not None else BENIGN)
    effects = {cid: "deny" for cid in baseline.control_ids(preset)}

    by_control: dict[str, ControlPrecision] = {}
    blocked: dict[str, str] = {}
    with tempfile.TemporaryDirectory() as td:
        module = Path(td) / f"{preset}_all_deny.rego"
        module.write_text(baseline.compile(preset, effects), encoding="utf-8")

        expected = 0
        for case in corpus:
            if _eval(module, _QUERY_DECISION, case) != "block":
                continue
            rule = _eval(module, _QUERY_RULE, case) or "unattributed"
            entry = by_control.setdefault(rule, ControlPrecision(rule))
            if case.expected_blocked_by == rule:
                # Refused by design AND attributed to the control that is supposed to refuse it. If a
                # DIFFERENT control caught it first the attribution is wrong, and that is a real
                # finding — so it falls through to the false-positive path below.
                entry.by_design.append(case.id)
                expected += 1
                continue
            blocked[case.id] = rule
            entry.fired_on.append(case.id)
            if case.historically_tripped == rule:
                entry.regressions.append(case.id)

    by_control = {cid: e for cid, e in by_control.items() if e.fired_on}
    return PrecisionReport(total=len(corpus), clean=len(corpus) - expected - len(blocked),
                           by_control=by_control, blocked=blocked, expected_refusals=expected)
