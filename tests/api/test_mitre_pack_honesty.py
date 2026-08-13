# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-043: the exported evidence pack must not read stronger than the API it came from.

`GET /mitre/coverage` honestly returns `{coverage_pct: 80, basis: "rules_present", proven: 7}`. The
exported pack carried only the 80. That is backwards: the pack is the DURABLE artifact — the one that
ends up in an audit file months later, long after the live view that qualified it has moved on.

Two concrete consequences the qualifiers prevent:
  * a monitor/audit-mode namespace exported "80% coverage" while blocking nothing at all, because
    `proven` (the count with actual block/escalate evidence) was not carried;
  * a pack exported while the audit query was failing attested enforced techniques with `blocked: 0`
    and no marker, which reads as a clean bill of health rather than "I could not see".
"""

from __future__ import annotations

import inspect

from norviq.api.routers import mitre


def _pack_source() -> str:
    """The export route's source; the pack is assembled as a literal inside it."""
    return inspect.getsource(mitre)


def test_the_pack_carries_the_basis_and_proven_qualifiers():
    src = _pack_source()
    assert '"basis": cov["basis"]' in src, "the pack no longer states what its percentage is a basis OF"
    assert '"proven": cov["proven"]' in src, (
        "without `proven`, a monitor-mode namespace exports high coverage while blocking nothing"
    )


def test_the_pack_carries_a_degraded_marker():
    src = _pack_source()
    assert '"degraded": cov["degraded"]' in src


def test_the_coverage_summary_reports_degradation():
    """The flag has to originate where the failure happens, or the pack can only guess."""
    src = inspect.getsource(mitre._activity_by_rule)
    assert "degraded = True" in src, "a failed audit join no longer marks itself"
    assert "return by_rule, excluded, degraded" in src


def test_the_pdf_states_the_qualifiers_too():
    """The PDF is what actually gets read in an audit; a bare percentage is the part that gets quoted."""
    src = inspect.getsource(mitre._evidence_pdf)
    assert "rules present, not efficacy" in src
    assert "DEGRADED" in src


def test_a_degraded_pack_renders_the_warning():
    """Behavioural, not just structural: the line must appear for a degraded pack and not otherwise."""
    base = {
        "framework": "OWASP LLM Top 10 (2025)", "namespace": "ns", "range": "7d",
        "generated_at": "2026-08-13T00:00:00Z", "coverage_pct": 80, "enforced": 8,
        "enforceable_total": 10, "gap": 2, "out_of_scope": 0, "blocked_over_range": 0,
        "synthetic_excluded": 0, "controls": [], "basis": "rules_present", "proven": 0,
    }
    degraded = mitre._evidence_pdf({**base, "degraded": True})
    healthy = mitre._evidence_pdf({**base, "degraded": False})
    assert b"DEGRADED" in degraded
    assert b"DEGRADED" not in healthy
    # ...and the basis line is on BOTH, because it is always true, not only when something broke.
    assert b"not efficacy" in degraded and b"not efficacy" in healthy


def test_the_pdf_reports_proven_against_enforced():
    """The gap between them is the whole difference between 'a rule is loaded' and 'it acted'."""
    pdf = mitre._evidence_pdf({
        "framework": "OWASP LLM Top 10 (2025)", "namespace": "ns", "range": "7d",
        "generated_at": "2026-08-13T00:00:00Z", "coverage_pct": 80, "enforced": 8,
        "enforceable_total": 10, "gap": 2, "out_of_scope": 0, "blocked_over_range": 0,
        "synthetic_excluded": 0, "controls": [], "basis": "rules_present", "proven": 3,
        "degraded": False,
    })
    assert b"3 of 8" in pdf
