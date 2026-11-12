# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""One definition of synthetic traffic, and every producer of it covered by that definition.

The engine treated {redteam, red-team, policy-tester, probe} as fabricated; the API's real-traffic
filter knew only "redteam"; the Attack Graph's Simulate tag "attack-graph" was in neither. So a
Simulate or a probe under a real agent class counted as real traffic on the Overview, in intent
proposals and in dry-run replay. These tests pin the one set in norviq/api/synthetic.py, check that
each place that stamps a synthetic tag uses a tag from it, and that the SQL twin names every tag.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from sqlalchemy.dialects import postgresql

from norviq.api import synthetic
from norviq.api.db.models import AuditLogEntry
from norviq.api.synthetic import audit_row_is_non_real, is_synthetic_identity

_ROOT = Path(__file__).resolve().parents[2]

# Read through the module rather than imported by name, so each test fails on its own against a tree
# that predates the shared set, instead of the whole file failing to collect.
_TAGS = ("attack-graph", "policy-tester", "probe", "red-team", "redteam")


def test_the_shared_set_is_exactly_these_tags() -> None:
    assert set(synthetic.SYNTHETIC_FRAMEWORKS) == set(_TAGS)


@pytest.mark.parametrize("tag", [*_TAGS, " RedTeam "])
def test_every_fabricated_tag_is_synthetic(tag: str) -> None:
    assert synthetic.is_synthetic_framework(tag)
    # A real class does not rescue it: the call was still fabricated.
    assert synthetic.is_non_real_traffic(tag, "customer-support", "spiffe://norviq/ns/p/sa/default")


@pytest.mark.parametrize("tag", ["", None, "sidecar", "sidecar-http", "mcp", "langchain", "crewai", "redteamx"])
def test_real_sources_are_not_synthetic(tag: str | None) -> None:
    assert not synthetic.is_synthetic_framework(tag)
    assert not synthetic.is_non_real_traffic(tag, "customer-support", "spiffe://norviq/ns/p/sa/default")


def test_a_policy_tester_session_is_synthetic_by_its_svid() -> None:
    """The Policy Tester runs under the class being tested and marks itself only in `sa/policy-tester-<rand>`.
    The SVID was read only when the class was empty, so these sessions counted as a real agent's traffic."""
    svid = "spiffe://norviq/ns/payments/sa/policy-tester-k3x9a2"
    assert is_synthetic_identity("invoice-agent", svid)
    assert not is_synthetic_identity("invoice-agent", "spiffe://norviq/ns/payments/sa/default")


def test_the_engine_uses_the_shared_set() -> None:
    from norviq.engine.evaluator import _is_synthetic_framework

    for tag in _TAGS:
        assert _is_synthetic_framework(tag), tag
    assert not _is_synthetic_framework("sidecar")


def test_every_producer_stamps_a_tag_the_set_knows() -> None:
    """Source-level check over the places that fabricate calls. A new producer with a new tag must add
    it to SYNTHETIC_FRAMEWORKS, or its traffic counts as real."""
    from norviq.redteam.attacks import ATTACKS, attack_request

    known = set(getattr(synthetic, "SYNTHETIC_FRAMEWORKS", ()))
    assert attack_request(ATTACKS[0], "my-agent", "my-team")["framework"] in known

    engine_src = (_ROOT / "norviq/engine/attack_graph.py").read_text()
    engine_tags = re.findall(r'framework="([^"]+)"', engine_src)
    assert engine_tags and set(engine_tags) <= known, engine_tags

    simulate_src = (_ROOT / "ui/src/pages/AttackGraph.tsx").read_text()
    simulate_tags = re.findall(r'framework:\s*"([^"]+)"', simulate_src)
    assert simulate_tags and set(simulate_tags) <= known, simulate_tags


def test_the_console_copy_of_the_set_matches() -> None:
    """ui/src/lib/syntheticTraffic.ts carries a copy, for the self-cancelling-filter warning."""
    path = _ROOT / "ui/src/lib/syntheticTraffic.ts"
    assert path.exists(), "the console has no copy of the synthetic framework set"
    m = re.search(r"SYNTHETIC_FRAMEWORKS[^=]*=\s*(\[[^\]]*\])", path.read_text())
    assert m, "SYNTHETIC_FRAMEWORKS not found in syntheticTraffic.ts"
    assert set(json.loads(m.group(1))) == set(_TAGS)


def _pg(expr) -> str:
    return str(expr.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))


def test_the_sql_twin_names_every_tag_and_reads_the_svid() -> None:
    """The Postgres form of the twin: one regex match per column, with the shared patterns.

    Rewritten when the twin moved from `trim(lower(...)) IN (...)` / LIKE / two-argument substring() to
    regex matches. The old assertions looked for each tag as a quoted literal, which the new form does
    not contain. What they meant is checked here instead: the twin reads all three columns with the
    `~` operator, and its framework pattern matches every tag. Its behaviour on real rows is in
    test_synthetic_sql_twin_behaviour.py."""
    non_real = _pg(audit_row_is_non_real(AuditLogEntry)).replace("\\\\", "\\")
    for column in ("audit_log.framework", "audit_log.agent_class", "audit_log.agent_id"):
        assert f"coalesce({column}, '') ~ '" in non_real, column
    for pattern in (synthetic._FRAMEWORK_PATTERN, synthetic._CLASS_PATTERN, synthetic._SVID_PATTERN):
        assert pattern in non_real
    for tag in _TAGS:
        assert re.search(synthetic._FRAMEWORK_PATTERN, tag), tag
