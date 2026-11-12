# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The SQL twins of the synthetic-traffic classifier, run against real rows.

`audit_row_is_non_real` is the real-traffic filter behind the Overview, /tools, MITRE, intent proposals,
dry-run replay and the Audit Log's "Real traffic only". Its only test read the SQL text. These tests
run it on SQLite (SQLAlchemy registers Python's `re` for REGEXP there) over a corpus of framework,
class and SPIFFE-id values, including case, surrounding whitespace and NULL, and require the SQL to give
the same answer as the Python classifier for every row.
"""

from __future__ import annotations

import itertools

import pytest
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, insert, select

from norviq.api import synthetic

_FRAMEWORKS = [
    None, "", "sidecar", "mcp", "langchain", "redteamx", "red team",
    "redteam", "RedTeam", " redteam", "redteam ", "\tredteam\n", "POLICY-TESTER", " probe\t", "policy-tester",
    "red-team", "   ",
]
_CLASSES = [
    None, "", "customer-support", "billing-assistant", "probe", "e2e", "scorers", "policy-testerx",
    "policy-tester", "Policy-Tester", " scorer ", "\tscorer", "SCORER\n", "e2e-intent-1", "E2E-bot",
    "  probe-1", "wave12e2e-77", "WAVE4E2E", "wave e2e", "evtrace-1783", "effecttest", "smoke-x", "canary-1",
    "allowlist-probe-2", "policy-tester-k3x9",
]
_SVIDS = [
    None, "",
    "spiffe://norviq/ns/payments/sa/default",
    "spiffe://norviq/ns/payments/sa/policy-tester-k3x9a2",
    "spiffe://norviq/ns/payments/sa/Policy-Tester-K3X",
    "spiffe://norviq/ns/payments/sa/ scorer ",
    "spiffe://norviq/ns/payments/sa/scorer",
    "spiffe://norviq/ns/payments/sa/scorer/extra",
    "spiffe://norviq/ns/payments/sa/scorers",
    "spiffe://norviq/ns/payments/sa/\twave3e2e-x",
    "spiffe://norviq/ns/payments/SA/policy-tester-k3x",  # the marker is case-sensitive in Python
    "spiffe://norviq/ns/payments/sa",                     # no segment after it
    "spiffe://norviq/ns/payments/sa//probe-1",            # an empty segment after it
    "spiffe://norviq/ns/sa/sa/probe-1",                   # namespace "sa": the FIRST sa segment wins
    "spiffe://norviq/ns/payments/xsa/probe-1",
    "spiffe://norviq/ns/payments/sax/probe-1",
    "sa/smoke-1",                                         # the marker as the first segment
    "spiffe://norviq/ns/probe-1/sa/default",
    "spiffe://norviq/ns/payments/sa/canary-",
]


@pytest.fixture(scope="module")
def db():
    engine = create_engine("sqlite://")
    meta = MetaData()
    # The columns the twins read, under audit_log's and agent_registry's names.
    rows = Table(
        "rows", meta,
        Column("id", Integer, primary_key=True),
        Column("framework", String), Column("agent_class", String),
        Column("agent_id", String), Column("spiffe_id", String),
    )
    meta.create_all(engine)
    corpus = list(itertools.product(_FRAMEWORKS, _CLASSES, _SVIDS))
    with engine.begin() as conn:
        conn.execute(insert(rows), [
            {"id": i, "framework": f, "agent_class": c, "agent_id": s, "spiffe_id": s}
            for i, (f, c, s) in enumerate(corpus)
        ])
    yield engine, rows, corpus
    engine.dispose()


def _flagged(db, predicate) -> set[int]:
    engine, rows, _ = db
    with engine.connect() as conn:
        return {r.id for r in conn.execute(select(rows.c.id).where(predicate(rows.c)))}


def _real(db, predicate) -> set[int]:
    engine, rows, _ = db
    with engine.connect() as conn:
        return {r.id for r in conn.execute(select(rows.c.id).where(~predicate(rows.c)))}


def _disagreements(db, predicate, python) -> list[tuple]:
    _, _, corpus = db
    sql = _flagged(db, predicate)
    return [row for i, row in enumerate(corpus) if (i in sql) != bool(python(*row))]


def test_the_corpus_has_both_answers(db) -> None:
    """Control: a corpus where the SQL and Python agree because both say "real" (or both "synthetic")
    for everything would prove nothing."""
    _, _, corpus = db
    flagged = _flagged(db, synthetic.audit_row_is_non_real)
    assert 0 < len(flagged) < len(corpus)


def test_the_real_traffic_filter_agrees_with_python_on_every_row(db) -> None:
    bad = _disagreements(db, synthetic.audit_row_is_non_real, synthetic.is_non_real_traffic)
    assert not bad, f"{len(bad)} rows where SQL and Python disagree, e.g. {bad[:5]}"


def test_the_fabricated_call_filter_agrees_with_python_on_every_row(db) -> None:
    bad = _disagreements(
        db, synthetic.audit_row_is_fabricated, lambda f, _c, _s: synthetic.is_synthetic_framework(f)
    )
    assert not bad, f"{len(bad)} rows where SQL and Python disagree, e.g. {bad[:5]}"


def test_the_registry_filter_agrees_with_python_on_every_row(db) -> None:
    registry = getattr(synthetic, "registry_row_is_synthetic", None)
    assert registry is not None, "no SQL twin of is_synthetic_identity for agent_registry rows"
    bad = _disagreements(db, registry, lambda _f, c, s: synthetic.is_synthetic_identity(c, s))
    assert not bad, f"{len(bad)} rows where SQL and Python disagree, e.g. {bad[:5]}"


def test_null_columns_are_real_traffic_not_dropped(db) -> None:
    """NOT(predicate) must be TRUE for an all-NULL row. A NULL inside it makes the row vanish from BOTH
    the real-traffic view and its complement."""
    _, _, corpus = db
    all_null = corpus.index((None, None, None))
    assert all_null in _real(db, synthetic.audit_row_is_non_real)
    assert all_null not in _flagged(db, synthetic.audit_row_is_non_real)


@pytest.mark.parametrize(
    ("framework", "agent_class", "svid"),
    [
        ("\tredteam\n", "customer-support", "spiffe://norviq/ns/payments/sa/default"),
        ("RedTeam", None, None),
        (None, "\tSCORER\n", None),
        (None, None, "spiffe://norviq/ns/payments/sa/ Policy-Tester-K3X"),
    ],
)
def test_case_and_whitespace_variants_are_synthetic_in_sql(db, framework, agent_class, svid) -> None:
    engine, rows, _ = db
    with engine.begin() as conn:
        rid = 10_000_000
        conn.execute(insert(rows), [{"id": rid, "framework": framework, "agent_class": agent_class,
                                     "agent_id": svid, "spiffe_id": svid}])
        try:
            hit = conn.execute(
                select(rows.c.id).where(rows.c.id == rid).where(synthetic.audit_row_is_non_real(rows.c))
            ).first()
        finally:
            conn.execute(rows.delete().where(rows.c.id == rid))
    assert hit is not None
    assert synthetic.is_non_real_traffic(framework, agent_class, svid)
