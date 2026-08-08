# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Knobs that were accepted, plumbed, documented — and read by nothing.

Each of these shipped as a setting an operator could set, land in the ConfigMap, and see reported as
working. None of them changed behaviour. They are grouped here because the failure is one shape: the
product answered "yes, applied" to a choice it never made.
"""

from __future__ import annotations

import datetime
import logging
from types import SimpleNamespace

import pytest

from norviq.config import settings


# ---- siem.format --------------------------------------------------------------------------------

@pytest.fixture
def siem_row(monkeypatch):
    import norviq.api.siem as siem

    monkeypatch.setattr(siem, "_to_dict", lambda r: {
        "decision": "block", "namespace": "analytics", "agent_class": "support",
        "tool_name": "send_email",
    })
    return SimpleNamespace(timestamp_utc=datetime.datetime(2026, 8, 7, 12, 0, tzinfo=datetime.timezone.utc))


def test_syslog_format_is_actually_emitted(siem_row, monkeypatch) -> None:
    """`siem.format: syslog` used to POST NDJSON labelled application/x-ndjson and log success, so a
    syslog collector silently dropped or mis-parsed every audit record."""
    from norviq.api.siem import _encode_batch

    monkeypatch.setattr(settings, "siem_format", "syslog")
    body, content_type = _encode_batch([siem_row])
    assert content_type.startswith("text/plain")
    assert body.startswith("<"), "not an RFC5424 frame"


def test_syslog_severity_distinguishes_a_block(siem_row, monkeypatch) -> None:
    """A block must not arrive at the same severity as an allow — it is the row an on-call rule fires
    on. local0(16)*8 + warning(4) = 132."""
    from norviq.api.siem import _encode_batch

    monkeypatch.setattr(settings, "siem_format", "syslog")
    assert _encode_batch([siem_row])[0].startswith("<132>1 ")


def test_ndjson_remains_the_default(siem_row, monkeypatch) -> None:
    from norviq.api.siem import _encode_batch

    monkeypatch.setattr(settings, "siem_format", "ndjson")
    body, content_type = _encode_batch([siem_row])
    assert content_type == "application/x-ndjson"
    assert body.rstrip().startswith("{")


def test_unknown_format_falls_back_to_ndjson_rather_than_failing(siem_row, monkeypatch) -> None:
    from norviq.api.siem import _encode_batch

    monkeypatch.setattr(settings, "siem_format", "protobuf-over-carrier-pigeon")
    assert _encode_batch([siem_row])[1] == "application/x-ndjson"


# ---- config.logLevel ----------------------------------------------------------------------------

@pytest.mark.parametrize("level,expected", [("WARNING", logging.WARNING), ("ERROR", logging.ERROR),
                                            ("DEBUG", logging.DEBUG)])
def test_log_level_is_applied(monkeypatch, level, expected) -> None:
    """NRVQ_LOG_LEVEL was accepted, rendered into the ConfigMap and documented while nothing outside
    the MCP stdio proxy configured structlog — so setting WARNING to keep decision and identity detail
    out of a shared sink changed nothing."""
    from norviq.logging_setup import configure_logging

    monkeypatch.setattr(settings, "log_level", level)
    assert configure_logging(force=True) == level
    assert logging.getLogger().level == expected


def test_a_nonsense_level_falls_back_to_info_not_debug(monkeypatch) -> None:
    """Failing open to DEBUG would be the dangerous direction — more detail leaving the pod, not less."""
    from norviq.logging_setup import configure_logging

    monkeypatch.setattr(settings, "log_level", "VERBOSE-ISH")
    assert configure_logging(force=True) == "INFO"
    assert logging.getLogger().level == logging.INFO


# ---- the Overview would-block prefix ------------------------------------------------------------

def test_coverage_counts_every_would_block_prefix() -> None:
    """coverage.py hardcoded `monitor_would_block:` and so could never see the per-policy audit path,
    leaving a trialled policy's Overview bar grey no matter how much it would have stopped."""
    import inspect

    from norviq.api.routers import coverage
    from norviq.engine.evaluator import WOULD_BLOCK_RULE_PREFIXES

    src = inspect.getsource(coverage)
    assert "WOULD_BLOCK_RULE_PREFIXES" in src
    assert '"monitor_would_block:")' not in src, "the forked literal is back"
    assert "policy_audit_would_block:x".startswith(WOULD_BLOCK_RULE_PREFIXES)


# ---- attack-path node labels --------------------------------------------------------------------

def test_attack_graph_reads_the_key_snapshots_actually_have() -> None:
    """`_load_nodes` read `name`; snapshot nodes carry `label` (GraphNode.label), so every stored path
    came out with mitre_techniques: [] — which reads as "maps to no ATLAS technique"."""
    import inspect

    from norviq.engine.attack_graph import AttackGraphEngine

    src = inspect.getsource(AttackGraphEngine._load_nodes)
    assert 'node.get("label")' in src


# ---- agent violation_count ----------------------------------------------------------------------

def test_violation_count_accumulates_rather_than_being_set() -> None:
    """The column was pinned at 0 two ways at once: no caller passed a value, and the ON CONFLICT
    clause SET it rather than adding — so even a caller that did pass one could not accumulate. The
    Agent Monitor renders it with amber >3 / red >8 thresholds that were unreachable."""
    import inspect

    from norviq.api.db import session as db_session

    src = inspect.getsource(db_session.upsert_agent_registry)
    assert "violation: bool" in src, "the parameter is a count again, which nothing increments"
    assert "AgentRegistryEntry.violation_count +" in src, (
        "the conflict clause SETS violation_count again — an overwritten counter is a constant"
    )


def test_evaluator_reports_a_violation_for_blocked_and_escalated_calls() -> None:
    import inspect

    from norviq.engine.evaluator import OPAEvaluator

    src = inspect.getsource(OPAEvaluator._safe_register_agent)
    assert 'in ("block", "escalate")' in src


# ---- source-capability panel in Monitor mode ----------------------------------------------------

def test_would_block_counts_as_guarded() -> None:
    """In a Monitor-mode namespace a policy's blocks are softened to `audit` with a would-block marker,
    so `block` stays 0 for a rule catching traffic daily. Reading only block+escalate made `defended`
    unreachable there — the panel told operators to revoke a grant their policy was actively stopping,
    or to author a rule that already existed."""
    import inspect

    from norviq.api.routers import graphs

    src = inspect.getsource(graphs)
    assert 'hist.get("would_block", 0)' in src, (
        "would_block is fetched but not counted as guarded again"
    )
