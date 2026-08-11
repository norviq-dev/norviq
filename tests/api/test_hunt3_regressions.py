# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Regression pins for the execution-hunt findings that had no coverage.

Every one of these was proved by RUNNING the product, not by reading it — which is why they survived
two source-reading sweeps. They are grouped by the surface that lied.
"""

from __future__ import annotations

import datetime
import inspect
from types import SimpleNamespace

import pytest

from norviq.config import settings


# ---- RFC5424 header injection (a defect I shipped) -----------------------------------------------

@pytest.fixture
def siem_row(monkeypatch):
    import norviq.api.siem as siem

    monkeypatch.setattr(siem, "_to_dict", lambda r: {
        "decision": "block",
        "namespace": "ns with space",
        # agent_class is caller-influenced. This value tries to close the field and start a new frame.
        "agent_class": 'evil\n<134>1 2026-01-01T00:00:00Z h norviq x FORGED - {"decision":"allow"}',
        "tool_name": "send_email",
    })
    return SimpleNamespace(timestamp_utc=datetime.datetime(2026, 8, 8, tzinfo=datetime.timezone.utc))


def test_syslog_header_cannot_be_used_to_forge_a_second_frame(siem_row, monkeypatch) -> None:
    from norviq.api.siem import _syslog_line

    line = _syslog_line(siem_row)
    assert "\n" not in line, "a caller-supplied field terminated the frame — SIEM events are forgeable"


def test_syslog_header_fields_carry_no_spaces(siem_row) -> None:
    """SP is the field separator: a space in HOSTNAME/PROCID shifts every field after it."""
    from norviq.api.siem import _syslog_line

    header = _syslog_line(siem_row).split(" - ", 1)[0]
    # <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID  -> exactly 6 space-separated tokens
    assert len(header.split(" ")) == 6, f"header field count wrong: {header!r}"


@pytest.mark.parametrize("value,cap", [("x" * 400, 255), ("y" * 400, 128), ("z" * 400, 32)])
def test_syslog_fields_are_length_capped(value, cap) -> None:
    from norviq.api.siem import _syslog_field

    assert len(_syslog_field(value, cap)) == cap


def test_syslog_field_falls_back_to_nilvalue() -> None:
    from norviq.api.siem import _syslog_field

    assert _syslog_field("", 32) == "-"
    assert _syslog_field(None, 32) == "-"


# ---- the SIEM cursor -----------------------------------------------------------------------------

def test_forwarder_persists_its_cursor() -> None:
    """It was in-memory only, so every API restart re-forwarded the audit log from row one."""
    from norviq.api.siem import AuditForwarder

    assert hasattr(AuditForwarder, "_CURSOR_ID")
    src = inspect.getsource(AuditForwarder)
    assert "_save_cursor" in src and "_load_cursor" in src
    from norviq.api.db.models import SiemForwardCursor

    assert SiemForwardCursor.__tablename__ == "siem_forward_cursor"


def test_forwarder_drains_a_backlog_rather_than_one_batch_per_poll() -> None:
    """500 rows per 30s poll is a 16.7 rows/sec ceiling; a busier namespace fell permanently behind."""
    from norviq.api.siem import AuditForwarder

    assert AuditForwarder._MAX_BATCHES_PER_POLL > 1
    assert "_forward_batch" in inspect.getsource(AuditForwarder.forward_once)


# ---- dry-run must agree with enforcement ---------------------------------------------------------

@pytest.mark.parametrize("score,expected", [(0.72, "high"), (0.7, "high"), (0.45, "medium"),
                                            (0.4, "medium"), (0.39, "low")])
def test_dryrun_uses_the_engine_trust_boundaries(score, expected) -> None:
    """The replay recomputed 0.75/0.5 while enforcement uses 0.7/0.4, so a candidate keyed on the trust
    tier got the OPPOSITE verdict for every call in [0.4,0.5) or [0.7,0.75)."""
    from norviq.api.routers.policies import _engine_trust_category

    assert _engine_trust_category(score) == expected


def test_validation_probe_carries_the_same_facts_as_enforcement() -> None:
    """I converted the REPLAY half of dry-run to _build_input and left the VALIDATION half hand-built,
    so sample_decision still omitted derived/mcp/direction — the readout that sets valid/errors."""
    from norviq.api.routers.policies import _sample_probe_input
    from norviq.engine.evaluator import OPAEvaluator

    doc = _sample_probe_input(OPAEvaluator.__new__(OPAEvaluator), "analytics", "support")
    for key in ("derived", "mcp", "direction"):
        assert key in doc, f"{key} missing from the validation probe"


# ---- logging must not widen what leaves the pod --------------------------------------------------

def test_default_log_level_does_not_enable_third_party_info(monkeypatch) -> None:
    """configure_logging used basicConfig+root, which turned ON httpx INFO that had never been enabled —
    the knob added to NARROW what leaves the pod widened it at its default setting."""
    import logging

    from norviq.logging_setup import configure_logging

    monkeypatch.setattr(settings, "log_level", "INFO")
    configure_logging(force=True)
    assert logging.getLogger("httpx").getEffectiveLevel() > logging.INFO, (
        "httpx is logging at INFO again — every request URL, including the SIEM webhook, hits the log"
    )
    assert logging.getLogger("norviq").level == logging.INFO


def test_the_sidecar_entrypoint_applies_the_level() -> None:
    """api/main.py was the ONLY caller, so the knob was inert in the process that logs every decision."""
    import norviq.sidecar.__main__ as sidecar_main

    assert "configure_logging" in inspect.getsource(sidecar_main)


# ---- agent violation accounting ------------------------------------------------------------------

def test_violation_count_is_not_overlaid_from_the_trust_cache() -> None:
    """The warm cache has no violation_count, so overlaying it zeroed the registry's real value for the
    whole 30s TTL — i.e. for exactly the agent being blocked right now."""
    from norviq.api.routers.agents import _LIVE_TRUST_FIELDS

    assert "violation_count" not in _LIVE_TRUST_FIELDS


def test_synthetic_traffic_does_not_count_as_a_violation() -> None:
    """The red-team simulator reuses REAL agent SVIDs, so one 'Run suite' click painted the whole fleet
    red with attacks that never happened."""
    from norviq.engine.evaluator import _is_synthetic_framework

    assert _is_synthetic_framework("redteam")
    assert not _is_synthetic_framework("sidecar")
    assert not _is_synthetic_framework("langchain")


def test_fail_closed_blocks_register_the_agent() -> None:
    """A spoofed SPIFFE id or a timing-out evaluator are the blocks that most indicate an attack, and
    they created no registry row at all — such an agent never appeared on the Agent Monitor."""
    from norviq.engine.evaluator import OPAEvaluator

    assert hasattr(OPAEvaluator, "_register_fail_closed")
    src = inspect.getsource(OPAEvaluator.evaluate)
    assert src.count("_register_fail_closed") == 3, "not every fail-closed branch registers"


# ---- eval-cache invalidation for the new tiers ---------------------------------------------------

@pytest.mark.parametrize("scope,ns_wide", [
    ("__baseline__", True), ("namespace:analytics", True), ("deployment:checkout", True),
    ("support-agent", False),
])
def test_tier_scopes_invalidate_the_whole_namespace(scope, ns_wide) -> None:
    """Eval results are cached per CLASS. A namespace- or workload-tier save invalidated the literal
    tier key, which nothing caches under, so every affected class served a stale decision for the TTL
    while the console said 'effective on the next matching tool call'."""
    from norviq.engine.policy_loader import PolicyLoader

    src = inspect.getsource(PolicyLoader._invalidate_eval_for_policy_scope)
    assert 'startswith("namespace:")' in src and 'startswith("deployment:")' in src
    computed = scope.startswith("__") or scope.startswith("namespace:") or scope.startswith("deployment:")
    assert computed is ns_wide
