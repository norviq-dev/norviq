# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""F-24: every block carries a correct named rule_id (never '' or default_allow). F-23: read-like tools are
exempt from the per-identity rate limiter."""

from norviq.config import settings
from norviq.engine.evaluator import OPAEvaluator
from norviq.sdk.core.decisions import PolicyDecision


def test_block_with_empty_rule_id_is_clamped():
    d = PolicyDecision(decision="block", rule_id="", reason="")
    out = OPAEvaluator._ensure_block_attribution(d, "evt")
    assert out.rule_id == "unattributed_block"
    assert out.reason


def test_block_with_default_allow_rule_id_is_clamped():
    d = PolicyDecision(decision="block", rule_id="default_allow", reason="x")
    out = OPAEvaluator._ensure_block_attribution(d, "evt")
    assert out.rule_id == "unattributed_block"


def test_named_block_is_untouched():
    d = PolicyDecision(decision="block", rule_id="sod_violation", reason="r")
    assert OPAEvaluator._ensure_block_attribution(d, "evt").rule_id == "sod_violation"


def test_allow_with_default_allow_is_untouched():
    d = PolicyDecision(decision="allow", rule_id="default_allow", reason="Allowed")
    out = OPAEvaluator._ensure_block_attribution(d, "evt")
    assert out.rule_id == "default_allow" and out.decision == "allow"


def test_invariant_no_block_keeps_bad_rule_id():
    # the union of every "bad" pairing must clamp; the guard is the audit-row invariant
    for rid in ("", "default_allow"):
        out = OPAEvaluator._ensure_block_attribution(PolicyDecision(decision="block", rule_id=rid), "e")
        assert out.rule_id not in ("", "default_allow")


# --- F-23 read-exempt ---
def test_read_tools_are_rate_limit_exempt():
    assert settings.evaluator_rate_limit_read_exempt is True
    for t in ("get_account", "read_record", "list_tickets", "query_db", "fetch_x", "valve_status", "sensor_read"):
        assert OPAEvaluator._is_rate_limit_exempt(t) is True


def test_write_tools_are_not_exempt():
    for t in ("delete_record", "wire_transfer", "valve_close", "approve_transfer", "export_statement"):
        assert OPAEvaluator._is_rate_limit_exempt(t) is False
