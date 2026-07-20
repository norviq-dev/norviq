# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Raw tool_params (PII/PAN/PHI) must never reach a logger. The eval input is masked before logging and
the input log is gated behind debug_opa_logging (default off)."""

from norviq.config import settings
from norviq.engine.evaluator import OPAEvaluator


def test_redacted_input_masks_pan_and_ssn():
    doc = {"tool_name": "export_statement",
           "tool_params": {"ssn": "999-88-7777", "pan": "4111111111111111", "note": "ok"},
           "tool_params_normalized": {"ssn": "999-88-7777"}}
    red = OPAEvaluator._redacted_input(doc)
    blob = str(red)
    # raw values appear NOWHERE
    assert "999-88-7777" not in blob
    assert "4111111111111111" not in blob
    # masked forms only
    assert red["tool_params"]["ssn"] == "****"          # 'ssn' is a sensitive key -> fully redacted
    assert red["tool_params"]["pan"] == "****1111"
    assert red["tool_params"]["note"] == "ok"           # benign value preserved
    assert red["tool_params_normalized"]["ssn"] == "****"
    # non-param fields untouched
    assert red["tool_name"] == "export_statement"


def test_redacted_input_handles_missing_params():
    assert OPAEvaluator._redacted_input({"tool_name": "x"}) == {"tool_name": "x"}


def test_pan_in_freetext_param_is_masked():
    red = OPAEvaluator._redacted_input({"tool_params": {"memo": "charge card 4111111111111111 now"}})
    assert "4111111111111111" not in str(red)
    assert "****1111" in red["tool_params"]["memo"]


def test_input_logging_is_gated_off_by_default():
    # the opa_input INFO log only fires when debug_opa_logging is enabled (default False)
    assert settings.debug_opa_logging is False
