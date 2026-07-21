# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Masked tool_params capture."""

from norviq.engine.masking import mask_params


def test_pan_masked_to_last4():
    out = mask_params({"card_number": "4111111111111111"})
    assert out["card_number"] == "****1111"


def test_grouped_pan_masked():
    out = mask_params({"note": "pay to 4111 1111 1111 1111 now"})
    assert "4111" not in out["note"]
    assert "****1111" in out["note"]


def test_ssn_masked():
    out = mask_params({"ssn": "123-45-6789"})
    # ssn is a sensitive key -> fully redacted
    assert out["ssn"] == "****"


def test_ssn_in_freetext_masked():
    out = mask_params({"body": "his ssn is 123-45-6789 ok"})
    assert "123-45-6789" not in out["body"]
    assert "***-**-6789" in out["body"]


def test_sensitive_keys_redacted():
    out = mask_params({"password": "hunter2", "api_key": "sk-abc", "token": "t"})
    assert out["password"] == "****"
    assert out["api_key"] == "****"
    assert out["token"] == "****"


def test_nested_masking():
    out = mask_params({"payload": {"card_number": "4111111111111111", "qty": 3}})
    assert out["payload"]["card_number"] == "****1111"
    assert out["payload"]["qty"] == 3


def test_benign_passthrough():
    out = mask_params({"q": "shipping status", "limit": 10})
    assert out == {"q": "shipping status", "limit": 10}


def test_non_dict_returns_empty():
    assert mask_params(None) == {}
