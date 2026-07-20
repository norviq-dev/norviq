# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Audit-export hash-chain integrity (tamper-evidence)."""

from norviq.api.routers.audit import _chain_hash


def test_chain_is_deterministic():
    r = {"id": "1", "decision": "block"}
    assert _chain_hash("", r) == _chain_hash("", r)


def test_chain_links_depend_on_prev():
    r = {"id": "1", "decision": "block"}
    h1 = _chain_hash("", r)
    h2 = _chain_hash(h1, r)
    assert h1 != h2  # same record, different prev -> different link


def test_tamper_breaks_chain():
    r1 = {"id": "1", "decision": "block"}
    r2 = {"id": "2", "decision": "allow"}
    tip_good = _chain_hash(_chain_hash("", r1), r2)
    # an auditor altering r1's decision recomputes a different chain tip
    r1_tampered = {"id": "1", "decision": "allow"}
    tip_tampered = _chain_hash(_chain_hash("", r1_tampered), r2)
    assert tip_good != tip_tampered


def test_key_order_does_not_change_hash():
    a = {"id": "1", "decision": "block"}
    b = {"decision": "block", "id": "1"}
    assert _chain_hash("", a) == _chain_hash("", b)
