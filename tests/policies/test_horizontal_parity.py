# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Policy-dedup guard: the canonical PCI/PII rules in `comprehensive.rego` (the default policy) and
`policies/sector/_shared/horizontal.rego` (composed into sector packs) are two copies by necessity —
the engine's OPA cannot import across packages, and codegen was declined. This test makes the two-copy
tradeoff SAFE by failing the build the moment they diverge on any case. Skips only if the `opa` binary
is absent."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess

import pytest

_OPA = shutil.which("opa")
_ROOT = Path(__file__).resolve().parents[2]
_COMPREHENSIVE = _ROOT / "comprehensive.rego"
_SHARED = _ROOT / "policies" / "sector" / "_shared" / "horizontal.rego"

# Inputs that exercise the PCI/PII rules (where both modules MUST agree) + a benign control. Inputs
# that exercise comprehensive-only rules (injection/sql/...) are intentionally excluded — the shared
# module only mirrors PCI + PII.
_CASES = [
    ({"tool_name": "x", "tool_params": {"card_number": "x"}}, "pci_field_name"),
    ({"tool_name": "x", "tool_params": {"q": "4111111111111111"}}, "pci_luhn_value"),
    ({"tool_name": "x", "tool_params": {"q": "4111 1111 1111 1111"}}, "pci_grouped_value"),
    ({"tool_name": "x", "tool_params": {"order_id": "1234567890123456"}}, "non_luhn_16_digits_allow"),
    ({"tool_name": "x", "tool_params": {"ssn": "123-45-6789"}}, "pii_ssn_value"),
    ({"tool_name": "note", "tool_params": {"body": "his ssn is 123-45-6789 ok"}}, "pii_freetext_ssn"),
    ({"tool_name": "x", "tool_params": {"acct": "1990-01-01"}}, "pii_date_shape"),
    ({"tool_name": "search_kb", "tool_params": {"q": "shipping status"}}, "benign_allow"),
    # Nested objects/arrays must be scanned identically by both policies.
    ({"tool_name": "api_post", "tool_params": {"payload": {"ssn": "123-45-6789"}}}, "nested_ssn"),
    ({"tool_name": "api_post", "tool_params": {"payload": {"data": {"v": "4111111111111111"}}}}, "nested_pan_value"),
    ({"tool_name": "api_post", "tool_params": {"body": {"card_number": "x"}}}, "nested_pan_field"),
    ({"tool_name": "api_post", "tool_params": {"items": [{"note": "ok"}, {"ssn": "123-45-6789"}]}}, "nested_array_ssn"),
    ({"tool_name": "api_post", "tool_params": {"payload": {"note": "hello world", "qty": 3}}}, "nested_benign_allow"),
]


def _decision(rego: Path, query: str, inp: dict) -> str:
    proc = subprocess.run(
        ["opa", "eval", "--v0-compatible", "-d", str(rego), "-I", query],
        input=json.dumps(inp), capture_output=True, text=True, check=True,
    )
    return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


@pytest.mark.skipif(_OPA is None, reason="opa binary required for the PCI/PII parity guard")
@pytest.mark.parametrize("inp,label", _CASES, ids=[c[1] for c in _CASES])
def test_shared_horizontal_pci_pii_parity(inp: dict, label: str) -> None:
    comprehensive = _decision(_COMPREHENSIVE, "data.norviq.strict.decision", inp)
    shared = _decision(_SHARED, "data.norviq.sector.shared.decision", inp)
    assert comprehensive == shared, (
        f"PCI/PII DRIFT on '{label}': comprehensive.rego={comprehensive} but "
        f"_shared/horizontal.rego={shared}. Re-sync the shared module with comprehensive.rego."
    )
