# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""FIX-6: `_FORBIDDEN_REGO_TOKENS` banned the bare word `\\btrace\\b`, which also rejected a legitimate rule/
var named `trace` (not just the OPA `trace()` builtin). Narrowed to the builtin CALL form `\\btrace\\s*\\(` —
this proves the narrowing is real (an identifier named `trace` is now legal) without weakening any of the
other network/env escapes `_reject_forbidden_rego` guards against (S1, from c18dd8a)."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from norviq.api.routers.policies import _reject_forbidden_rego


def test_bare_trace_identifier_is_no_longer_rejected() -> None:
    """A rule/var legitimately named `trace` (not the builtin call) must be allowed post-FIX-6."""
    rego = 'package norviq.x\ntrace := "audit-note"\ndecision = "block" { trace == "audit-note" }\n'
    _reject_forbidden_rego(rego)  # must not raise


def test_trace_builtin_call_is_still_rejected() -> None:
    """The actual OPA `trace()` builtin call must still be rejected."""
    rego = 'package norviq.x\ndecision = "block" { trace("debug") }\n'
    with pytest.raises(HTTPException) as exc:
        _reject_forbidden_rego(rego)
    assert exc.value.status_code == 422


@pytest.mark.parametrize(
    "rego",
    [
        'package norviq.x\ndecision = "block" { http.send({"url": "http://evil"}) }\n',
        'package norviq.x\ndecision = "block" { opa.runtime().env.SECRET }\n',
        'package norviq.x\ndecision = "block" { net.lookup_ip_addr("evil.example") }\n',
        'package norviq.x\ndecision = "block" { io.jwt.decode("x") }\n',
        'package norviq.x\ndecision = "block" { rego.parse_module("x", "y") }\n',
    ],
)
def test_other_forbidden_builtins_still_rejected(rego: str) -> None:
    """FIX-6 must not weaken any of the other S1 bans (http.send/opa.runtime/net.*/io.*/rego.parse_module)."""
    with pytest.raises(HTTPException) as exc:
        _reject_forbidden_rego(rego)
    assert exc.value.status_code == 422
