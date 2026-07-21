# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""`_FORBIDDEN_REGO_TOKENS` banned the bare word `\\btrace\\b`, which also rejected a legitimate rule/
var named `trace` (not just the OPA `trace()` builtin). Narrowed to the builtin CALL form `\\btrace\\s*\\(` —
this proves the narrowing is real (an identifier named `trace` is legal) without weakening any of the
other network/env escapes `_reject_forbidden_rego` guards against."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from norviq.api.routers.policies import _reject_forbidden_rego


def test_bare_trace_identifier_is_no_longer_rejected() -> None:
    """A rule/var legitimately named `trace` (not the builtin call) must be allowed."""
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
    """The narrowing must not weaken any of the other bans (http.send/opa.runtime/net.*/io.*/rego.parse_module)."""
    with pytest.raises(HTTPException) as exc:
        _reject_forbidden_rego(rego)
    assert exc.value.status_code == 422


# --- CRITICAL: cross-tenant OPA policy read via forged package self-reference ----------------------
#
# `opa_client.rewrite_package` replaces a submitted module's declared `package` line with the
# SERVER-COMPUTED `managed_package(f"{ns}:{class}")` at push time — but it does not touch `data.`
# references left in the module BODY. The old own-package allowance trusted the ATTACKER-DECLARED
# `package` line: a tenant could declare `package norviq.managed.<victim-key>` (the victim's own
# server-computed package) as ITS OWN package, pass the self-reference check, and read the victim's
# compiled policy (exfiltrated via the dry-run `reason`). No legitimate policy ever needs to reach into
# OPA's internal per-tenant namespace, so the ban is unconditional and checked before any self-reference
# logic runs.


def test_forged_own_package_declaration_no_longer_bypasses_the_managed_namespace_ban() -> None:
    """The exact exploit shape: declare the VICTIM's server-computed package as your own `package` line,
    then reference `data.norviq.managed.<victim-key>` in the body — this must now 422 even though the
    reference matches the (forged) declared package."""
    victim_key = "victim-ns:victim-class"
    from norviq.engine.opa_client import managed_package, sanitize_key

    victim_package = managed_package(victim_key)  # what the server would have computed for the victim
    rego = (
        f"package {victim_package}\n"
        f'decision = "block" {{ true }}\n'
        f'reason = sprintf("leaked: %v", [data.{victim_package}.decision])\n'
    )
    with pytest.raises(HTTPException) as exc:
        _reject_forbidden_rego(rego)
    assert exc.value.status_code == 422
    assert sanitize_key(victim_key) in victim_package  # sanity: this is really the victim's computed package


@pytest.mark.parametrize(
    "rego",
    [
        'package norviq.x\ndecision = "block" { data.norviq.managed.other_ns_other_class_abc12345.decision == "block" }\n',
        'package norviq.x\ndecision = "block" { data . norviq . managed . x_1234.decision }\n',  # whitespace between dots
        'package norviq.x\nreason = sprintf("%v", [data.norviq.managed.victim.reason])\n',
    ],
)
def test_data_norviq_managed_reference_is_always_rejected(rego: str) -> None:
    """`data.norviq.managed.*` — OPA's internal per-tenant namespace — must be rejected regardless of
    whitespace between the dots or whether it appears in a `reason`/`decision` expression."""
    with pytest.raises(HTTPException) as exc:
        _reject_forbidden_rego(rego)
    assert exc.value.status_code == 422


def test_own_package_self_reference_still_allowed_when_not_the_managed_namespace() -> None:
    """The own-package allowance itself (unrelated to `norviq.managed`) must still work — a policy that
    references its own declared package (not OPA's internal namespace) is legitimate."""
    rego = 'package norviq.sector.finance\nhelper { data.norviq.sector.finance.other_rule }\ndecision = "block" { helper }\n'
    _reject_forbidden_rego(rego)  # must not raise
