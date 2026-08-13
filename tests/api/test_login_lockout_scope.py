# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-044: the login throttle must not be a remote lockout of any account you can name.

Measured live: five bad `admin` logins locked out the REAL admin for ~5 minutes — three
correct-password logins returned 429 before one succeeded. An availability control an
unauthenticated attacker can aim at the operator is a denial-of-service primitive, and the operator
it locks out is exactly the person who would respond to the attack.

The credit in the finding is preserved and asserted below: the throttle IS enforced and is NOT
X-Forwarded-For-spoofable. Fixing the scope must not cost either property.
"""

from __future__ import annotations

import inspect

from norviq.api.routers import auth_login


def _login_src() -> str:
    return inspect.getsource(auth_login)


def test_the_lockout_key_includes_the_source_ip():
    src = _login_src()
    assert 'per_ip_key = f"{username}|{ip}"' in src, (
        "the throttle is keyed on the username alone again — an attacker can lock out any account "
        "whose name they can guess"
    )
    assert "is_locked_out(cache, per_ip_key" in src


def test_the_source_ip_comes_from_the_hardened_resolver():
    """Reading X-Forwarded-For directly would be worse than the bug being fixed: the header is
    caller-writable, so an attacker rotates it for a fresh bucket per request and the ceiling is
    never reached. `_client_ip` believes XFF only behind a trusted proxy."""
    src = _login_src()
    assert "from norviq.api.rate_limit import _client_ip" in src
    assert "_client_ip(request.scope)" in src
    # Checks for header ACCESS, not the string: the code comments legitimately name the header when
    # explaining why they do not read it, and an assertion that cannot tell those apart fails on its
    # own documentation.
    for access in ('headers.get("x-forwarded-for"', "headers.get('x-forwarded-for'",
                   'headers["x-forwarded-for"', "headers['x-forwarded-for'"):
        assert access not in src.lower(), (
            f"login reads the forwarded header directly ({access}) instead of the hardened resolver"
        )


def test_a_per_username_backstop_still_exists():
    """Removing the username counter entirely would leave a distributed attempt unbounded. It is kept
    at a much higher ceiling — the attacker pays 10x to deny one operator instead of 5 requests."""
    src = _login_src()
    assert "_USERNAME_LOCK_MULTIPLIER" in src
    assert auth_login._USERNAME_LOCK_MULTIPLIER >= 5, (
        "a tight username ceiling reintroduces the remote-lockout DoS it sits beside"
    )


def test_both_counters_advance_and_both_clear():
    """A failure that advanced only one counter, or a success that cleared only one, would leave the
    other to lock the user out later for attempts that are no longer relevant."""
    src = _login_src()
    assert "register_failure(cache, per_ip_key" in src
    assert "register_failure(cache, username" in src
    assert "clear_failures(cache, per_ip_key)" in src
    assert "clear_failures(cache, username)" in src
