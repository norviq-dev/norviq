# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""SECURITY regression for /ws/audit authentication.

The bearer JWT must be accepted from the Sec-WebSocket-Protocol handshake header
(``["nrvq-audit-jwt", "<token>"]``) so the console never has to put it in a ``?token=`` query string —
a query string leaks the credential into access logs / browser history / Referer. The legacy query and
Authorization paths stay as a deprecated fallback for non-browser clients. Invalid / missing tokens are
still rejected before ``accept()``.
"""

from __future__ import annotations

import jwt
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from norviq.api.main import create_app
from norviq.config import settings

_MARKER = "nrvq-audit-jwt"


def _client() -> TestClient:
    return TestClient(create_app())


def _token(namespace: str = "default") -> str:
    return jwt.encode(
        {"sub": "admin", "role": "admin", "namespace": namespace},
        settings.api_secret_key,
        algorithm="HS256",
    )


def test_valid_token_via_subprotocol_connects_without_query_token() -> None:
    """FAIL-ON-BUG: the JWT rides ONLY in the subprotocol (no ?token=). Before the fix the handler read
    the token exclusively from the query string, so this handshake authenticated with nothing and was
    closed 1008. It must now connect."""
    client = _client()
    with client.websocket_connect(
        "/ws/audit?namespace=default", subprotocols=[_MARKER, _token()]
    ):
        pass  # entering the context == handshake accepted (a rejected socket raises below)


def test_missing_token_is_rejected() -> None:
    """No subprotocol token, no ?token=, no Authorization → closed before accept()."""
    client = _client()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/audit?namespace=default"):
            pass


def test_invalid_subprotocol_token_is_rejected() -> None:
    """A garbage token in the subprotocol must fail signature verification and be closed — the
    subprotocol value is authenticated, not merely present."""
    client = _client()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/ws/audit?namespace=default", subprotocols=[_MARKER, "not-a-jwt"]
        ):
            pass


def test_legacy_query_token_still_accepted() -> None:
    """Back-compat: non-browser clients (curl, the integration harness) may still pass ?token=."""
    client = _client()
    with client.websocket_connect(f"/ws/audit?namespace=default&token={_token()}"):
        pass
