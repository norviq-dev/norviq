# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""HTTP client for Norviq CLI."""

from __future__ import annotations
from typing import Any

import click
import httpx
import structlog

log = structlog.get_logger()
REQUEST_TIMEOUT_SECONDS = 10.0


class APIClient:
    """Small HTTP client wrapper."""

    def __init__(self, base_url: str, token: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self._headers = {"Content-Type": "application/json"}
        if token:
            self._headers["Authorization"] = f"Bearer {token}"

    def get(self, path: str) -> dict[str, Any] | list[dict[str, Any]]:
        """Run GET request."""
        return self._request("GET", path, None)

    def post(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        """Run POST request."""
        return self._request("POST", path, data)

    def put(self, path: str, data: dict[str, Any]) -> dict[str, Any]:
        """Run PUT request."""
        return self._request("PUT", path, data)

    def delete(self, path: str) -> dict[str, Any]:
        """Run DELETE request."""
        return self._request("DELETE", path, None)

    def _request(self, method: str, path: str, data: dict[str, Any] | None) -> Any:
        """Run HTTP request and parse payload."""
        try:
            response = httpx.request(
                method,
                f"{self.base_url}{path}",
                headers=self._headers,
                json=data,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            return response.json()
        except httpx.ConnectError:
            log.error("nrvq.cli.connect_error", base_url=self.base_url, code="NRVQ-CLI-8001")
            self._fatal(f"Cannot connect to {self.base_url} - is the API running?")
        except httpx.TimeoutException:
            log.error("nrvq.cli.timeout", method=method, path=path, code="NRVQ-CLI-8004")
            self._fatal("Request timed out. Try again or narrow your query.")
        except httpx.HTTPStatusError as exc:
            self._http_error(exc)
        except ValueError:
            log.error("nrvq.cli.bad_json", method=method, path=path, code="NRVQ-CLI-8004")
            self._fatal("Malformed API response.")
        return {}

    def _http_error(self, exc: httpx.HTTPStatusError) -> None:
        """Print status-aware API errors."""
        status_code = exc.response.status_code
        if status_code == 401:
            log.error("nrvq.cli.auth_failed", code="NRVQ-CLI-8002")
            self._fatal("Authentication failed - check NRVQ_API_TOKEN.")
        if status_code == 404:
            log.error("nrvq.cli.not_found", code="NRVQ-CLI-8004")
            self._fatal("Resource not found.")
        detail = str(exc)
        try:
            detail = str(exc.response.json().get("detail", detail))
        except ValueError:
            pass
        log.error("nrvq.cli.http_error", status=status_code, code="NRVQ-CLI-8004")
        self._fatal(f"API error ({status_code}): {detail}")

    def _fatal(self, message: str) -> None:
        """Exit CLI with user-facing error."""
        click.echo(f"ERROR: {message}", err=True)
        raise SystemExit(1)
