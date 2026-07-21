# SPDX-License-Identifier: Apache-2.0
"""Shared fixtures for integration tests."""

from __future__ import annotations

import os
import time

import httpx
import jwt
import pytest


@pytest.fixture(scope="session")
def api_url() -> str:
    """API URL — defaults to local dev, override with NRVQ_API_URL env."""
    return os.environ.get("NRVQ_API_URL", "http://127.0.0.1:8080")


@pytest.fixture(scope="session")
def pg_url() -> str:
    """Postgres URL for integration tests, defaulting to local dev."""
    return os.environ.get(
        "NRVQ_PG_URL",
        "postgresql://norviq:norviq_local_dev@127.0.0.1:5433/norviq?sslmode=disable",
    )


@pytest.fixture(scope="session")
def auth_token() -> str:
    """JWT token — auto-generated from default secret for local dev."""
    env_token = os.environ.get("NRVQ_API_TOKEN")
    if env_token:
        return env_token
    secret = os.environ.get("NRVQ_JWT_SECRET", "change-me-in-production")
    return jwt.encode(
        {"sub": "test", "role": "admin", "exp": int(time.time()) + 3600}, secret, algorithm="HS256"
    )


@pytest.fixture(scope="session")
def auth_headers(auth_token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {auth_token}"}


@pytest.fixture
async def api_client(api_url: str):
    """HTTP client pointed at local API. Skips test if API unreachable."""
    async with httpx.AsyncClient(base_url=api_url, timeout=10.0) as client:
        try:
            health = await client.get("/healthz")
            if health.status_code != 200:
                pytest.skip(f"API not healthy at {api_url}")
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            pytest.skip(f"API unreachable at {api_url}: {exc}")
        yield client
