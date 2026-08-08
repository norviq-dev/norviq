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


# Transport budgets, separated on purpose.
#
# DEFAULT_TIMEOUT_S stays tight so a genuinely HUNG endpoint fails fast and loudly — that is what this
# number is for, and raising it globally would hide exactly the hangs it exists to catch.
#
# SLOW_ENDPOINT_TIMEOUT_S is for the handful of calls that are legitimately heavy (a whole-cluster
# recompute). Those were failing against a REMOTE cluster on the transport budget, not on behaviour:
# POST /attack-paths/compute across every namespace measured 9.86s against the 10.0s default on a
# cluster holding 676 paths in `default` alone. A test that fails because a correct answer took 9.9
# seconds is asserting performance while claiming to assert correctness, and it will keep flaking on
# any cluster bigger or further away than a laptop's.
#
# Both are env-tunable so CI can tighten or a slow link can loosen without editing tests.
DEFAULT_TIMEOUT_S = float(os.environ.get("NRVQ_TEST_TIMEOUT_S", "10"))
SLOW_ENDPOINT_TIMEOUT_S = float(os.environ.get("NRVQ_TEST_SLOW_TIMEOUT_S", "120"))


@pytest.fixture
async def api_client(api_url: str):
    """HTTP client pointed at local API. Skips test if API unreachable."""
    async with httpx.AsyncClient(base_url=api_url, timeout=DEFAULT_TIMEOUT_S) as client:
        try:
            health = await client.get("/healthz")
            if health.status_code != 200:
                pytest.skip(f"API not healthy at {api_url}")
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            pytest.skip(f"API unreachable at {api_url}: {exc}")
        yield client


# Namespace prefixes this suite invents for throwaway policies. Every one is unambiguously
# test-owned: `integration-<uuid4hex>`, `emittest-<8hex>`, `replica-<uuid4hex>`.
_THROWAWAY_PREFIXES = ("integration-", "emittest-", "replica-")


@pytest.fixture(scope="session", autouse=True)
def _sweep_throwaway_policies(api_url: str, auth_headers: dict[str, str]):
    """Delete the policies this suite creates, at session end.

    WHY THIS EXISTS. `test_policy_lifecycle.py` POSTs a policy into `integration-<uuid>` and never
    removed it, so every run left rows behind permanently. Ten of them accumulated on the local
    cluster across five runs — and because a namespace EXISTS as far as the console is concerned once
    a policy names it, the namespace selector grew ten phantom entries.

    That is not a tidiness problem. It broke the BROWSER suite, which has no seeding step of its own
    and asserts against whatever the cluster holds: policy counts, catalog listings, pack governance
    rollups and namespace-scoped graph views all read a table this suite had quietly filled with
    fixtures. Fifty-nine pre-existing specs failed, in files that had nothing to do with the change
    under test, and the failure signature pointed at the console rather than at here.

    Swept by PREFIX rather than by tracking each creation: the leak spans several modules, some of
    which build the name inline, and a sweep cannot miss one that a registration list would.

    Best-effort by design — a failure to clean up must never fail the suite that just passed, and the
    API being gone at teardown is normal when the tests skipped.
    """
    yield

    try:
        with httpx.Client(base_url=api_url, timeout=10.0) as client:
            listing = client.get("/api/v1/policies?limit=500", headers=auth_headers)
            if listing.status_code != 200:
                return
            body = listing.json()
            rows = body if isinstance(body, list) else (body.get("policies") or body.get("items") or [])
            removed = 0
            for row in rows:
                ns = str(row.get("namespace", ""))
                if not ns.startswith(_THROWAWAY_PREFIXES):
                    continue
                cls = str(row.get("agent_class", ""))
                resp = client.delete(f"/api/v1/policies/{ns}/{cls}", headers=auth_headers)
                removed += 1 if resp.status_code < 300 else 0
            if removed:
                print(f"\n[cleanup] removed {removed} throwaway integration policies")
    except Exception as exc:  # noqa: BLE001 - teardown must never fail a passing run
        print(f"\n[cleanup] could not sweep throwaway policies: {exc}")
