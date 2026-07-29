# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The readiness gate and the connection URL must name the SAME datastore.

The chart renders three datastore shapes, and each names its Postgres and Redis differently:

    bundled (default)  norviq-postgresql / norviq-redis        the in-chart StatefulSets
    HA operators       postgresql.ha.serviceName / redis.ha.serviceName
    bring-your-own     postgresql.host / redis.host

`secret.yaml` resolved this correctly for NRVQ_PG_URL / NRVQ_REDIS_URL. The init containers did not
— they hard-coded the BUNDLED names. So in the two configurations the docs call production:

    HA        the bundled Services exist with NO endpoints (their StatefulSets are disabled)
    external  the bundled Services are not rendered at all

…`until nc -z norviq-postgresql 5432` never returns, and every api/engine pod sits in Init forever
while both datastores are perfectly healthy. Only the default worked. Nothing caught it because
`helm template` renders happily either way — the names are only wrong relative to EACH OTHER, which
is exactly what this test compares.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import subprocess

import pytest

CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"
BASE = ["--set-json", 'policyQuotaNamespaces=["default"]']

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not on PATH")

SHAPES = {
    "bundled": [],
    "ha": [
        "--set", "postgresql.ha.enabled=true", "--set", "postgresql.password=Str0ng!Pg",
        "--set", "redis.ha.enabled=true", "--set", "redis.password=Str0ng!Redis",
    ],
    "external": [
        "--set", "postgresql.enabled=false", "--set", "postgresql.host=mydb.example.com",
        "--set", "redis.enabled=false", "--set", "redis.host=mycache.example.com",
    ],
}


def _render(extra: list[str]) -> str:
    res = subprocess.run(["helm", "template", "norviq", str(CHART), *BASE, *extra],
                         capture_output=True, text=True)
    assert res.returncode == 0, res.stderr[-600:]
    return res.stdout


def _gate_hosts(rendered: str) -> set[str]:
    """Hosts the init containers block on — excluding norviq-api, which is an in-chart Service."""
    return {
        h for h, _p in re.findall(r"until nc -z ([A-Za-z0-9._-]+) (\d+)", rendered)
        if h != "norviq-api"
    }


def _url_hosts(rendered: str) -> set[str]:
    pg = re.search(r'NRVQ_PG_URL:\s*"postgresql://[^@]*@([^:]+):', rendered)
    rd = re.search(r'NRVQ_REDIS_URL:\s*"redis://[^@]*@([^:]+):', rendered)
    assert pg and rd, "could not find NRVQ_PG_URL / NRVQ_REDIS_URL in the render"
    return {pg.group(1), rd.group(1)}


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_readiness_gate_matches_the_connection_url(shape: str) -> None:
    """Whatever the app dials, the init container must wait for THAT — not something else."""
    rendered = _render(SHAPES[shape])
    gates, urls = _gate_hosts(rendered), _url_hosts(rendered)
    assert gates == urls, (
        f"{shape}: init containers wait on {sorted(gates)} but the app connects to {sorted(urls)} — "
        "the control plane will block in Init forever"
    )


def test_ha_does_not_gate_on_the_disabled_bundled_services() -> None:
    """The specific regression, named: under HA the bundled Services have no endpoints."""
    gates = _gate_hosts(_render(SHAPES["ha"]))
    assert "norviq-postgresql" not in gates and "norviq-redis" not in gates, (
        f"HA still gates on a bundled Service with no endpoints: {sorted(gates)}"
    )


def test_cnpg_uses_a_cloudnative_pg_operand_image() -> None:
    """CNPG hardcodes postgresUID/GID 26 and only supports images built to its own contract.

    Pointed at stock `postgres:16-alpine` (postgres = UID 70) initdb dies with
    "could not look up effective user ID 26: user does not exist" and the cluster never bootstraps.
    """
    rendered = _render(SHAPES["ha"])
    m = re.search(r"kind: Cluster\b.*?imageName:\s*\"([^\"]+)\"", rendered, re.S)
    assert m, "no CloudNativePG Cluster imageName rendered"
    assert "alpine" not in m.group(1), (
        f"CNPG cannot bootstrap on {m.group(1)} — it needs a CNPG operand image"
    )


def test_redis_ha_tells_the_operator_the_password() -> None:
    """`requirepass` configures redis; `auth.secretPath` is what the OPERATOR reads.

    Without it the operator never injects REDIS_PASSWORD, so its readiness script queries redis
    unauthenticated and the pods never go Ready — with replication perfectly healthy.
    """
    rendered = _render(SHAPES["ha"])
    assert re.search(r"kind: RedisFailover\b.*?auth:\s*\n\s*secretPath:\s*(\S+)", rendered, re.S), (
        "RedisFailover has no auth.secretPath — the operator cannot authenticate to the cluster"
    )
    assert "name: norviq-redis-ha-auth" in rendered, "the Secret auth.secretPath names is not rendered"
