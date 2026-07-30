# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""The chart's own defaults must be mutually consistent — a pure-defaults install has to start.

The chart shipped two defaults that could not both hold:

    postgresql.enabled: true      the in-chart StatefulSet, which has NO TLS listener
                                  (nothing in the chart ever gives it a cert)
    config.dbSslMode:  require    so asyncpg demanded TLS from it

`helm install` with nothing but the required `policyQuotaNamespaces` therefore could not start — the
first thing a new operator does:

    ConnectionError: PostgreSQL server at "norviq-postgresql...:5432" rejected SSL upgrade
    ERROR:    Application startup failed. Exiting.

`helm template` renders both happily; the values are only wrong relative to EACH OTHER, which is what
these tests compare. Four docs and the release gate all carried `--set config.dbSslMode=disable` to
paper over it, which is how it survived: every tested path overrode the broken default.

`config.dbSslMode` is now derived when left empty, and an explicit value always wins. Verified live —
`helm install --wait --atomic` with no dbSslMode override reached STATUS deployed with every pod
Running, and `helm test` passed.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

import pytest
import yaml

CHART = pathlib.Path(__file__).resolve().parents[2] / "helm" / "norviq"

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not on PATH")


def _config(extra: list[str]) -> dict[str, str]:
    res = subprocess.run(
        ["helm", "template", "norviq", str(CHART), "--set-json", 'policyQuotaNamespaces=["agents"]', *extra],
        capture_output=True, text=True)
    assert res.returncode == 0, res.stderr[-600:]
    for doc in yaml.safe_load_all(res.stdout):
        if doc and doc.get("kind") == "ConfigMap" and doc["metadata"]["name"] == "norviq-config":
            return doc["data"]
    raise AssertionError("norviq-config ConfigMap not rendered")


def test_bundled_postgres_does_not_demand_tls_it_cannot_serve() -> None:
    """The regression, named. This is the default install."""
    mode = _config([])["NRVQ_DB_SSL_MODE"]
    assert mode == "disable", (
        f"default install resolves NRVQ_DB_SSL_MODE={mode!r}, but the bundled Postgres StatefulSet "
        "serves no TLS listener — the API will crash-loop on 'rejected SSL upgrade'"
    )


def test_the_bundled_postgres_really_has_no_tls_listener() -> None:
    """Guards the PREMISE of the test above: if the chart ever gives Postgres a cert, revisit this."""
    sts = (CHART / "templates" / "postgresql-statefulset.yaml").read_text().lower()
    assert "ssl_cert_file" not in sts and "ssl=on" not in sts and "ssl_key_file" not in sts, (
        "the bundled Postgres now configures TLS — the derived default should become 'require'"
    )


@pytest.mark.parametrize("shape,extra", [
    ("cnpg-ha", ["--set", "postgresql.ha.enabled=true", "--set", "postgresql.password=Str0ngPg1"]),
    ("external", ["--set", "postgresql.enabled=false", "--set", "postgresql.host=db.example.com"]),
])
def test_a_real_datastore_still_gets_require_with_no_operator_action(shape: str, extra: list[str]) -> None:
    """The derivation must never relax anything but the bundled non-TLS StatefulSet."""
    mode = _config(extra)["NRVQ_DB_SSL_MODE"]
    assert mode == "require", f"{shape} resolved to {mode!r} — production TLS must not be weakened"


@pytest.mark.parametrize("explicit", ["require", "verify-full", "disable", "prefer"])
def test_an_explicit_value_always_wins(explicit: str) -> None:
    assert _config(["--set", f"config.dbSslMode={explicit}"])["NRVQ_DB_SSL_MODE"] == explicit


def test_values_prod_still_pins_require() -> None:
    mode = _config(["-f", str(CHART / "values-prod.yaml"),
                    "--set", "postgresql.password=Str0ngPg1", "--set", "redis.password=Str0ngR1"])["NRVQ_DB_SSL_MODE"]
    assert mode == "require", f"values-prod.yaml must pin require, got {mode!r}"


def test_the_schema_accepts_the_derive_sentinel() -> None:
    """An empty default that the schema rejects would fail every install instead."""
    schema = json.loads((CHART / "values.schema.json").read_text())
    enum = schema["properties"]["config"]["properties"]["dbSslMode"]["enum"]
    assert "" in enum, f"values.schema.json rejects the empty (derive) default: {enum}"


def test_the_release_gate_does_not_override_the_default_it_is_meant_to_verify() -> None:
    """A gate that passes --set config.dbSslMode=disable can never catch this class of defect.

    The published-chart install inside the same script keeps the override on purpose — older releases
    hard-code `require` — so this asserts on the CANDIDATE install specifically.
    """
    src = (CHART.parents[1] / "scripts" / "verify_release.py").read_text()
    candidate = src.split('res = helm(ctx, "install", "norviq", str(chart)', 1)[1].split("timeout=900")[0]
    assert "dbSslMode" not in candidate, (
        "verify_release.py overrides dbSslMode on the candidate install — it would not have caught "
        "the defect that a pure-defaults install cannot start"
    )
