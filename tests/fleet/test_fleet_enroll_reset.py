# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Spoke enrollment version-lineage reset. `leave` must FORGET the last-applied bundle version (not just
shed policies), otherwise a later re-enrollment to a hub whose per-cluster version restarted lower (remove->rejoin)
is permanently rejected by the spoke's anti-rollback guard (version <= last_applied -> skip) and the cluster is
stuck "pending" forever despite governing correctly."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from norviq.api.routers.fleet_enroll import fleet_leave


class _Bundle:
    def __init__(self, version: int, manifest: str | None):
        self.last_applied_version = version
        self.last_bundle_sha256 = "deadbeefcafe"
        self.last_manifest = manifest


class _JoinRow:
    def __init__(self):
        self.enabled = True
        self.cluster_id = "fleet-c"
        self.hub_url = "http://hub:8080"
        self.bundle_pubkey = "pk"


class _Session:
    """Routes the two selects (join-state row, bundle rows) by table name in the compiled SQL string."""

    def __init__(self, bundles, join_row):
        self.bundles = bundles
        self.join_row = join_row
        self.committed = False

    async def execute(self, stmt):
        sql = str(stmt)
        if "fleet_join_state" in sql:
            return SimpleNamespace(scalar_one_or_none=lambda: self.join_row)
        return SimpleNamespace(
            scalars=lambda: SimpleNamespace(
                all=lambda: self.bundles,
                first=lambda: (self.bundles[0] if self.bundles else None),
            )
        )

    def add(self, _obj):
        pass

    async def commit(self):
        self.committed = True


class _Loader:
    def __init__(self):
        self.deleted: list[tuple[str, str]] = []

    async def delete(self, ns: str, ac: str) -> bool:
        self.deleted.append((ns, ac))
        return True


class _Stub:
    def __init__(self):
        self.stopped = False

    async def stop(self):
        self.stopped = True


def _request(loader):
    state = SimpleNamespace(loader=loader, fleet_relay=_Stub(), fleet_puller=_Stub())
    return SimpleNamespace(app=SimpleNamespace(state=state))


@pytest.mark.asyncio
async def test_leave_resets_version_lineage_and_sheds():
    # Spoke remembers applying v3836 with one fleet-pushed policy.
    bundle = _Bundle(3836, json.dumps(["default:bot"]))
    session = _Session([bundle], _JoinRow())
    loader = _Loader()

    res = await fleet_leave(request=_request(loader), user={"role": "admin", "sub": "op"}, session=session)

    assert res["enrolled"] is False
    assert ("default", "bot") in loader.deleted          # Shed still happens
    assert bundle.last_applied_version == 0              # version lineage forgotten
    assert bundle.last_bundle_sha256 == ""
    assert json.loads(bundle.last_manifest) == []
    assert session.join_row.enabled is False
    assert session.committed is True


@pytest.mark.asyncio
async def test_leave_resets_every_bundle_row():
    # A spoke may carry state for more than one cluster id across re-enrollments — reset them all.
    b1 = _Bundle(4933, None)
    b2 = _Bundle(120, json.dumps([]))
    session = _Session([b1, b2], _JoinRow())

    await fleet_leave(request=_request(_Loader()), user={"role": "admin", "sub": "op"}, session=session)

    assert b1.last_applied_version == 0 and b2.last_applied_version == 0
