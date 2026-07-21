# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""fleet_join (spoke enrollment) and
mint_cluster_join_token (hub join-token mint) both took an unvalidated hub_url and dialed/persisted it.
This locks in the fleet_join half: a join token whose (HMAC-verified, so this ISN'T about token
forgery) embedded hub_url points at a blocked address must be rejected BEFORE the spoke ever dials it
or persists it as its ongoing relay/puller target."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from norviq.api.routers.fleet_enroll import JoinBody, fleet_join
from norviq.config import settings
from norviq.fleet.join_token import mint_join_token


def _request():
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))


class _Session:
    """Never actually reached if the SSRF guard does its job — execute()/commit() would raise if called."""

    async def execute(self, _stmt):
        raise AssertionError("must not query the DB before the hub_url SSRF check")

    async def commit(self):
        raise AssertionError("must not persist before the hub_url SSRF check")


@pytest.mark.asyncio
async def test_fleet_join_rejects_ssrf_hub_url_before_dialing_or_persisting() -> None:
    token, _ = mint_join_token(
        secret=settings.api_secret_key, hub_url="http://169.254.169.254/", cluster_id="fleet-a",
        bundle_pubkey="pk",
    )
    with pytest.raises(Exception) as exc_info:
        await fleet_join(body=JoinBody(token=token), request=_request(),
                          user={"role": "admin", "sub": "op"}, session=_Session())
    # FastAPI's HTTPException carries `.detail`/`.status_code`; assert the guard fired (422), not a
    # generic failure, and that the message names the SSRF check (not a DB/network error).
    assert getattr(exc_info.value, "status_code", None) == 422
    assert "ssrf" in str(getattr(exc_info.value, "detail", exc_info.value)).lower()
