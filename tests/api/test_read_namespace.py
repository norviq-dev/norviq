# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`read_namespace` — the cross-namespace ("All namespaces") read filter. Tenant isolation must hold:
admin/"all" => None (no filter, every namespace); a scoped viewer's "all" is pinned to its own namespace
(never cross-tenant); a no-scope viewer 403s; a specific cross-tenant request 403s."""

from __future__ import annotations

import pytest
from fastapi import HTTPException

from norviq.api.auth import read_namespace

ADMIN = {"role": "admin", "namespace": ""}
VIEWER_A = {"role": "viewer", "namespace": "team-a"}
STAR = {"role": "viewer", "namespace": "*"}
SERVICE = {"role": "service", "namespace": ""}
NO_CLAIM = {"role": "viewer", "namespace": ""}


@pytest.mark.parametrize("requested", ["all", None])
def test_admin_all_is_unfiltered(requested):
    assert read_namespace(ADMIN, requested) is None  # None => no WHERE namespace filter


def test_star_claim_all_is_unfiltered():
    assert read_namespace(STAR, "all") is None


def test_service_no_claim_all_is_unfiltered():
    assert read_namespace(SERVICE, "all") is None  # machine principal (webhook/relay) trusted


def test_viewer_all_is_pinned_to_own_namespace():
    assert read_namespace(VIEWER_A, "all") == "team-a"
    assert read_namespace(VIEWER_A, None) == "team-a"


def test_viewer_specific_own_namespace_passes():
    assert read_namespace(VIEWER_A, "team-a") == "team-a"


def test_viewer_cross_namespace_is_403():
    with pytest.raises(HTTPException) as exc:
        read_namespace(VIEWER_A, "team-b")
    assert exc.value.status_code == 403


def test_no_claim_viewer_all_is_403_not_unfiltered():
    # CRITICAL: a no-scope viewer requesting "all" must NOT get None (that would leak every namespace).
    with pytest.raises(HTTPException) as exc:
        read_namespace(NO_CLAIM, "all")
    assert exc.value.status_code == 403
