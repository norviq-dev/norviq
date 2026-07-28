# SPDX-License-Identifier: Apache-2.0
"""`PUT /settings` must reject an unknown field rather than silently misdirecting the write.

The target namespace comes from the QUERY string (`?namespace=`). A caller who reasonably puts it in
the BODY — `{"namespace": "prod", "enforcement_mode": "audit"}` — used to get a 200 while the write
landed in `default`: the namespace they named was untouched, and one they never named had its
posture changed. Pydantic's default is to ignore unknown fields, so nothing complained.

That is worse than an error for this particular object. `enforcement_mode` decides whether a
namespace blocks or merely audits, so a misdirected write both leaves the intended namespace
unprotected AND silently relaxes another — while reporting success. It cost real debugging time
during pre-GA testing and briefly polluted `default`.

`SettingsUpdate` now sets `extra="forbid"`, so the call 422s and names the field.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from norviq.api.routers.settings_router import SettingsUpdate


def test_body_namespace_is_rejected_not_ignored() -> None:
    """The exact shape that silently wrote to the wrong namespace."""
    with pytest.raises(ValidationError) as exc:
        SettingsUpdate(namespace="prod", enforcement_mode="audit")
    # The error must NAME the offending field, otherwise the caller still cannot tell what to fix.
    assert "namespace" in str(exc.value)


def test_any_unknown_field_is_rejected() -> None:
    """Not special-cased to `namespace` — a typo'd field name is the same class of silent no-op.

    `enforcment_mode` (missing 'e') would previously be dropped, leaving the namespace in whatever
    posture it already had while the API returned 200 and the UI showed the requested value.
    """
    with pytest.raises(ValidationError):
        SettingsUpdate(enforcment_mode="audit")


@pytest.mark.parametrize(
    "payload",
    [
        {"enforcement_mode": "audit"},
        {"enforcement_mode": "block", "trust_threshold": 0.7},
        {"rate_limit": 100, "sector": "finance", "apply_mode": "dry_run_only"},
        {},  # every field optional — an empty body is a legitimate no-op
    ],
)
def test_legitimate_payloads_still_accepted(payload: dict) -> None:
    """The five fields the console actually sends must keep working.

    `saveSettings` in ui/src/api/client.ts sends exactly this Pick<> and passes the namespace as a
    query param, so forbidding extras cannot break the Settings page — this pins that.
    """
    assert SettingsUpdate(**payload) is not None


def test_validation_still_applies_to_known_fields() -> None:
    """extra="forbid" must not shadow the existing per-field constraints."""
    with pytest.raises(ValidationError):
        SettingsUpdate(enforcement_mode="off")          # pattern is ^(block|audit)$
    with pytest.raises(ValidationError):
        SettingsUpdate(trust_threshold=1.5)             # ge=0.0 le=1.0
    with pytest.raises(ValidationError):
        SettingsUpdate(apply_mode="whenever")           # ^(enforce|dry_run_only)$
