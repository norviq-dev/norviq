# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""`framework` is this product's marker for FABRICATED traffic, so the HTTP boundary must not assert
it on a caller's behalf.

`framework == "redteam"` is what `audit_row_is_non_real` keys on. Rows carrying it are excluded from
the Overview KPIs, MITRE/compliance evidence, coverage efficacy, intent proposals and dry-run replay,
and hidden behind the Audit Log's default-ON "Real traffic only" filter.

EvaluateRequest defaulted it to "redteam". The sidecar, SDK, MCP firewall and console runner all set
it explicitly and were unaffected — but the RAW-HTTP path inherited it, and raw HTTP is exactly what
docs/getting-started.md teaches (its curl bodies never mention the field). An operator following the
documentation would have had their real enforcement counted as fabricated: present in the raw audit
log, worth nothing as evidence, and reported by the Compliance pack as "synthetic events excluded".

The two halves are a PAIR and must be tested together. Removing the default alone would have flipped
the redteam CLI suite's fabricated attacks into real traffic and inflated the very same evidence in
the opposite direction.
"""

from __future__ import annotations

from norviq.api.routers.evaluate import EvaluateRequest
from norviq.redteam.attacks import ATTACKS
from norviq.redteam.simulator import _request_payload


def test_a_caller_who_says_nothing_is_not_recorded_as_fabricated() -> None:
    """FAIL-ON-BUG: the default was "redteam"."""
    req = EvaluateRequest(
        tool_name="send_email",
        tool_params={"to": "a@b.com"},
        agent_identity={"spiffe_id": "spiffe://norviq/ns/default/sa/x", "namespace": "default", "agent_class": "x"},
    )
    assert req.framework == "", "raw-HTTP callers must not be tagged as red-team traffic by default"


def test_the_http_boundary_agrees_with_the_sdk_model() -> None:
    """The SDK's ToolCallEvent has always defaulted this to "". The HTTP boundary was the only place
    that disagreed, and one concept spelled two ways is how this happened."""
    from norviq.sdk.core.events import ToolCallEvent

    assert ToolCallEvent.model_fields["framework"].default == EvaluateRequest.model_fields["framework"].default


def test_a_caller_can_still_declare_itself_synthetic() -> None:
    assert EvaluateRequest(
        tool_name="t", tool_params={},
        agent_identity={"spiffe_id": "s", "namespace": "default", "agent_class": "x"},
        framework="redteam",
    ).framework == "redteam"


def test_the_redteam_suite_still_declares_itself_synthetic() -> None:
    """The other half of the pair. These attacks ARE fabricated; if they stopped being marked as such
    they would count as real enforcement and inflate compliance evidence — the same defect, inverted."""
    payload = _request_payload(ATTACKS[0], "support-agent", "default")
    assert payload["framework"] == "redteam", (
        "the redteam simulator must declare itself rather than inherit an HTTP default"
    )


def test_every_attack_in_the_corpus_is_marked_not_just_the_first() -> None:
    for attack in ATTACKS:
        assert _request_payload(attack, "a", "default")["framework"] == "redteam", attack.id
