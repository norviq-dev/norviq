# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Does `protect()` actually intercept everything it appears to?

`protect()` replaces `tool._run` / `tool._arun`. Everything downstream — the policy decision, the
audit row, output DLP — hangs off those two swaps. These probe the edges of that: shapes a real tool
returns, things an application does to a tool after wrapping, and the paths a framework can take that
are not `_run`.

Each test states a property an operator would assume from the product's own copy. Where one fails it
is describing a gap between what the console claims and what the wrapper does, not a style choice.
"""

from __future__ import annotations

import pytest

from norviq.config import settings
from norviq.sdk.core.wrapping import _output_dlp

PAN = "4111 1111 1111 1111"
SSN = "123-45-6789"


@pytest.fixture(autouse=True)
def _dlp_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "sdk_output_dlp_enabled", True, raising=False)


def test_output_dlp_masks_a_plain_string_return() -> None:
    """The shipped case, pinned so the rest is measured against something that works."""
    out = _output_dlp("search_docs", f"customer card {PAN}, ssn {SSN}")
    assert PAN not in out and SSN not in out


def test_output_dlp_masks_a_list_of_strings() -> None:
    """The single most common tool return shape after a bare string — search hits, row exports, log
    lines. A PAN in element 0 leaves the process unmasked today because the guard tests
    `isinstance(result, str)` on the TOP-LEVEL object only."""
    out = _output_dlp("search_docs", [f"row1 {PAN}", "row2 clean"])
    assert PAN not in str(out), f"a PAN survived in a list return: {out!r}"


def test_output_dlp_masks_a_dict_return() -> None:
    """A structured record — the shape any 'get_customer'-style tool returns."""
    out = _output_dlp("get_customer", {"name": "acme", "card": PAN, "ssn": SSN})
    assert PAN not in str(out) and SSN not in str(out), f"a PAN/SSN survived a dict return: {out!r}"


def test_output_dlp_masks_a_nested_structure() -> None:
    """Nesting is not an exotic case: it is what a paginated API response looks like."""
    payload = {"results": [{"customer": {"card": PAN}}], "next": None}
    out = _output_dlp("list_customers", payload)
    assert PAN not in str(out), f"a PAN survived nested one level down: {out!r}"


def test_output_dlp_is_bounded_and_cannot_be_made_to_walk_forever() -> None:
    """Whatever walks a structure must be bounded — a tool result is attacker-influenced, and the
    engine fails CLOSED at a 2s timeout, so unbounded work on the output plane is a denial of service
    against every other call in flight."""
    deep: object = PAN
    for _ in range(2000):
        deep = {"n": deep}
    import time

    t0 = time.perf_counter()
    _output_dlp("deep", deep)
    assert time.perf_counter() - t0 < 1.0, "output DLP took over a second on a deeply nested result"


def test_output_dlp_preserves_the_shape_it_was_given() -> None:
    """Masking must not change a tool's contract with its caller — a dict must stay a dict, or the
    agent framework breaks on a value it was told is safe to use."""
    out = _output_dlp("get_customer", {"card": PAN, "n": 1, "ok": True, "none": None})
    assert isinstance(out, dict)
    assert out["n"] == 1 and out["ok"] is True and out["none"] is None


def test_output_dlp_off_is_an_exact_passthrough(monkeypatch: pytest.MonkeyPatch) -> None:
    """The default is OFF and must stay a true no-op — same object, not a rebuilt copy."""
    monkeypatch.setattr(settings, "sdk_output_dlp_enabled", False, raising=False)
    payload = {"card": PAN}
    assert _output_dlp("t", payload) is payload
