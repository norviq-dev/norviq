# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-032 regression: the normalize+decode stage in front of every content detector.

Both directions are asserted, and the second matters more than the first. Widening a detector is
easy; keeping it quiet on ordinary traffic while widening it is the whole difficulty. A control that
fires on order ids and ISO dates gets moved to `monitor` by the first customer who sees it, which is
a slower and more expensive way of having no control at all.

The evasion corpus mirrors `scripts/f032_battery.py`, which measured 68% evasion before this stage
existed and 4% after. The one case still expected to evade is pinned here deliberately rather than
omitted — see `test_bare_nine_digits_is_deliberately_not_pii`.
"""

from __future__ import annotations

import base64

import pytest

from norviq.engine import content_norm
from norviq.engine.evaluator import OPAEvaluator

SSN = "123-45-6789"
AKIA = "AKIAIOSFODNN7EXAMPLE"
PAN = "4111111111111111"


@pytest.fixture(scope="module")
def classes():
    """`_data_classes` without building a whole evaluator — this is pure content inspection."""
    ev = OPAEvaluator.__new__(OPAEvaluator)

    def run(params: dict) -> list[str]:
        values = [v for v in params.values() if isinstance(v, str)]
        return ev._data_classes(params, values)

    return run


# --- normalisation primitives -------------------------------------------------------------------


def test_normalize_folds_compatibility_forms_without_touching_case():
    # NFKC is what makes fullwidth and math-alphanumeric spellings collapse onto ASCII. Case must
    # SURVIVE it: `AKIA[0-9A-Z]{16}` is a case-sensitive shape, and case-folding here is exactly how
    # an earlier attempt lost the AWS key it was meant to find.
    assert content_norm.normalize("ＡＫＩＡ") == "AKIA"
    assert content_norm.normalize("𝗔𝗞𝗜𝗔") == "AKIA"
    assert content_norm.normalize("AkIa") == "AkIa"


def test_normalize_strips_invisible_characters():
    assert content_norm.normalize("123​45⁠678") == "12345678"


def test_canonical_separators_collapses_every_spelling():
    for spelling in ("123 45 6789", "123.45.6789", "123 45 6789", "123‐45‐6789"):
        assert content_norm.canonical_separators(content_norm.normalize(spelling)) == SSN


def test_views_always_leads_with_the_normalised_original():
    assert content_norm.views("hello")[0] == "hello"


def test_views_are_bounded():
    # The input is hostile and this runs per parameter: one value must not fan out without limit.
    nested = base64.b64encode(base64.b64encode(base64.b64encode(b"x" * 200))).decode()
    assert len(content_norm.views(nested)) <= content_norm.MAX_VIEWS


def test_views_coerces_non_string_leaves():
    # F-045: the same digits as an int were invisible while the quoted form blocked.
    assert content_norm.views(4111111111111111)[0] == PAN
    assert content_norm.views(None) == []
    assert content_norm.views(True) == []  # a bool is not content


def test_desep_is_not_applied_to_plain_views():
    # The load-bearing precision decision: separators are canonicalised, never deleted, on the
    # general path. Deleting them turns every nine-digit order number into an SSN.
    assert "123456789" not in content_norm.views("123-45-6789")
    assert "AKIAIOSFODNN7EXAMPLE" in content_norm.credential_views("AKIA IOSF ODNN 7EXA MPLE")


# --- recall: the evasions F-032 measured -------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("plain", SSN),
        ("spaces", "123 45 6789"),
        ("dots", "123.45.6789"),
        ("nbsp", "123 45 6789"),
        ("zero-width", "123-45-67​89"),
        ("fullwidth", "１２３-４５-６７８９"),
        ("base64", base64.b64encode(SSN.encode()).decode()),
        ("prose context", f"the ssn is {SSN} please"),
    ],
)
def test_ssn_evasions_are_caught(classes, label, payload):
    assert "pii" in classes({"body": payload}), label


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("plain", AKIA),
        ("lowercase", AKIA.lower()),
        ("spaced", "AKIA IOSF ODNN 7EXA MPLE"),
        ("zero-width", "AKIA​IOSFODNN7EXAMPLE"),
        ("base64", base64.b64encode(AKIA.encode()).decode()),
        ("hex", AKIA.encode().hex()),
    ],
)
def test_secret_evasions_are_caught(classes, label, payload):
    assert "secret" in classes({"body": payload}), label


def test_secret_in_a_key_position_is_caught(classes):
    # Key TEXT is content too. `{"AKIA...": "v"}` hid a credential from a walker that only read values.
    assert "secret" in classes({"data": {AKIA: "v"}})


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("plain 16", PAN),
        ("spaced", "4111 1111 1111 1111"),
        ("dashed", "4111-1111-1111-1111"),
        ("grouped amex 15", "3782 822463 10005"),
        ("base64", base64.b64encode(PAN.encode()).decode()),
    ],
)
def test_pci_evasions_are_caught(classes, label, payload):
    assert "pci" in classes({"body": payload}), label


def test_pci_integer_leaf_is_caught(classes):
    ev = OPAEvaluator.__new__(OPAEvaluator)
    # Deliberately passing NO string values: the walker must reach the int leaf on its own (F-045).
    assert "pci" in ev._data_classes({"note": int(PAN)}, [])


# --- precision: the property that is easiest to lose while widening -----------------------------


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("order id", "ORD-002"),
        ("uuid", "550e8400-e29b-41d4-a716-446655440000"),
        ("prose with a number", "please refund the customer, order 12345"),
        ("semver", "version 1.2.3 build 4567"),
        ("phone-ish", "call me on 555 0134"),
        ("hex colour", "#a1b2c3"),
        ("sha-256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ],
)
def test_benign_traffic_stays_clean(classes, label, payload):
    assert classes({"body": payload}) == [], label


def test_luhn_gates_pci_so_arbitrary_digit_runs_are_not_cards(classes):
    # A 16-digit run that fails the check digit is an id, a timestamp, a sequence — not a PAN.
    assert classes({"body": "4111111111111112"}) == []


def test_bare_nine_digits_is_deliberately_not_pii(classes):
    """The one evasion left open, on purpose — pinned so removing it is a decision, not an accident.

    Nine digits with no separators is an SSN, an order number, an account id or a timestamp, and
    nothing in the digits distinguishes them. Closing this would trade one evasion for a false
    positive on ordinary business traffic, which is the worse half of the trade. A detector with an
    independent reason to be sure (a key named `ssn`, a Luhn pass) can opt into `digits_only()`.
    """
    assert classes({"body": "123456789"}) == []
