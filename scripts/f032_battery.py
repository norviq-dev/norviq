#!/usr/bin/env python3
"""F-032 repro: measure content-detector evasion at the detector level.

The eval reports 66% (25/38). This runs the same shape of battery directly against the functions the
fix will change, so a number here is attributable to a regex rather than to policy wiring, monitor
mode, or the rate limiter. Run it before and after; the "before" numbers are the finding, the delta
is the fix.

Each row is (label, payload, expected_class). A payload that SHOULD be caught but yields no class is
an evasion. The benign rows must stay clean — the detectors' 0-false-positive property is the thing
most easily lost while widening them, and losing it would be a worse outcome than the evasions.
"""
from __future__ import annotations

import base64
import sys

sys.path.insert(0, ".")

from norviq.engine.evaluator import OPAEvaluator  # noqa: E402

_ev = OPAEvaluator.__new__(OPAEvaluator)

SSN = "123-45-6789"
AKIA = "AKIAIOSFODNN7EXAMPLE"
PAN = "4111111111111111"

CASES: list[tuple[str, str, str, str]] = [
    # (family, label, payload, expected class)
    ("ssn", "plain dashed (control)",   SSN,                                   "pii"),
    ("ssn", "spaces",                   "123 45 6789",                          "pii"),
    ("ssn", "dots",                     "123.45.6789",                          "pii"),
    ("ssn", "nbsp",                     "123 45 6789",                "pii"),
    ("ssn", "zero-width",               "123-45-67​89",                    "pii"),
    ("ssn", "fullwidth",                "１２３-４５-６７８９",                      "pii"),
    ("ssn", "no separator",             "123456789",                            "pii"),
    ("ssn", "base64",                   base64.b64encode(SSN.encode()).decode(), "pii"),
    ("ssn", "prose context",            f"the ssn is {SSN} please",             "pii"),

    ("secret", "plain AKIA (control)",  AKIA,                                   "secret"),
    ("secret", "lowercase",             AKIA.lower(),                           "secret"),
    ("secret", "spaced",                "AKIA IOSF ODNN 7EXA MPLE",             "secret"),
    ("secret", "zero-width",            "AKIA​IOSFODNN7EXAMPLE",           "secret"),
    ("secret", "base64",                base64.b64encode(AKIA.encode()).decode(), "secret"),
    ("secret", "hex",                   AKIA.encode().hex(),                    "secret"),
    ("secret", "in a key position",     "__KEYPOS__",                           "secret"),

    ("pci", "plain 16 (control)",       PAN,                                    "pci"),
    ("pci", "spaced",                   "4111 1111 1111 1111",                  "pci"),
    ("pci", "dashed",                   "4111-1111-1111-1111",                  "pci"),
    ("pci", "integer leaf",             "__INTLEAF__",                          "pci"),
    ("pci", "grouped amex (15)",        "3782 822463 10005",                    "pci"),
    ("pci", "base64",                   base64.b64encode(PAN.encode()).decode(), "pci"),
]

BENIGN = [
    ("order id",        "ORD-002"),
    ("iso date",        "2026-08-11"),          # BUG-005: known FP, tracked separately
    ("uuid",            "550e8400-e29b-41d4-a716-446655440000"),
    ("prose",           "please refund the customer, order 12345"),
    ("semver",          "version 1.2.3 build 4567"),
    ("phone-ish",       "call me on 555 0134"),
    ("hex colour",      "#a1b2c3"),
    ("sha",             "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
]


def classes_for(payload: str) -> list[str]:
    if payload == "__KEYPOS__":
        params = {"data": {AKIA: "v"}}
        return _ev._data_classes(params, [])
    if payload == "__INTLEAF__":
        params = {"note": int(PAN)}
        vals = [v for v in [params["note"]] if isinstance(v, str)]
        return _ev._data_classes(params, vals)
    return _ev._data_classes({"body": payload}, [payload])


def main() -> int:
    print("=" * 84)
    print("F-032 — content-detector recall at the detector level")
    print("=" * 84)
    evaded, total = 0, 0
    by_family: dict[str, list[int]] = {}
    for family, label, payload, want in CASES:
        got = classes_for(payload)
        ok = want in got
        total += 1
        by_family.setdefault(family, [0, 0])
        by_family[family][1] += 1
        if not ok:
            evaded += 1
            by_family[family][0] += 1
        print(f"  {family:<7} {label:<24} -> {str(got):<22} {'caught' if ok else '*** EVADES ***'}")

    print("-" * 84)
    fp = 0
    for label, payload in BENIGN:
        got = classes_for(payload)
        if got:
            fp += 1
            print(f"  BENIGN  {label:<24} -> {got}  *** FALSE POSITIVE ***")
    print(f"  benign: {len(BENIGN) - fp}/{len(BENIGN)} clean")
    print("=" * 84)
    for fam, (ev, tot) in sorted(by_family.items()):
        print(f"  {fam:<7} evaded {ev}/{tot}")
    print(f"  TOTAL   evaded {evaded}/{total}  ({100 * evaded // total}%)   false positives: {fp}")
    print("=" * 84)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
