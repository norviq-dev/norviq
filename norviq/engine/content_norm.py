# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""One normalize+decode stage in front of every content detector (F-032).

## What this fixes

The content detectors were precise and brittle: 0 false positives, and a measured 68% of attack
variants walked past them. Only the exact byte shape matched. `123-45-6789` was PII; `123 45 6789`,
`123.45.6789`, the same with a non-breaking space or a zero-width character, or base64 of any of them,
were nothing at all. `AKIAIOSFODNN7EXAMPLE` was a secret; the same string lowercased, spaced,
zero-width-split, base64'd or hex'd was not.

Every one of those is the same defect: the detector compared bytes the attacker chose the spelling of.
So this module produces the VIEWS a detector should see, once, in one place, and the detectors run over
all of them. Adding a view here fixes every detector at once; that is the whole point of it being
shared rather than three copies that drift.

## The property that must not be lost

The detectors' precision is worth more than their recall. A control that cries wolf gets promoted to
`monitor` and then ignored, which is a slower way of having no control. `scripts/f032_battery.py`
therefore asserts BOTH directions, and the benign corpus is deliberately the awkward one: order ids,
ISO dates, UUIDs, SHA-256 digests, semver strings, phone numbers.

That is also why this module does NOT strip separators entirely. A bare nine-digit run is a plausible
SSN and an equally plausible order number, account id or timestamp, and there is no way to tell them
apart from the digits alone. Squeezing all separators would "close" one evasion and hand back a false
positive on ordinary business traffic — a bad trade. Separators are normalised to a canonical form,
not deleted; a detector that wants the aggressive reading can opt into `digits_only()` explicitly and
own the consequence.

## Bounds

Everything here is bounded, because it runs on the hot path and the input is hostile: decode depth is
capped, each candidate is length-capped, and the number of views per value is capped. An attacker must
not be able to turn one 4 KB parameter into megabytes of rescanning.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

import structlog

log = structlog.get_logger()

# Format/invisible characters an attacker inserts to break a byte match while leaving the string
# visually identical: zero-width space/non-joiner/joiner, word joiner, BOM, and the bidi controls.
_INVISIBLE = dict.fromkeys(
    [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD]
    + list(range(0x202A, 0x202F))
    + list(range(0x2066, 0x206A)),
    None,
)

# Separator characters that appear BETWEEN the digit groups of a formatted identifier. Normalised to
# a plain ASCII hyphen so one pattern matches every spelling, rather than each detector growing its
# own alternation and drifting from the others.
# Built from explicit code points and ESCAPED, not written as a literal class. A hand-typed class of
# dashes and dots silently forms RANGES — `.` through `\u2010` spans thousands of code points — and
# Python rejected mine outright with "bad character range". That refusal was the friendly outcome; a
# class that merely matched far too much would have widened every detector invisibly.
_SEPARATOR_CHARS = (
    "\u0020\u00a0\u2007\u2009\u202f\u3000"          # spaces incl. NBSP / thin / ideographic
    "\u002e\u2024\uff0e"                              # full stop variants
    "\u002d\u2010\u2011\u2012\u2013\u2014\u2015"  # hyphen / dash variants
    "\u2212\ufe58\uff0d"
    "\u005f\uff3f"                                     # underscores
)
_SEPARATORS = re.compile("[" + re.escape(_SEPARATOR_CHARS) + "]+")

MAX_VALUE_LEN = 8192      # a single value longer than this is truncated before normalising
MAX_DECODE_DEPTH = 2      # base64(base64(x)) is worth following; deeper is an attacker burning our CPU
MAX_VIEWS = 12            # hard cap on the views produced per value
_MIN_DECODE_LEN = 12      # shorter candidates decode to noise and cost more than they find

_B64_RE = re.compile(r"[A-Za-z0-9+/=_-]{%d,}" % _MIN_DECODE_LEN)
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def strip_invisible(text: str) -> str:
    """Remove zero-width and bidi-control characters. Visual identity preserved, bytes normalised."""
    return text.translate(_INVISIBLE)


def normalize(text: str) -> str:
    """NFKC + invisible-strip: the canonical view every detector should match against.

    NFKC folds fullwidth, mathematical-alphanumeric and other compatibility forms to their ASCII
    prototypes, so `ＡＫＩＡ…` and `𝗔𝗞𝗜𝗔…` become `AKIA…`. It deliberately does NOT case-fold —
    case is carried separately, because a credential pattern such as `AKIA[0-9A-Z]{16}` is meaningful
    and destroying its case is how the previous base64 path lost the AWS key it was meant to find.
    """
    if len(text) > MAX_VALUE_LEN:
        text = text[:MAX_VALUE_LEN]
    return strip_invisible(unicodedata.normalize("NFKC", text))


def canonical_separators(text: str) -> str:
    """Collapse every separator spelling to a single ASCII hyphen.

    `123 45 6789`, `123.45.6789`, `123 45 6789` and `123‑45‑6789` all become `123-45-6789`,
    so ONE pattern covers them. Runs of separators collapse to one, so `123  45   6789` matches too.
    """
    return _SEPARATORS.sub("-", text)


def digits_only(text: str) -> str:
    """Every digit, separators discarded. NOT used by default — see the module docstring.

    Offered for a detector that has an independent reason to be confident (a Luhn check, a key name
    that already says `ssn`), because on its own it cannot tell an SSN from an order number.
    """
    return "".join(ch for ch in text if ch.isdigit())


def _decode_candidates(text: str) -> list[str]:
    """Base64/hex substrings decoded to text, when the result looks like text at all."""
    out: list[str] = []
    for match in _B64_RE.findall(text)[:4]:
        raw = match.replace("-", "+").replace("_", "/")
        pad = raw + "=" * (-len(raw) % 4)
        try:
            decoded = base64.b64decode(pad, validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            as_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # Decoded bytes that are mostly unprintable are noise, not a payload. Without this every
        # ordinary word decodes to junk and every detector rescans it — the same fan-out that put a
        # bare "|" into the shell detector and produced the base64 false-positive curve (C2-023).
        if as_text and sum(c.isprintable() for c in as_text) / len(as_text) >= 0.9:
            out.append(as_text)
    for match in _HEX_RE.findall(text)[:4]:
        try:
            decoded = bytes.fromhex(match[: len(match) // 2 * 2])
        except ValueError:
            continue
        try:
            as_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if as_text and sum(c.isprintable() for c in as_text) / len(as_text) >= 0.9:
            out.append(as_text)
    return out


def views(value: object, *, depth: int = 0) -> list[str]:
    """Every spelling of `value` a detector should be matched against.

    Order is stable and the first element is always the normalised original, so a caller that only
    wants the cheap view can take `views(v)[0]`.

    Non-string leaves are coerced, which is a fix in its own right: `{"note": 4111111111111111}` as an
    INTEGER was invisible to detectors that only walked string leaves, while the same digits in quotes
    blocked (F-045).
    """
    if value is None or isinstance(value, bool):
        return []
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception as exc:  # noqa: BLE001 — a hostile __str__ can raise anything at all
            # A leaf that cannot be stringified is a leaf NO detector ever sees. Refusing the whole
            # evaluation over one bad object would be worse (fail-closed on a caller's data bug), but
            # this must not be silent: it is precisely the invisible-content class F-032 exists to
            # close, and it cannot arise from JSON-deserialised params at all — so if it ever fires,
            # something is constructing params by hand and the log line is the only way to find out.
            log.warning(
                "nrvq.content_norm.unstringable_leaf",
                code="NRVQ-ENG-2065",
                leaf_type=type(value).__name__,
                error=str(exc),
            )
            return []
    if not value:
        return []

    base = normalize(value)
    out = [base]
    canon = canonical_separators(base)
    if canon != base:
        out.append(canon)
    folded = base.casefold()
    if folded != base:
        out.append(folded)

    if depth < MAX_DECODE_DEPTH:
        for decoded in _decode_candidates(base):
            for nested in views(decoded, depth=depth + 1):
                if nested not in out:
                    out.append(nested)
                if len(out) >= MAX_VIEWS:
                    return out[:MAX_VIEWS]
    return out[:MAX_VIEWS]


def desep(text: str) -> str:
    """Separators removed entirely — `AKIA IOSF ODNN 7EXA MPLE` -> `AKIAIOSFODNN7EXAMPLE`.

    SAFE FOR CREDENTIAL PATTERNS ONLY, and the distinction is the whole reason this is a separate
    function rather than another entry in `views()`.

    A credential shape is specific enough to survive it: `AKIA` followed by exactly 16 uppercase
    alphanumerics does not occur by accident in de-spaced prose. A NUMERIC shape is not: strip the
    separators from any nine digits and every order number, account id and timestamp becomes an SSN.
    So `credential_views()` opts in and the PII path does not.
    """
    return _SEPARATORS.sub("", text)


def credential_views(value: object) -> list[str]:
    """`views()` plus the de-separated spelling. For credential/secret shapes only — see `desep`."""
    out = views(value)
    extra: list[str] = []
    for v in out:
        stripped = desep(v)
        if stripped != v and stripped not in out:
            extra.append(stripped)
    return (out + extra)[:MAX_VIEWS]


def search_any(pattern: re.Pattern[str], value: object) -> bool:
    """True if `pattern` matches ANY view of `value`. The one call sites should use."""
    return any(pattern.search(v) for v in views(value))
