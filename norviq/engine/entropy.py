# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""High-entropy string detection for bare credential VALUES (F-004).

## The gap

An AWS access-key **id** (`AKIA…`) is caught by shape. The 40-character secret access-key **value**
(`wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`) has no shape at all — it is just base64-ish bytes — and
matched nothing. The id alone is a public-ish half-credential; the value is the half that actually
signs requests.

## Why this is an AUDIT signal and never a block

This is the one detector in the engine that cannot be precise, and pretending otherwise would undo
the property the rest of the content work is built on. A 40-character high-entropy string is a secret,
a SHA-256 digest, a UUID without dashes, a JWT segment, a git commit, a content hash, a base64 thumbnail
or a session id — and nothing in the bytes distinguishes them. Every heuristic here is a guess.

So `looks_like_secret_value` exists to RAISE A FLAG, not to refuse a call. The engine reports it as a
distinct `secret_suspected` data class rather than folding it into `secret`, so:

  * a policy author can write an audit rule against it deliberately;
  * the shipped baseline does NOT block on it, so the 0-false-positive property of `secret` survives;
  * an operator who sees it in the audit log can decide, which is the only party with the context to.

That separation is the whole design. Merging it into `secret` would have been a one-line change and
would have made `llm02_data_leakage` fire on every commit hash in a payload.

## The filters

Precision comes from EXCLUDING the known-benign shapes, not from tuning the entropy threshold — a
threshold alone cannot tell a secret from a digest, because they have the same entropy.
"""

from __future__ import annotations

import math
import re

# Below this length, ordinary words and ids reach secret-like entropy by accident.
_MIN_LEN = 32
_MAX_LEN = 200

# Shannon entropy per character. Base64-ish credential material sits around 4.5-5.5; English prose is
# near 2-3; a hex digest is ~4.0, which is why hex is excluded by SHAPE below rather than by score.
_MIN_ENTROPY = 4.2

# Shapes that are high-entropy by construction and are NOT credentials. Each is here because it would
# otherwise be the majority of what this fires on.
_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")            # sha1/sha256/md5 digests, git commits, content hashes
_UUID = re.compile(r"^[0-9a-fA-F-]{32,36}$")
_JWT = re.compile(r"^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")  # already caught as a credential by shape
_DIGITS_ONLY = re.compile(r"^\d+$")
_URL_LIKE = re.compile(r"^[a-z][a-z0-9+.-]*://")
_PATH_LIKE = re.compile(r"^/|^[A-Za-z]:\\")

# A credential value is drawn from a narrow alphabet. Prose and CSV rows are not.
_CREDENTIAL_ALPHABET = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_secret_value(value: str) -> bool:
    """True if `value` is plausibly a bare credential value. ADVISORY — see the module docstring.

    Ordered cheapest-first, and every early return is an exclusion rather than a match: the default
    answer is no, and a candidate has to survive every filter to earn a maybe.
    """
    if not value or not isinstance(value, str):
        return False
    token = value.strip()
    if not (_MIN_LEN <= len(token) <= _MAX_LEN):
        return False
    if not _CREDENTIAL_ALPHABET.match(token):
        return False
    # Shape exclusions before the score, because these are the ones a threshold cannot separate: a
    # SHA-256 digest is high-entropy and is not a secret.
    if _HEX_ONLY.match(token) or _UUID.match(token) or _DIGITS_ONLY.match(token):
        return False
    if _JWT.match(token) or _URL_LIKE.match(token) or _PATH_LIKE.match(token):
        return False
    # A real credential mixes cases and digits. `aaaaaaaa…` and a lowercase-only slug do not.
    if token.islower() or token.isupper():
        return False
    if not any(c.isdigit() for c in token):
        return False
    return shannon_entropy(token) >= _MIN_ENTROPY
