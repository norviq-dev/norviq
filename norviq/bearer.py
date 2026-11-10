# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Bearer tokens on outbound requests: checked before they are sent, and kept out of log lines.

A token usually reaches a client from ``NRVQ_API_TOKEN``, which in a cluster is often a Kubernetes
Secret created from a file. A file written by ``echo`` ends in a newline. httpx accepts that header
when the client is built and refuses it when the request is written, with an error that quotes the
whole header value, token included. `NorviqSettings` strips surrounding whitespace when it loads;
`bearer_token_problem` is for what remains, and for a token passed to a client directly.
"""

from __future__ import annotations

import re

#: What replaces a credential in text that is about to be logged or returned.
REDACTED = "[redacted]"

# C0 controls (CR, LF and NUL among them), DEL, C1 controls, and anything outside latin-1.
_UNSENDABLE = re.compile(r"[\x00-\x1f\x7f-\x9f]|[^\x00-\xff]")


def bearer_token_problem(token: str) -> str | None:
    """Why `token` cannot be sent as ``Authorization: Bearer <token>``, or None when it can.

    The answer never contains the token or any part of it. An empty token means "send no header" and
    is not a problem.
    """
    if not token:
        return None
    if token != token.strip():
        return "it begins or ends with whitespace"
    bad = _UNSENDABLE.search(token)
    if bad is None:
        return None
    if bad.group() in "\r\n":
        return "it contains a line break"
    if ord(bad.group()) > 0xFF:
        return "it contains a character outside latin-1"
    return "it contains a control character"


# `Bearer <credential>` in any text; the credential ends at whitespace or a quote.
_BEARER = re.compile(r"(?i)\b(bearer)(\s+)[^\s'\"]+")
# A refused header value is quoted whole, by h11 ("Illegal header value b'...'") and by the standard
# library's http.client ("Invalid header value b'...'"); nothing after the prefix is safe to keep.
_ILLEGAL_HEADER_VALUE = re.compile(r"((?:Illegal|Invalid) header value)\s*\S.*", re.DOTALL)
# Shorter pieces of a token are not searched for: they would match ordinary text.
_MIN_PIECE = 4


def _secret_forms(secret: str) -> set[str]:
    """The ways `secret` can appear in an error message: as given, stripped, escaped as a bytes or
    str literal shows it, and each run of it between whitespace or control characters."""
    forms = {secret, secret.strip()}
    forms.add(secret.encode("unicode_escape").decode("ascii"))
    forms.add(repr(secret.encode("utf-8", "surrogatepass"))[2:-1])
    forms.update(re.split(r"[\s\x00-\x1f\x7f]+", secret))
    return {f for f in forms if len(f) >= _MIN_PIECE}


def redact_credentials(text: str, *secrets: str) -> str:
    """`text` with every bearer credential, and every form of each of `secrets`, replaced.

    For error text that is logged or returned: an httpx error raised while writing a request can quote
    its headers. Pass the token the client holds when there is one; the patterns cover a ``Bearer``
    value and a refused header value without it.
    """
    for secret in secrets:
        if not secret:
            continue
        for form in sorted(_secret_forms(secret), key=len, reverse=True):
            text = text.replace(form, REDACTED)
    text = _ILLEGAL_HEADER_VALUE.sub(lambda m: f"{m.group(1)} {REDACTED}", text)
    return _BEARER.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
