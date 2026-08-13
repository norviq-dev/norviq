# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Mask sensitive tool_params for audit capture (PCI 10.3 event reconstruction without raw PII/PAN)."""

from __future__ import annotations

import re

import structlog

log = structlog.get_logger()

_PAN_RE = re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")

# SSN, tolerant of HOW the groups are separated but not of whether they are.
#
# It was `\b\d{3}-\d{2}-\d{4}\b` — dashes only — while _PAN_RE already accepted spaces. That
# asymmetry was the finding (F-012/F-032): `123 45 6789`, `123.45.6789`, the same with a non-breaking
# space or a zero-width character all walked past a detector that caught the dashed form. Callers run
# this over `content_norm.views()`, which canonicalises every separator spelling to `-`, so this
# pattern only has to accept one.
#
# A bare `\d{9}` is deliberately NOT matched. Nine digits with no separator is as likely an order
# number or account id as an SSN, and there is nothing in the digits to tell them apart — matching it
# would trade one evasion for false positives on ordinary business traffic, which is the worse deal
# for a control an operator has to trust. See content_norm's module docstring.
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

_LONG_DIGITS_RE = re.compile(r"^\d{13,19}$")

# Card numbers that are NOT 16 digits: Amex (15), Diners (14). _PAN_RE covers the 16-digit brands.
# Grouped Amex (`3782 822463 10005`) was reported allowed while the 16-digit form blocked (F-045).
# Luhn gates both, so widening the digit-count does not widen the false-positive surface much: a
# random 15-digit run passes Luhn one time in ten.
_PAN_ALT_RE = re.compile(r"\b\d{4}[ -]?\d{6}[ -]?\d{4,5}\b")

# Key NAMES that mean "the value beside me is a credential". Matched as normalised SUBSTRINGS rather
# than by exact equality, because the exact-set version missed the commonest real spellings:
# `access_token`, `client_secret`, `apiKey`, `AWS_SECRET_ACCESS_KEY` (F-045).
_SENSITIVE_KEYS = {"password", "secret", "api_key", "token", "private_key", "authorization", "ssn", "pin", "cvv"}
_SENSITIVE_KEY_PARTS = (
    "password", "passwd", "pwd", "secret", "apikey", "api_key", "privatekey", "private_key",
    "authorization", "credential", "ssn", "cvv", "accesskey", "access_key", "accesstoken",
    "access_token", "refreshtoken", "refresh_token", "clientsecret", "client_secret",
    "bearertoken", "bearer_token", "sessiontoken", "session_token",
)


def is_sensitive_key(name: str) -> bool:
    """True if a parameter NAME says its value is a credential.

    Normalises separators and case first (`AWS_SECRET_ACCESS_KEY`, `aws-secret-access-key` and
    `awsSecretAccessKey` are the same key), then looks for any known part as a substring. `pin` and
    `token` stay EXACT matches — as substrings they would fire on `pinned`, `shipping`, `tokenizer`
    and similar ordinary field names, which is precisely the false-positive class worth avoiding.
    """
    raw = (name or "").strip()
    flat = re.sub(r"[^a-z0-9]", "", raw.casefold())
    if flat in {"pin", "token", "ssn", "cvv"}:
        return True
    return any(part.replace("_", "") in flat for part in _SENSITIVE_KEY_PARTS)


def luhn_ok(digits: str) -> bool:
    """Luhn check-digit validation — what separates a card number from any long digit run."""
    if not digits.isdigit() or not 12 <= len(digits) <= 19:
        return False
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _mask_pan(value: str) -> str:
    """Replace any 13-19 digit run / grouped PAN with ****<last4>."""

    def repl(match: re.Match) -> str:
        digits = re.sub(r"[ -]", "", match.group(0))
        return "****" + digits[-4:]

    masked = _PAN_RE.sub(repl, value)
    if _LONG_DIGITS_RE.match(masked):
        masked = "****" + masked[-4:]
    return masked


def _mask_string(value: str) -> str:
    """Mask PAN then SSN substrings inside a string value."""
    masked = _mask_pan(value)
    masked = _SSN_RE.sub(lambda m: "***-**-" + m.group(0)[-4:], masked)
    return masked


def mask_value(key: str, value: object) -> object:
    """Mask one value, recursing into nested dicts/lists; sensitive keys are fully redacted."""
    if isinstance(value, dict):
        return {k: mask_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_value(key, v) for v in value]
    if isinstance(value, str):
        if key.lower() in _SENSITIVE_KEYS:
            return "****"
        return _mask_string(value)
    return value


def mask_params(params: dict | None) -> dict:
    """Return a masked copy of tool_params safe to persist in the audit record."""
    if not isinstance(params, dict):
        return {}
    return {k: mask_value(k, v) for k, v in params.items()}


def mask_text(value: str) -> str:
    """Mask PAN then SSN inside a free string (for opt-in output-DLP on tool return values)."""
    if not isinstance(value, str):
        return value
    return _mask_string(value)


# Bounds for `mask_structure`. A tool RESULT is attacker-influenced — it is whatever the far side of
# an allowed call chose to return — and the engine fails CLOSED at a 2s evaluator timeout, so an
# unbounded walk here is a denial of service against every other call in flight, not just slow.
_MASK_MAX_NODES = 4096
_MASK_MAX_DEPTH = 24


def mask_structure(value: object) -> object:
    """Mask PAN/SSN in every string reachable inside a result, not only a top-level one.

    WHY THIS EXISTS. `mask_text` masks a string; `_output_dlp` applied it under
    `isinstance(result, str)`, so a tool returning a LIST of rows, a dict record, or a paginated
    envelope — the shapes real tools actually return — carried a PAN straight through the guard that
    exists to stop exactly that. The MCP plane already redacts structured output
    (`nrvq.mcp.output_dlp.structured_redacted`), so the product masked a card number on one path and
    missed it on the other while calling both "output DLP": one concept, two behaviours.

    Shape is preserved — a dict stays a dict, numbers/bools/None are untouched — because a tool's
    return is a contract with the agent framework, and a guard that reshapes it breaks the caller on
    a value it was told was safe.

    BOUNDED, and the bound is visible in the result rather than silent: past the node or depth budget
    the remaining subtree is returned UNMASKED, which is the honest failure — pretending to have
    masked what we did not walk would be worse than saying nothing. Callers that need to know can
    compare identity.
    """
    masked, _ = mask_structure_counted(value)
    return masked


def mask_structure_counted(value: object) -> tuple[object, int]:
    """`mask_structure`, plus how many strings it actually changed.

    Same single walk — the MCP plane needs the count for its telemetry and its `_meta` annotation, and
    a second traversal written next to this one is exactly how the two output-DLP paths drifted apart
    the first time. Callers that do not need the count use `mask_structure`.
    """
    nodes = 0
    redacted = 0

    def walk(node: object, depth: int) -> object:
        nonlocal nodes, redacted
        if nodes >= _MASK_MAX_NODES or depth > _MASK_MAX_DEPTH:
            return node
        nodes += 1
        if isinstance(node, str):
            out = _mask_string(node)
            if out != node:
                redacted += 1
            return out
        if isinstance(node, dict):
            return {k: walk(v, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v, depth + 1) for v in node]
        if isinstance(node, tuple):
            return tuple(walk(v, depth + 1) for v in node)
        # Numbers, bools, None, and anything opaque (a model instance, bytes) pass through untouched.
        return node

    return walk(value, 0), redacted


def redact_url_credentials(url: str) -> str:
    """Strip userinfo from a URL so it is safe to log.

    `RedisCache.connect` logged its connection URL at INFO on every startup, and a chart-generated Redis
    password lives in that URL's userinfo — so the password was emitted to stdout on every pod start, which
    means it reached whatever log aggregator the cluster ships to, searchable and retained. Observed live on
    AKS: `nrvq.cache.connected url=redis://:<password>@norviq-redis...`.

    Keeps everything an operator actually needs to debug a connection (scheme, host, port, db path) and
    replaces only the credential. Returns the input unchanged when there is no userinfo, and never raises —
    a redaction helper that throws on a malformed URL would take down the very startup path it protects.
    """
    if not url or "@" not in url:
        return url
    try:
        scheme_sep = url.find("://")
        if scheme_sep == -1:
            return "***"  # not a URL shape we recognise; do not risk emitting it
        scheme = url[: scheme_sep + 3]
        rest = url[scheme_sep + 3 :]
        # rsplit: a password may itself contain '@', and the LAST one always separates userinfo from host.
        userinfo, _, hostpart = rest.rpartition("@")
        if not userinfo:
            return url
        # Preserve the username when present — it is not a secret and identifies which principal connected.
        user = userinfo.split(":", 1)[0]
        return f"{scheme}{user}:***@{hostpart}" if user else f"{scheme}***@{hostpart}"
    except Exception as exc:  # never let redaction break the startup log it protects
        # Loud but URL-FREE: the whole point is that this string may hold a credential, so the failure is
        # reported by type only. Returning "***" keeps the safe direction — nothing is emitted.
        log.warning(
            "nrvq.masking.url_redaction_failed", error_type=type(exc).__name__, code="NRVQ-ENG-2063",
        )
        return "***"


def redact_url_to_origin(url: str) -> str:
    """Reduce a URL to scheme://host[:port], dropping path, query and userinfo.

    For webhook endpoints the secret is usually NOT in the userinfo — Slack puts it in the path
    (`/services/T…/B…/XXXX`), Splunk HEC and others in a query parameter. Stripping userinfo alone would
    still publish the token, so the whole path and query go. The origin is enough to answer "where are we
    shipping events" without publishing the credential that authorises it.
    """
    if not url:
        return url
    try:
        scheme_sep = url.find("://")
        if scheme_sep == -1:
            return "***"
        scheme = url[: scheme_sep + 3]
        rest = url[scheme_sep + 3 :]
        _, _, hostpart = rest.rpartition("@")  # drop any userinfo
        host = hostpart.split("/", 1)[0].split("?", 1)[0]
        return f"{scheme}{host}" if host else "***"
    except Exception as exc:  # same contract as redact_url_credentials above
        log.warning(
            "nrvq.masking.url_origin_failed", error_type=type(exc).__name__, code="NRVQ-ENG-2064",
        )
        return "***"
