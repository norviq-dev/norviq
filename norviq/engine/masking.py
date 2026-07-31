# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Mask sensitive tool_params for audit capture (PCI 10.3 event reconstruction without raw PII/PAN)."""

from __future__ import annotations

import re

import structlog

log = structlog.get_logger()

_PAN_RE = re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_LONG_DIGITS_RE = re.compile(r"^\d{13,19}$")
_SENSITIVE_KEYS = {"password", "secret", "api_key", "token", "private_key", "authorization", "ssn", "pin", "cvv"}


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
