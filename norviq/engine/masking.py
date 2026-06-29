# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""F-19: mask sensitive tool_params for audit capture (PCI 10.3 event reconstruction without raw PII/PAN)."""

from __future__ import annotations

import re

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
