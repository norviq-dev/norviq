# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Custom exception hierarchy for Norviq."""

from __future__ import annotations
from typing import Any

def _reason_or_default(decision: Any, default: str) -> str:
    """Return decision reason when available."""
    reason = getattr(decision, "reason", None)
    return str(reason) if reason else default


class NorviqError(Exception):
    """Base exception for all Norviq errors."""

    def __init__(self, message: str, code: str = "NRVQ-SDK-1000") -> None:
        self.message = message
        self.code = code
        super().__init__(f"[{code}] {message}")


class NorviqBlockError(NorviqError):
    """Raised when a tool call is blocked by policy."""

    def __init__(self, decision: Any, code: str = "NRVQ-ENG-2010") -> None:
        self.decision = decision
        super().__init__(
            message=f"Blocked: {_reason_or_default(decision, 'Blocked by policy')}",
            code=code,
        )


class NorviqEscalateError(NorviqError):
    """Raised when a tool call requires human approval."""

    def __init__(self, decision: Any, code: str = "NRVQ-ENG-2015") -> None:
        self.decision = decision
        super().__init__(
            message=f"Escalate: {_reason_or_default(decision, 'Requires escalation')}",
            code=code,
        )


class NorviqTimeoutError(NorviqError):
    """Raised when policy engine times out."""

    def __init__(self, timeout_ms: int, code: str = "NRVQ-ENG-2002") -> None:
        self.timeout_ms = timeout_ms
        super().__init__(message=f"Policy engine timeout after {timeout_ms}ms", code=code)


class NorviqConfigError(NorviqError):
    """Raised when configuration is invalid."""

    def __init__(self, field: str, reason: str, code: str = "NRVQ-SDK-1002") -> None:
        self.field = field
        super().__init__(message=f"Invalid config {field}: {reason}", code=code)
