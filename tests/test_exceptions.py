"""Tests for Norviq exceptions."""

from norviq.exceptions import (
    NorviqBlockError,
    NorviqConfigError,
    NorviqError,
    NorviqEscalateError,
    NorviqTimeoutError,
)


class _Decision:
    """Test policy decision stub."""

    def __init__(self, reason: str) -> None:
        self.reason = reason


def test_norviq_error_has_message_and_code() -> None:
    """Store message and code on base error."""
    err = NorviqError("base failure")
    assert err.message == "base failure"
    assert err.code == "NRVQ-SDK-1000"
    assert str(err) == "[NRVQ-SDK-1000] base failure"


def test_block_error_carries_decision() -> None:
    """Keep decision object for blocked calls."""
    decision = _Decision("dangerous tool")
    err = NorviqBlockError(decision)
    assert err.decision is decision
    assert err.code == "NRVQ-ENG-2010"
    assert "dangerous tool" in str(err)


def test_escalate_error_carries_decision() -> None:
    """Keep decision object for escalation."""
    decision = _Decision("requires approver")
    err = NorviqEscalateError(decision)
    assert err.decision is decision
    assert err.code == "NRVQ-ENG-2015"
    assert "requires approver" in str(err)


def test_timeout_error_carries_timeout() -> None:
    """Store timeout milliseconds."""
    err = NorviqTimeoutError(2500)
    assert err.timeout_ms == 2500
    assert err.code == "NRVQ-ENG-2002"
    assert str(err) == "[NRVQ-ENG-2002] Policy engine timeout after 2500ms"


def test_config_error_contains_field_and_reason() -> None:
    """Encode field context for invalid config."""
    err = NorviqConfigError("api_secret_key", "empty")
    assert err.field == "api_secret_key"
    assert err.code == "NRVQ-SDK-1002"
    assert str(err) == "[NRVQ-SDK-1002] Invalid config api_secret_key: empty"


def test_all_custom_errors_are_norviq_and_exception() -> None:
    """Verify inheritance contract for all types."""
    decision = _Decision("x")
    errs = [
        NorviqError("x"),
        NorviqBlockError(decision),
        NorviqEscalateError(decision),
        NorviqTimeoutError(1),
        NorviqConfigError("field", "reason"),
    ]
    for err in errs:
        assert isinstance(err, NorviqError)
        assert isinstance(err, Exception)
