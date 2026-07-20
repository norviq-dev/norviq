# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors
"""Opt-in, default-OFF output-DLP hook. Disabled = exact passthrough; enabled = PAN/SSN redacted."""

from norviq.config import settings
from norviq.sdk.langchain.adapter import _output_dlp


def test_output_dlp_off_is_passthrough():
    assert settings.sdk_output_dlp_enabled is False
    s = "statement: PAN 4111111111111111 ssn 123-45-6789"
    assert _output_dlp("export_statement", s) == s          # default OFF -> unchanged


def test_output_dlp_on_redacts_pan_and_ssn(monkeypatch):
    monkeypatch.setattr(settings, "sdk_output_dlp_enabled", True)
    out = _output_dlp("export_statement", "PAN 4111111111111111 ssn 123-45-6789")
    assert "4111111111111111" not in out and "****1111" in out
    assert "123-45-6789" not in out and "***-**-6789" in out


def test_output_dlp_on_passes_clean_text(monkeypatch):
    monkeypatch.setattr(settings, "sdk_output_dlp_enabled", True)
    assert _output_dlp("get_account", "balance $4,210.55") == "balance $4,210.55"


def test_output_dlp_non_string_passthrough(monkeypatch):
    monkeypatch.setattr(settings, "sdk_output_dlp_enabled", True)
    assert _output_dlp("t", {"a": 1}) == {"a": 1}
