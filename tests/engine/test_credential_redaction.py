# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Connection URLs must never carry a credential into the logs.

`RedisCache.connect` logged its URL at INFO on every startup, and the chart-generated Redis password lives
in that URL's userinfo. So the password was written to stdout on every pod start and reached whatever log
aggregator the cluster ships to — searchable, retained, and in a place with a completely different access
model from the Secret it came from. Found live on AKS while measuring latency:

    nrvq.cache.connected url=redis://:<password>@norviq-redis.norviq.svc.cluster.local:6379

`siem.started` had the same shape for the SIEM webhook, where the secret is usually in the PATH (Slack
`/services/T…/B…/XXXX`) or a query parameter (Splunk HEC `?token=…`) rather than the userinfo — so stripping
userinfo alone would still have published it, which is why that one is reduced to its origin.
"""

from __future__ import annotations

import pytest

from norviq.engine.masking import redact_url_credentials, redact_url_to_origin

_SECRET = "s3cr3t-p4ssw0rd"


@pytest.mark.parametrize("url", [
    f"redis://:{_SECRET}@norviq-redis.norviq.svc.cluster.local:6379",
    f"redis://norviq:{_SECRET}@host:6379/0",
    f"postgresql://norviq:{_SECRET}@norviq-postgresql:5432/norviq",
    f"rediss://:{_SECRET}@host:6380",
])
def test_the_credential_never_survives_redaction(url: str) -> None:
    assert _SECRET not in redact_url_credentials(url)


def test_a_password_containing_an_at_sign_is_still_removed() -> None:
    """Naive `split('@')` would keep the tail of such a password. rpartition is why this holds."""
    url = "redis://:pa@ss@w0rd@norviq-redis:6379"
    out = redact_url_credentials(url)
    assert "pa@ss@w0rd" not in out and "ss@w0rd" not in out
    assert "norviq-redis:6379" in out  # the host an operator needs is preserved


def test_what_an_operator_needs_is_preserved() -> None:
    """Redaction that removes the host too would just move the outage from security to debuggability."""
    out = redact_url_credentials("postgresql://norviq:pw@db.internal:5432/norviq")
    assert "db.internal:5432" in out and "/norviq" in out
    assert "norviq:***@" in out  # username kept: not a secret, and it says which principal connected


def test_a_url_without_a_credential_is_untouched() -> None:
    plain = "redis://norviq-redis.norviq.svc.cluster.local:6379"
    assert redact_url_credentials(plain) == plain


@pytest.mark.parametrize("value", ["", "not-a-url", "garbage@@@", "redis://"])
def test_malformed_input_never_raises_and_never_echoes(value: str) -> None:
    """This runs inside a startup log call. Raising here would break the path it protects."""
    out = redact_url_credentials(value)
    assert isinstance(out, str)
    if "@" in value:
        assert "@" not in out or out == "***"


@pytest.mark.parametrize("url,secret", [
    ("https://hooks.slack.com/services/T00000/B00000/TOKENINPATH", "TOKENINPATH"),
    ("https://splunk.example.com:8088/services/collector?token=TOKENINQUERY", "TOKENINQUERY"),
    ("https://user:TOKENINUSERINFO@siem.example.com/ingest", "TOKENINUSERINFO"),
])
def test_webhook_urls_lose_path_query_and_userinfo(url: str, secret: str) -> None:
    """For webhooks the secret is rarely in the userinfo, so the origin is all that may be logged."""
    out = redact_url_to_origin(url)
    assert secret not in out
    assert out.startswith("https://") and "/" not in out[len("https://"):]


def test_the_call_sites_actually_use_the_helpers() -> None:
    """Guards the fix, not just the helper. A helper nobody calls redacts nothing.

    Asserted on source because the leak was a logging argument: the only way to regress it is to pass the
    raw URL again, and that is visible here without needing a live Redis or SIEM endpoint.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2]
    cache = (root / "norviq" / "engine" / "cache.py").read_text()
    assert 'url=redact_url_credentials(self._url)' in cache, "cache.py logs the raw Redis URL again"
    assert 'url=self._url,' not in cache, "cache.py still passes the unredacted URL to a log call"

    siem = (root / "norviq" / "api" / "siem.py").read_text()
    assert "redact_url_to_origin(settings.siem_webhook_url)" in siem, "siem.py logs the raw webhook URL"
