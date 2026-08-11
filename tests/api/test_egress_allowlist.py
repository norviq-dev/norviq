# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""C2-013 — the destination-keyed egress control.

Every assertion runs the GENERATED MODULE through real OPA. Campaign 2 already burned itself once by
reporting a policy as working on the strength of "it compiled and the dry-run said valid", when real
OPA showed it exactly inverted. Compiling is not evidence.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from norviq.api import egress_allowlist as ea

_OPA = shutil.which("opa")
pytestmark = pytest.mark.skipif(_OPA is None, reason="opa binary required to evaluate the module")


def _eval(domains: list[str], *, rcpt=(), hosts=(), decision="audit") -> tuple[str, str]:
    """(decision, rule_id) for one call against a freshly compiled allowlist module."""
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "egress.rego"
        p.write_text(ea.compile(list(domains), decision=decision), encoding="utf-8")
        inp = json.dumps({"derived": {"destinations": {
            "recipient_domains": list(rcpt), "hosts": list(hosts)}}})
        out = []
        for query in ("decision", "rule_id"):
            r = subprocess.run(
                [_OPA, "eval", "--v0-compatible", "-d", str(p), "-I", "--format", "raw",
                 f"data.norviq.egress.{query}"],
                input=inp, capture_output=True, text=True, check=True,
            )
            out.append(r.stdout.strip())
        return out[0], out[1]


def test_the_c2_001_chain_is_caught():
    """The finding this control exists for: a customer record emailed to an untrusted relay.

    Every step is individually legitimate and no content detector fires — the payload is a name and an
    address, not an SSN. Only the destination marks it.
    """
    assert _eval(["acme.com"], rcpt=["mail-relay.example.net"]) == ("audit", ea.RULE_ID)


def test_an_allowed_destination_is_not_flagged():
    """A defence that breaks legitimate traffic is worse than the attack it prevents."""
    assert _eval(["acme.com"], rcpt=["acme.com"]) == ("allow", "default_allow")


def test_a_call_with_no_destination_is_not_flagged():
    """This must key on the DESTINATION, not on being an egress-shaped tool."""
    assert _eval(["acme.com"]) == ("allow", "default_allow")


def test_an_empty_allowlist_discovers_rather_than_sleeps():
    """Nothing configured flags everything, on purpose.

    "Empty = inert" would produce a control that reads ON while catching nothing, which is the exact
    false assurance C2-001 is about. Flagging everything turns monitor mode into the destination
    inventory an operator needs before they can write an allowlist at all.
    """
    assert _eval([], rcpt=["anywhere.example.net"]) == ("audit", ea.RULE_ID)


class TestSuffixMatching:
    """`.acme.com` means "this organisation". Getting this wrong backdoors the control."""

    def test_it_matches_a_subdomain(self):
        assert _eval([".acme.com"], rcpt=["mail.acme.com"]) == ("allow", "default_allow")

    def test_it_matches_the_apex_too(self):
        """Making an operator list the apex separately is a footgun, not a control."""
        assert _eval([".acme.com"], rcpt=["acme.com"]) == ("allow", "default_allow")

    def test_it_does_NOT_match_a_lookalike_registration(self):
        """The whole point. `evil-acme.com` is a domain an attacker can register today; a naive
        substring match would have handed it the allowlist."""
        assert _eval([".acme.com"], rcpt=["evil-acme.com"]) == ("audit", ea.RULE_ID)

    def test_it_does_NOT_match_a_suffix_appended_to_another_domain(self):
        assert _eval([".acme.com"], rcpt=["acme.com.evil.net"]) == ("audit", ea.RULE_ID)


def test_hosts_are_checked_as_well_as_email_recipients():
    """Exfiltration via a webhook URL is the same finding wearing a different argument name."""
    assert _eval(["acme.com"], hosts=["evil.example.net"]) == ("audit", ea.RULE_ID)


def test_promotion_to_enforcement_blocks():
    assert _eval([], hosts=["evil.example.net"], decision="block") == ("block", ea.RULE_ID)


def test_discovery_can_never_interrupt_traffic():
    """The default decision must be audit, never block — discovery must not drop customer calls."""
    assert 'audits["' in ea.compile([]) and 'blocks["' not in ea.compile([])


class TestRoundTrip:
    def test_the_list_survives_a_compile_and_read_back(self):
        got = ea.parse(ea.compile([".Acme.COM ", "acme.com", "acme.com"], decision="block"))
        assert got == {"domains": [".acme.com", "acme.com"], "decision": "block"}

    def test_a_module_we_did_not_generate_reads_back_as_None(self):
        assert ea.parse("package x\nallow = true") is None

    def test_a_corrupt_header_degrades_rather_than_raising(self):
        """This is called to DISPLAY the operator's list; a truncated module must not 500 the page
        they would use to fix it."""
        assert ea.parse("# nrvq-egress-allowlist/v1: !!!not-base64!!!") is None


class TestValidation:
    @pytest.mark.parametrize("bad", ["https://acme.com/", "user@acme.com", "acme", "acme .com", "a..b"])
    def test_a_non_domain_is_rejected_loudly(self, bad):
        """Silently dropping a typo leaves the operator believing a destination is allowed while every
        call to it is flagged — or blocked, once they promote."""
        with pytest.raises(ea.InvalidDomain):
            ea.normalise([bad])

    def test_entries_are_normalised_and_deduplicated(self):
        assert ea.normalise([" ACME.com ", "acme.com.", "acme.com"]) == ["acme.com"]

    def test_an_oversized_list_is_refused(self):
        with pytest.raises(ea.InvalidDomain):
            ea.normalise([f"d{i}.example.com" for i in range(ea.MAX_DOMAINS + 1)])

    def test_an_invalid_decision_is_refused(self):
        with pytest.raises(ValueError):
            ea.compile([], decision="escalate")
