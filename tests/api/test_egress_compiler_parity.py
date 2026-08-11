# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Norviq Contributors

"""Two compilers emit the "No external egress" refinement. They must emit the same rules.

The Visual Policy Builder (ui/src/lib/builderCompile.ts) and the server generator
(norviq/api/threat_intent.py) both compile that toggle. The builder shipped the PRE-HARDENING form —
an eighteen-name literal list and nothing else — while the server's version also reads the engine's own
`derived.verb`, applies a retrieval-lead exemption, and matches egress ACTION tokens.

So the same toggle produced opposite decisions depending on which surface authored the policy:
`forward_ticket`, `slack_post_message`, `relay_case`, `dispatch_report`, `share_summary` are all
verb=send to the engine and absent from the literal list, so the builder's policy allowed them
straight through. The Overview rendered the identical `egress` refinement badge for both, so nothing
on screen told the operator which one enforced.

Asserted on source rather than by running both toolchains: this must fail in the ordinary pytest sweep
on a machine with no node, and its whole job is to fail the moment one side gains a rule the other
lacks.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from norviq.api.threat_intent import EGRESS_ACTION_TOKENS, EGRESS_TOOLS, RETRIEVAL_LEAD_VERBS

ROOT = pathlib.Path(__file__).resolve().parents[2]
BUILDER = ROOT / "ui" / "src" / "lib" / "builderCompile.ts"

pytestmark = pytest.mark.skipif(not BUILDER.is_file(), reason="builderCompile.ts not present")


def _builder_src() -> str:
    return BUILDER.read_text()


def _ts_list(name: str, src: str) -> set[str]:
    m = re.search(rf"const {name} = \[(.*?)\];", src, re.S)
    assert m, f"{name} not found in builderCompile.ts"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


@pytest.mark.parametrize("ts_name,py_values", [
    ("EGRESS_TOOL_NAMES", EGRESS_TOOLS),
    ("RETRIEVAL_LEAD_VERBS", RETRIEVAL_LEAD_VERBS),
    ("EGRESS_ACTION_TOKENS", EGRESS_ACTION_TOKENS),
])
def test_egress_word_lists_match(ts_name: str, py_values: tuple[str, ...]) -> None:
    ts = _ts_list(ts_name, _builder_src())
    py = set(py_values)
    assert ts == py, (
        f"{ts_name} drift — only in builder: {sorted(ts - py)}; only in server: {sorted(py - ts)}. "
        "The same toggle would then compile to two different policies."
    )


def test_builder_reads_the_engines_own_classification() -> None:
    """The rule that actually closed the gap: the literal list misses ordinary vendor tools that the
    capability registry classifies as send."""
    src = _builder_src()
    assert 'object.get(input.derived, "verb", "") == "send"' in src, (
        "the builder no longer consults derived.verb — it is back to matching an eighteen-name list, "
        "so verb=send tools like forward_ticket pass straight through a 'no external egress' policy"
    )
    assert "not is_retrieval_lead" in src, (
        "the retrieval-lead exemption is missing; without it a default-deny allowlist refuses "
        "get_mail/list_mail, because the registry takes the worst verb over all name tokens"
    )


def test_builder_matches_egress_action_tokens_as_whole_tokens() -> None:
    src = _builder_src()
    assert "egress_action_tokens[tool_name_tokens[_]]" in src
    assert "egress_action_tokens[norm_name_tokens[_]]" in src


def _destination_keys(text: str) -> set[str]:
    m = re.search(r"destination_keys = \{\{?(.*?)\}\}?", text, re.S)
    assert m, "destination_keys block not found"
    return set(re.findall(r'"([^"]+)"', m.group(1)))


def test_both_sides_agree_on_the_destination_key_escape_hatch() -> None:
    """`names_a_destination` is what revokes the retrieval-lead exemption for a call that plainly names
    where it is sending data — and the two compilers must revoke it on the same parameter shapes."""
    builder = _destination_keys(_builder_src())
    server = _destination_keys((ROOT / "norviq/api/threat_intent.py").read_text())
    assert builder == server, (
        f"destination-key drift — only in builder: {sorted(builder - server)}; "
        f"only in server: {sorted(server - builder)}"
    )


def test_mail_address_parameters_revoke_the_retrieval_exemption() -> None:
    """The hole both compilers shared: `to` was absent, so a retrieval-NAMED mail tool addressed by
    `to=` kept its exemption and exfiltrated with the egress toggle ON. Widening can only tighten —
    more shapes revoke the exemption, none grant it."""
    keys = _destination_keys(_builder_src())
    for key in ("to", "cc", "bcc", "email", "address", "channel", "target"):
        assert key in keys, f"{key!r} does not revoke the retrieval-lead exemption"
